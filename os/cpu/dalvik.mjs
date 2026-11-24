/**
 * OmniOS Dalvik/ART Register Bytecode Virtual Machine (`os/cpu/dalvik.mjs`, F-039)
 * Genuine synchronous, step-budgeted register-based Dalvik bytecode interpreter.
 * - Executes standard Dalvik opcodes `0x00`..`0xE2` (`10x`..`51l`, `35c`, `3rc`)
 * - Incoming arguments `p0..p(insSize-1)` placed in top registers `v(registersSize-insSize)..v(registersSize-1)`
 * - Exact Java/Dalvik semantics: `div`/`rem` by 0 throws catchable `ArithmeticException`;
 *   `INT32_MIN / -1` wraps to `INT32_MIN` (`rem` = 0); `INT64_MIN / -1` wraps to `INT64_MIN` (`rem` = 0) (Edge Case #10)
 * - Call-stack unwinding through DEX `try_item` / `encoded_catch_handler` matching type hierarchy & `catch_all`
 * - Strict call depth limit throwing catchable `Ljava/lang/StackOverflowError;` without JS stack overflow (Edge Case #11)
 * - Strict instruction quota enforcing `QuotaExceededError(E_CPU_QUOTA)` and `instructionsExecuted <= budget`
 * - Zero external dependencies; pure in-memory execution without host filesystem access.
 */

import {
  IllegalInstructionError,
  UnsupportedOpcodeError,
  QuotaExceededError,
  ERROR_CODES,
} from '../common/errors.mjs';

const INT32_MIN = -2147483648;
const INT32_MAX = 2147483647;
const INT64_MIN = -9223372036854775808n;
const INT64_MAX = 9223372036854775807n;

const MAX_EXCEPTION_ID_CHARS = 128;
const MAX_EXCEPTION_MESSAGE_CHARS = 512;
const MAX_VM_EXCEPTION_CACHE = 64;
const VM_EXCEPTION_ALLOC_BASE_BYTES = 1024;
const VM_EMPTY_ARRAY_HEADER_BYTES = 128;
const VM_ARRAY_HEADER_BYTES = 256;
const EMPTY_INT8 = new Int8Array(0);
const EMPTY_UINT16 = new Uint16Array(0);
const EMPTY_INT16 = new Int16Array(0);
const EMPTY_INT32 = new Int32Array(0);
const EMPTY_BIGINT64 = new BigInt64Array(0);
const EMPTY_FLOAT32 = new Float32Array(0);
const EMPTY_FLOAT64 = new Float64Array(0);
const EMPTY_OBJ_ARR = Object.freeze([]);

function capExceptionId(str) {
  const s = String(str ?? '');
  return s.length > MAX_EXCEPTION_ID_CHARS ? `${s.slice(0, MAX_EXCEPTION_ID_CHARS)}...` : s;
}

function capExceptionMessage(str) {
  const s = String(str ?? '');
  return s.length > MAX_EXCEPTION_MESSAGE_CHARS ? s.slice(0, MAX_EXCEPTION_MESSAGE_CHARS) : s;
}

// Reusable 8-byte scratch buffer for exact IEEE-754 float/double and 64-bit long bit conversions
const SCRATCH_AB = new ArrayBuffer(8);
const SCRATCH_DV = new DataView(SCRATCH_AB);

function toInt32(val) {
  if (typeof val === 'number') return val | 0;
  if (typeof val === 'bigint') return Number(BigInt.asIntN(32, val));
  if (typeof val === 'boolean') return val ? 1 : 0;
  if (val === null || val === undefined) return 0;
  if (typeof val === 'string') {
    const n = Number(val);
    return Number.isFinite(n) ? (n | 0) : 0;
  }
  return 0;
}

function toSafeNumber(val) {
  if (typeof val === 'number') return val;
  if (typeof val === 'bigint') return Number(val);
  if (typeof val === 'boolean') return val ? 1 : 0;
  if (val === null || val === undefined) return 0;
  if (typeof val === 'string') return Number(val);
  return 0;
}

function floatToIntBits(f) {
  SCRATCH_DV.setFloat32(0, f, true);
  return SCRATCH_DV.getInt32(0, true);
}

function intBitsToFloat(bits) {
  SCRATCH_DV.setInt32(0, toInt32(bits), true);
  return SCRATCH_DV.getFloat32(0, true);
}

function doubleToLongBits(d) {
  SCRATCH_DV.setFloat64(0, d, true);
  return SCRATCH_DV.getBigInt64(0, true);
}

function longBitsToDouble(bits) {
  const safeBits = typeof bits === 'bigint' ? bits : floatToJavaLong(toSafeNumber(bits));
  SCRATCH_DV.setBigInt64(0, BigInt.asIntN(64, safeBits), true);
  return SCRATCH_DV.getFloat64(0, true);
}

function floatToJavaInt(f) {
  if (Number.isNaN(f)) return 0;
  if (f >= INT32_MAX) return INT32_MAX;
  if (f <= INT32_MIN) return INT32_MIN;
  return Math.trunc(f) | 0;
}

function floatToJavaLong(f) {
  if (Number.isNaN(f)) return 0n;
  if (f >= 9223372036854775808.0) return INT64_MAX;
  if (f <= -9223372036854775808.0) return INT64_MIN;
  return BigInt.asIntN(64, BigInt(Math.trunc(f)));
}

export const DALVIK_OPCODES = Object.freeze({
  NOP: 0x00,
  MOVE: 0x01,
  MOVE_FROM16: 0x02,
  MOVE_16: 0x03,
  MOVE_WIDE: 0x04,
  MOVE_WIDE_FROM16: 0x05,
  MOVE_WIDE_16: 0x06,
  MOVE_OBJECT: 0x07,
  MOVE_OBJECT_FROM16: 0x08,
  MOVE_OBJECT_16: 0x09,
  MOVE_RESULT: 0x0a,
  MOVE_RESULT_WIDE: 0x0b,
  MOVE_RESULT_OBJECT: 0x0c,
  MOVE_EXCEPTION: 0x0d,
  RETURN_VOID: 0x0e,
  RETURN: 0x0f,
  RETURN_WIDE: 0x10,
  RETURN_OBJECT: 0x11,
  CONST_4: 0x12,
  CONST_16: 0x13,
  CONST: 0x14,
  CONST_HIGH16: 0x15,
  CONST_WIDE_16: 0x16,
  CONST_WIDE_32: 0x17,
  CONST_WIDE: 0x18,
  CONST_WIDE_HIGH16: 0x19,
  CONST_STRING: 0x1a,
  CONST_STRING_JUMBO: 0x1b,
  CONST_CLASS: 0x1c,
  MONITOR_ENTER: 0x1d,
  MONITOR_EXIT: 0x1e,
  CHECK_CAST: 0x1f,
  INSTANCE_OF: 0x20,
  ARRAY_LENGTH: 0x21,
  NEW_INSTANCE: 0x22,
  NEW_ARRAY: 0x23,
  FILLED_NEW_ARRAY: 0x24,
  FILLED_NEW_ARRAY_RANGE: 0x25,
  FILL_ARRAY_DATA: 0x26,
  THROW: 0x27,
  GOTO: 0x28,
  GOTO_16: 0x29,
  GOTO_32: 0x2a,
  PACKED_SWITCH: 0x2b,
  SPARSE_SWITCH: 0x2c,
  CMPL_FLOAT: 0x2d,
  CMPG_FLOAT: 0x2e,
  CMPL_DOUBLE: 0x2f,
  CMPG_DOUBLE: 0x30,
  CMP_LONG: 0x31,
  IF_EQ: 0x32,
  IF_NE: 0x33,
  IF_LT: 0x34,
  IF_GE: 0x35,
  IF_GT: 0x36,
  IF_LE: 0x37,
  IF_EQZ: 0x38,
  IF_NEZ: 0x39,
  IF_LTZ: 0x3a,
  IF_GEZ: 0x3b,
  IF_GTZ: 0x3c,
  IF_LEZ: 0x3d,
  AGET: 0x44,
  AGET_WIDE: 0x45,
  AGET_OBJECT: 0x46,
  AGET_BOOLEAN: 0x47,
  AGET_BYTE: 0x48,
  AGET_CHAR: 0x49,
  AGET_SHORT: 0x4a,
  APUT: 0x4b,
  APUT_WIDE: 0x4c,
  APUT_OBJECT: 0x4d,
  APUT_BOOLEAN: 0x4e,
  APUT_BYTE: 0x4f,
  APUT_CHAR: 0x50,
  APUT_SHORT: 0x51,
  IGET: 0x52,
  IGET_WIDE: 0x53,
  IGET_OBJECT: 0x54,
  IGET_BOOLEAN: 0x55,
  IGET_BYTE: 0x56,
  IGET_CHAR: 0x57,
  IGET_SHORT: 0x58,
  IPUT: 0x59,
  IPUT_WIDE: 0x5a,
  IPUT_OBJECT: 0x5b,
  IPUT_BOOLEAN: 0x5c,
  IPUT_BYTE: 0x5d,
  IPUT_CHAR: 0x5e,
  IPUT_SHORT: 0x5f,
  SGET: 0x60,
  SGET_WIDE: 0x61,
  SGET_OBJECT: 0x62,
  SGET_BOOLEAN: 0x63,
  SGET_BYTE: 0x64,
  SGET_CHAR: 0x65,
  SGET_SHORT: 0x66,
  SPUT: 0x67,
  SPUT_WIDE: 0x68,
  SPUT_OBJECT: 0x69,
  SPUT_BOOLEAN: 0x6a,
  SPUT_BYTE: 0x6b,
  SPUT_CHAR: 0x6c,
  SPUT_SHORT: 0x6d,
  INVOKE_VIRTUAL: 0x6e,
  INVOKE_SUPER: 0x6f,
  INVOKE_DIRECT: 0x70,
  INVOKE_STATIC: 0x71,
  INVOKE_INTERFACE: 0x72,
  INVOKE_VIRTUAL_RANGE: 0x74,
  INVOKE_SUPER_RANGE: 0x75,
  INVOKE_DIRECT_RANGE: 0x76,
  INVOKE_STATIC_RANGE: 0x77,
  INVOKE_INTERFACE_RANGE: 0x78,
  NEG_INT: 0x7b,
  NOT_INT: 0x7c,
  NEG_LONG: 0x7d,
  NOT_LONG: 0x7e,
  NEG_FLOAT: 0x7f,
  NEG_DOUBLE: 0x80,
  INT_TO_LONG: 0x81,
  INT_TO_FLOAT: 0x82,
  INT_TO_DOUBLE: 0x83,
  LONG_TO_INT: 0x84,
  LONG_TO_FLOAT: 0x85,
  LONG_TO_DOUBLE: 0x86,
  FLOAT_TO_INT: 0x87,
  FLOAT_TO_LONG: 0x88,
  FLOAT_TO_DOUBLE: 0x89,
  DOUBLE_TO_INT: 0x8a,
  DOUBLE_TO_LONG: 0x8b,
  DOUBLE_TO_FLOAT: 0x8c,
  INT_TO_BYTE: 0x8d,
  INT_TO_CHAR: 0x8e,
  INT_TO_SHORT: 0x8f,
  ADD_INT: 0x90,
  SUB_INT: 0x91,
  MUL_INT: 0x92,
  DIV_INT: 0x93,
  REM_INT: 0x94,
  AND_INT: 0x95,
  OR_INT: 0x96,
  XOR_INT: 0x97,
  SHL_INT: 0x98,
  SHR_INT: 0x99,
  USHR_INT: 0x9a,
  ADD_LONG: 0x9b,
  SUB_LONG: 0x9c,
  MUL_LONG: 0x9d,
  DIV_LONG: 0x9e,
  REM_LONG: 0x9f,
  AND_LONG: 0xa0,
  OR_LONG: 0xa1,
  XOR_LONG: 0xa2,
  SHL_LONG: 0xa3,
  SHR_LONG: 0xa4,
  USHR_LONG: 0xa5,
  ADD_FLOAT: 0xa6,
  SUB_FLOAT: 0xa7,
  MUL_FLOAT: 0xa8,
  DIV_FLOAT: 0xa9,
  REM_FLOAT: 0xaa,
  ADD_DOUBLE: 0xab,
  SUB_DOUBLE: 0xac,
  MUL_DOUBLE: 0xad,
  DIV_DOUBLE: 0xae,
  REM_DOUBLE: 0xaf,
  ADD_INT_2ADDR: 0xb0,
  SUB_INT_2ADDR: 0xb1,
  MUL_INT_2ADDR: 0xb2,
  DIV_INT_2ADDR: 0xb3,
  REM_INT_2ADDR: 0xb4,
  AND_INT_2ADDR: 0xb5,
  OR_INT_2ADDR: 0xb6,
  XOR_INT_2ADDR: 0xb7,
  SHL_INT_2ADDR: 0xb8,
  SHR_INT_2ADDR: 0xb9,
  USHR_INT_2ADDR: 0xba,
  ADD_LONG_2ADDR: 0xbb,
  SUB_LONG_2ADDR: 0xbc,
  MUL_LONG_2ADDR: 0xbd,
  DIV_LONG_2ADDR: 0xbe,
  REM_LONG_2ADDR: 0xbf,
  AND_LONG_2ADDR: 0xc0,
  OR_LONG_2ADDR: 0xc1,
  XOR_LONG_2ADDR: 0xc2,
  SHL_LONG_2ADDR: 0xc3,
  SHR_LONG_2ADDR: 0xc4,
  USHR_LONG_2ADDR: 0xc5,
  ADD_FLOAT_2ADDR: 0xc6,
  SUB_FLOAT_2ADDR: 0xc7,
  MUL_FLOAT_2ADDR: 0xc8,
  DIV_FLOAT_2ADDR: 0xc9,
  REM_FLOAT_2ADDR: 0xca,
  ADD_DOUBLE_2ADDR: 0xcb,
  SUB_DOUBLE_2ADDR: 0xcc,
  MUL_DOUBLE_2ADDR: 0xcd,
  DIV_DOUBLE_2ADDR: 0xce,
  REM_DOUBLE_2ADDR: 0xcf,
  ADD_INT_LIT16: 0xd0,
  RSUB_INT: 0xd1,
  MUL_INT_LIT16: 0xd2,
  DIV_INT_LIT16: 0xd3,
  REM_INT_LIT16: 0xd4,
  AND_INT_LIT16: 0xd5,
  OR_INT_LIT16: 0xd6,
  XOR_INT_LIT16: 0xd7,
  ADD_INT_LIT8: 0xd8,
  RSUB_INT_LIT8: 0xd9,
  MUL_INT_LIT8: 0xda,
  DIV_INT_LIT8: 0xdb,
  REM_INT_LIT8: 0xdc,
  AND_INT_LIT8: 0xdd,
  OR_INT_LIT8: 0xde,
  XOR_INT_LIT8: 0xdf,
  SHL_INT_LIT8: 0xe0,
  SHR_INT_LIT8: 0xe1,
  USHR_INT_LIT8: 0xe2,
});

// Built-in Java / Android framework class inheritance for accurate `catch`, `instance-of`, and `check-cast`
const BUILTIN_SUPERCLASS = Object.freeze({
  'Ljava/lang/Throwable;': 'Ljava/lang/Object;',
  'Ljava/lang/Exception;': 'Ljava/lang/Throwable;',
  'Ljava/lang/Error;': 'Ljava/lang/Throwable;',
  'Ljava/lang/LinkageError;': 'Ljava/lang/Error;',
  'Ljava/lang/IncompatibleClassChangeError;': 'Ljava/lang/LinkageError;',
  'Ljava/lang/NoSuchMethodError;': 'Ljava/lang/IncompatibleClassChangeError;',
  'Ljava/lang/AbstractMethodError;': 'Ljava/lang/IncompatibleClassChangeError;',
  'Ljava/lang/NoClassDefFoundError;': 'Ljava/lang/LinkageError;',
  'Ljava/lang/VirtualMachineError;': 'Ljava/lang/Error;',
  'Ljava/lang/StackOverflowError;': 'Ljava/lang/VirtualMachineError;',
  'Ljava/lang/OutOfMemoryError;': 'Ljava/lang/VirtualMachineError;',
  'Ljava/lang/RuntimeException;': 'Ljava/lang/Exception;',
  'Ljava/lang/ArithmeticException;': 'Ljava/lang/RuntimeException;',
  'Ljava/lang/NullPointerException;': 'Ljava/lang/RuntimeException;',
  'Ljava/lang/IndexOutOfBoundsException;': 'Ljava/lang/RuntimeException;',
  'Ljava/lang/ArrayIndexOutOfBoundsException;': 'Ljava/lang/IndexOutOfBoundsException;',
  'Ljava/lang/StringIndexOutOfBoundsException;': 'Ljava/lang/IndexOutOfBoundsException;',
  'Ljava/lang/ArrayStoreException;': 'Ljava/lang/RuntimeException;',
  'Ljava/lang/ClassCastException;': 'Ljava/lang/RuntimeException;',
  'Ljava/lang/IllegalArgumentException;': 'Ljava/lang/RuntimeException;',
  'Ljava/lang/NumberFormatException;': 'Ljava/lang/IllegalArgumentException;',
  'Ljava/lang/IllegalStateException;': 'Ljava/lang/RuntimeException;',
  'Ljava/lang/SecurityException;': 'Ljava/lang/RuntimeException;',
  'Ljava/lang/NegativeArraySizeException;': 'Ljava/lang/RuntimeException;',
  'Ljava/lang/UnsupportedOperationException;': 'Ljava/lang/RuntimeException;',
  'Ljava/io/IOException;': 'Ljava/lang/Exception;',
  'Ljava/io/FileNotFoundException;': 'Ljava/io/IOException;',
  'Ljava/io/InputStream;': 'Ljava/lang/Object;',
  'Ljava/io/FileInputStream;': 'Ljava/io/InputStream;',
  'Ljava/io/OutputStream;': 'Ljava/lang/Object;',
  'Ljava/io/FileOutputStream;': 'Ljava/io/OutputStream;',
  'Ljava/io/FilterOutputStream;': 'Ljava/io/OutputStream;',
  'Ljava/io/PrintStream;': 'Ljava/io/FilterOutputStream;',
  'Ljava/io/File;': 'Ljava/lang/Object;',
  'Landroid/content/ActivityNotFoundException;': 'Ljava/lang/RuntimeException;',
  'Landroid/content/Context;': 'Ljava/lang/Object;',
  'Landroid/content/ContextWrapper;': 'Landroid/content/Context;',
  'Landroid/app/Activity;': 'Landroid/content/ContextWrapper;',
  'Landroid/app/Service;': 'Landroid/content/ContextWrapper;',
  'Landroid/content/Intent;': 'Ljava/lang/Object;',
  'Landroid/content/ComponentName;': 'Ljava/lang/Object;',
  'Landroid/content/ClipboardManager;': 'Ljava/lang/Object;',
  'Landroid/content/ClipData;': 'Ljava/lang/Object;',
  'Landroid/content/ClipData$Item;': 'Ljava/lang/Object;',
  'Landroid/content/ContentResolver;': 'Ljava/lang/Object;',
  'Landroid/content/ContentValues;': 'Ljava/lang/Object;',
  'Landroid/content/SharedPreferences;': 'Ljava/lang/Object;',
  'Landroid/content/SharedPreferences$Editor;': 'Ljava/lang/Object;',
  'Landroid/app/SharedPreferencesImpl;': 'Ljava/lang/Object;',
  'Landroid/app/SharedPreferencesImpl$EditorImpl;': 'Ljava/lang/Object;',
  'Landroid/content/res/Resources;': 'Ljava/lang/Object;',
  'Landroid/content/res/Resources$NotFoundException;': 'Ljava/lang/RuntimeException;',
  'Landroid/database/Cursor;': 'Ljava/lang/Object;',
  'Landroid/net/Uri;': 'Ljava/lang/Object;',
  'Landroid/os/BaseBundle;': 'Ljava/lang/Object;',
  'Landroid/os/Bundle;': 'Landroid/os/BaseBundle;',
  'Landroid/os/Environment;': 'Ljava/lang/Object;',
  'Landroid/app/NotificationManager;': 'Ljava/lang/Object;',
  'Landroid/app/Notification;': 'Ljava/lang/Object;',
  'Landroid/app/Notification$Builder;': 'Ljava/lang/Object;',
  'Landroid/util/Log;': 'Ljava/lang/Object;',
  'Landroid/widget/Toast;': 'Ljava/lang/Object;',
  'Landroid/view/InflateException;': 'Ljava/lang/RuntimeException;',
  'Landroid/view/View;': 'Ljava/lang/Object;',
  'Landroid/view/ViewGroup;': 'Landroid/view/View;',
  'Landroid/widget/LinearLayout;': 'Landroid/view/ViewGroup;',
  'Landroid/widget/FrameLayout;': 'Landroid/view/ViewGroup;',
  'Landroid/widget/RelativeLayout;': 'Landroid/view/ViewGroup;',
  'Landroid/widget/ListView;': 'Landroid/view/ViewGroup;',
  'Landroid/widget/ScrollView;': 'Landroid/widget/FrameLayout;',
  'Landroid/widget/TextView;': 'Landroid/view/View;',
  'Landroid/widget/Button;': 'Landroid/widget/TextView;',
  'Landroid/widget/CheckBox;': 'Landroid/widget/Button;',
  'Landroid/widget/EditText;': 'Landroid/widget/TextView;',
  'Landroid/widget/ImageView;': 'Landroid/view/View;',
  'Ljava/lang/String;': 'Ljava/lang/Object;',
  'Ljava/lang/StringBuilder;': 'Ljava/lang/Object;',
  'Ljava/lang/StringBuffer;': 'Ljava/lang/Object;',
  'Ljava/lang/Number;': 'Ljava/lang/Object;',
  'Ljava/lang/Byte;': 'Ljava/lang/Number;',
  'Ljava/lang/Short;': 'Ljava/lang/Number;',
  'Ljava/lang/Integer;': 'Ljava/lang/Number;',
  'Ljava/lang/Long;': 'Ljava/lang/Number;',
  'Ljava/lang/Float;': 'Ljava/lang/Number;',
  'Ljava/lang/Double;': 'Ljava/lang/Number;',
  'Ljava/lang/Boolean;': 'Ljava/lang/Object;',
  'Ljava/lang/Character;': 'Ljava/lang/Object;',
  'Ljava/lang/Class;': 'Ljava/lang/Object;',
  'Ljava/lang/System;': 'Ljava/lang/Object;',
  'Ljava/lang/Math;': 'Ljava/lang/Object;',
  'Ljava/util/AbstractCollection;': 'Ljava/lang/Object;',
  'Ljava/util/AbstractList;': 'Ljava/util/AbstractCollection;',
  'Ljava/util/ArrayList;': 'Ljava/util/AbstractList;',
  'Ljava/util/AbstractSet;': 'Ljava/util/AbstractCollection;',
  'Ljava/util/HashSet;': 'Ljava/util/AbstractSet;',
  'Ljava/util/AbstractMap;': 'Ljava/lang/Object;',
  'Ljava/util/HashMap;': 'Ljava/util/AbstractMap;',
});

const BUILTIN_INTERFACES = Object.freeze({
  'Ljava/lang/String;': Object.freeze(['Ljava/lang/CharSequence;', 'Ljava/lang/Comparable;', 'Ljava/io/Serializable;']),
  'Ljava/lang/StringBuilder;': Object.freeze(['Ljava/lang/CharSequence;', 'Ljava/lang/Appendable;', 'Ljava/io/Serializable;']),
  'Ljava/lang/StringBuffer;': Object.freeze(['Ljava/lang/CharSequence;', 'Ljava/lang/Appendable;', 'Ljava/io/Serializable;']),
  'Ljava/lang/Number;': Object.freeze(['Ljava/io/Serializable;']),
  'Ljava/lang/Byte;': Object.freeze(['Ljava/lang/Comparable;']),
  'Ljava/lang/Short;': Object.freeze(['Ljava/lang/Comparable;']),
  'Ljava/lang/Integer;': Object.freeze(['Ljava/lang/Comparable;']),
  'Ljava/lang/Long;': Object.freeze(['Ljava/lang/Comparable;']),
  'Ljava/lang/Float;': Object.freeze(['Ljava/lang/Comparable;']),
  'Ljava/lang/Double;': Object.freeze(['Ljava/lang/Comparable;']),
  'Ljava/lang/Boolean;': Object.freeze(['Ljava/lang/Comparable;', 'Ljava/io/Serializable;']),
  'Ljava/lang/Character;': Object.freeze(['Ljava/lang/Comparable;', 'Ljava/io/Serializable;']),
  'Ljava/io/Closeable;': Object.freeze(['Ljava/lang/AutoCloseable;']),
  'Ljava/io/InputStream;': Object.freeze(['Ljava/io/Closeable;', 'Ljava/lang/AutoCloseable;']),
  'Ljava/io/OutputStream;': Object.freeze(['Ljava/io/Closeable;', 'Ljava/io/Flushable;', 'Ljava/lang/AutoCloseable;']),
  'Ljava/io/PrintStream;': Object.freeze(['Ljava/lang/Appendable;', 'Ljava/io/Closeable;']),
  'Ljava/io/File;': Object.freeze(['Ljava/io/Serializable;', 'Ljava/lang/Comparable;']),
  'Ljava/util/Collection;': Object.freeze(['Ljava/lang/Iterable;']),
  'Ljava/util/List;': Object.freeze(['Ljava/util/Collection;', 'Ljava/lang/Iterable;']),
  'Ljava/util/Set;': Object.freeze(['Ljava/util/Collection;', 'Ljava/lang/Iterable;']),
  'Ljava/util/AbstractCollection;': Object.freeze(['Ljava/util/Collection;', 'Ljava/lang/Iterable;']),
  'Ljava/util/AbstractList;': Object.freeze(['Ljava/util/List;']),
  'Ljava/util/ArrayList;': Object.freeze([
    'Ljava/util/List;',
    'Ljava/util/RandomAccess;',
    'Ljava/lang/Cloneable;',
    'Ljava/io/Serializable;',
    'Ljava/util/Collection;',
    'Ljava/lang/Iterable;',
  ]),
  'Ljava/util/AbstractSet;': Object.freeze(['Ljava/util/Set;']),
  'Ljava/util/HashSet;': Object.freeze([
    'Ljava/util/Set;',
    'Ljava/lang/Cloneable;',
    'Ljava/io/Serializable;',
    'Ljava/util/Collection;',
    'Ljava/lang/Iterable;',
  ]),
  'Ljava/util/AbstractMap;': Object.freeze(['Ljava/util/Map;']),
  'Ljava/util/HashMap;': Object.freeze(['Ljava/util/Map;', 'Ljava/lang/Cloneable;', 'Ljava/io/Serializable;']),
  'Landroid/app/SharedPreferencesImpl;': Object.freeze(['Landroid/content/SharedPreferences;']),
  'Landroid/app/SharedPreferencesImpl$EditorImpl;': Object.freeze(['Landroid/content/SharedPreferences$Editor;']),
  'Landroid/database/Cursor;': Object.freeze(['Ljava/io/Closeable;', 'Ljava/lang/AutoCloseable;']),
  'Landroid/content/Intent;': Object.freeze(['Landroid/os/Parcelable;', 'Ljava/lang/Cloneable;']),
  'Landroid/os/Bundle;': Object.freeze(['Landroid/os/Parcelable;', 'Ljava/lang/Cloneable;']),
  'Landroid/net/Uri;': Object.freeze(['Landroid/os/Parcelable;', 'Ljava/lang/Comparable;']),
});

/**
 * Thrown by host framework bridge methods to raise a catchable Dalvik exception inside the VM.
 */
export class DalvikGuestException {
  constructor(exceptionObject) {
    const msg = exceptionObject?.fields?.detailMessage ?? exceptionObject?.classType ?? 'DalvikException';
    this.name = 'DalvikGuestException';
    this.message = String(msg);
    this.exception = exceptionObject;
  }
}
Object.setPrototypeOf(DalvikGuestException.prototype, Error.prototype);

export class DalvikVM {
  constructor({
    dexFiles = [],
    bridge = null,
    maxCallDepth = 256,
    maxTotalInstructions = Infinity,
    maxMemoryBytes = 64 * 1024 * 1024,
    pid = null,
  } = {}) {
    this.dexFiles = [];
    this.classesByName = new Map();
    this.staticFields = new Map(); // classType -> Object.create(null)
    this.initializedClasses = new Set();
    this.bridge = bridge;
    this.maxCallDepth = Number.isInteger(maxCallDepth) && maxCallDepth >= 1 ? maxCallDepth : 256;
    this.maxTotalInstructions =
      typeof maxTotalInstructions === 'number' && maxTotalInstructions > 0
        ? maxTotalInstructions
        : Infinity;
    this.maxMemoryBytes =
      typeof maxMemoryBytes === 'number' && Number.isFinite(maxMemoryBytes) && maxMemoryBytes > 0
        ? Math.trunc(maxMemoryBytes)
        : 64 * 1024 * 1024;
    this.maxSingleArrayBytes = Math.min(this.maxMemoryBytes, 16 * 1024 * 1024);
    this.allocatedHeapBytes = 0;
    this.activeStackBytes = 0;
    this.pid = pid;

    this.callStack = [];
    this.totalInstructionsExecuted = 0;
    this._stepExternalWork = 0;
    this.lastResultInt = 0;
    this.lastResultWide = 0n;
    this.lastResultRef = null;
    this.lastReturnValue = undefined;
    this.lastUncaughtException = null;
    this.lastNativeCall = null;
    this._nextObjId = 1;
    this._classObjects = new Map();
    this._vmExceptionCache = new Map();
    this._assignableCache = new Map();
    this._oomSingleton = this._makeFrozenException(
      'Ljava/lang/OutOfMemoryError;',
      'Dalvik VM heap memory quota exceeded'
    );
    this._soeSingleton = this._makeFrozenException(
      'Ljava/lang/StackOverflowError;',
      'Dalvik VM call stack depth quota exceeded'
    );

    for (const dex of dexFiles) {
      this.loadDex(dex);
    }
  }

  setBridge(bridge) {
    this.bridge = bridge;
  }

  chargeExternalWork(units) {
    const add = typeof units === 'number' && Number.isFinite(units) && units > 0 ? Math.trunc(units) : 0;
    if (add <= 0) return;
    this.totalInstructionsExecuted += add;
    this._stepExternalWork += add;
    if (this.totalInstructionsExecuted >= this.maxTotalInstructions) {
      throw new QuotaExceededError(
        `Dalvik VM exceeded total instruction quota (${this.maxTotalInstructions})`,
        {
          code: ERROR_CODES.E_CPU_QUOTA,
          quotaType: 'cpu',
          limit: this.maxTotalInstructions,
          actual: this.totalInstructionsExecuted,
          pid: this.pid,
          signal: 'SIGXCPU',
        }
      );
    }
  }

  loadDex(dexFile) {
    if (!dexFile || !dexFile.classesByName) return;
    this.dexFiles.push(dexFile);
    for (const [classType, classDef] of dexFile.classesByName.entries()) {
      if (!this.classesByName.has(classType)) {
        this.classesByName.set(classType, classDef);
      }
    }
    this._assignableCache.clear();
  }

  createObject(classType, initialFields = null, nativeData = null, opts = null) {
    // Collect class hierarchy first so heap quota is enforced before object allocation.
    // Skip untrusted DEX class definitions for no-charge host framework bootstrap singletons.
    const skipDexWalk =
      opts?.charge === false &&
      typeof classType === 'string' &&
      (classType.startsWith('Ljava/') || classType.startsWith('Landroid/'));
    const firstDef = skipDexWalk ? undefined : this.classesByName.get(classType);
    let chain = null;
    let fieldCount = 0;
    if (firstDef) {
      chain = [firstDef];
      fieldCount = firstDef.instanceFields.length;
      let cur = firstDef.superclassType;
      if (cur && cur !== classType) {
        let seen = null;
        while (cur) {
          const def = this.classesByName.get(cur);
          if (!def) break;
          if (!seen) {
            seen = new Set([classType]);
          }
          if (seen.has(cur)) break;
          seen.add(cur);
          chain.push(def);
          fieldCount += def.instanceFields.length;
          cur = def.superclassType;
        }
      }
    }
    const initialKeys = initialFields != null ? Object.keys(initialFields) : null;
    const totalFieldCount = fieldCount + (initialKeys ? initialKeys.length : 0);
    const hasFields = fieldCount > 0 || initialFields != null;
    if (!opts || opts.charge !== false) {
      // 0-field instances leave fields=null (single compact fast-mode object: 128 B);
      // instances with fields allocate a V8 dictionary-mode Object.create(null) (256 + 128/field).
      const objBytes = hasFields ? 256 + totalFieldCount * 128 : 128;
      this.chargeHeap(objBytes, `new ${capExceptionId(classType)}`);
    }
    let fields = null;
    if (hasFields) {
      fields = Object.create(null);
      // Initialize declared instance fields with JVM default zero/null values along hierarchy
      if (chain) {
        for (let i = chain.length - 1; i >= 0; i--) {
          for (const f of chain[i].instanceFields) {
            fields[f.name] = this._defaultValueForType(f.type);
          }
        }
      }
      if (initialKeys) {
        for (let i = 0; i < initialKeys.length; i++) {
          const k = initialKeys[i];
          fields[k] = initialFields[k];
        }
      }
    }
    return {
      __dalvikType: 'instance',
      classType,
      id: this._nextObjId++,
      fields,
      native: nativeData,
    };
  }

  _makeFrozenException(classType, detailMessage, precomputedChain = null) {
    const fields = Object.create(null);
    const isBuiltin =
      typeof classType === 'string' &&
      (classType.startsWith('Ljava/') || classType.startsWith('Landroid/'));
    // Never walk untrusted DEX class definitions for built-in java.*/android.* exceptions (seals DEX shadowing).
    if (!isBuiltin) {
      let chain = precomputedChain;
      if (!chain) {
        chain = [];
        let cur = classType;
        const seen = new Set();
        while (cur && !seen.has(cur)) {
          seen.add(cur);
          if (cur.startsWith('Ljava/') || cur.startsWith('Landroid/')) break;
          const def = this.classesByName.get(cur);
          if (!def) break;
          chain.push(def);
          cur = def.superclassType;
        }
      }
      for (let i = chain.length - 1; i >= 0; i--) {
        for (const f of chain[i].instanceFields) {
          fields[f.name] = this._defaultValueForType(f.type);
        }
      }
    }
    fields.detailMessage = detailMessage;
    Object.freeze(fields);
    return Object.freeze({
      __dalvikType: 'instance',
      classType,
      id: this._nextObjId++,
      fields,
      native: null,
    });
  }

  createException(classType, message = '') {
    const safeType =
      typeof classType === 'string' && classType.length > 0
        ? capExceptionId(classType)
        : 'Ljava/lang/RuntimeException;';
    const cappedMsg = capExceptionMessage(message);

    if (safeType === 'Ljava/lang/OutOfMemoryError;') {
      return this._oomSingleton;
    }
    if (safeType === 'Ljava/lang/StackOverflowError;') {
      return this._soeSingleton;
    }

    const cacheKey = `${safeType}\0${cappedMsg}`;
    const cached = this._vmExceptionCache.get(cacheKey);
    if (cached) {
      return cached;
    }

    const isBuiltin = safeType.startsWith('Ljava/') || safeType.startsWith('Landroid/');
    let chain = null;
    let fieldCount = 0;
    if (!isBuiltin) {
      chain = [];
      let cur = safeType;
      const seen = new Set();
      while (cur && !seen.has(cur)) {
        seen.add(cur);
        if (cur.startsWith('Ljava/') || cur.startsWith('Landroid/')) break;
        const def = this.classesByName.get(cur);
        if (!def) break;
        chain.push(def);
        fieldCount += def.instanceFields.length;
        cur = def.superclassType;
      }
    }

    const cost = VM_EXCEPTION_ALLOC_BASE_BYTES + cappedMsg.length * 2 + fieldCount * 128;
    const usedBytes = this.allocatedHeapBytes + this.activeStackBytes;
    if (cost > this.maxSingleArrayBytes || usedBytes + cost > this.maxMemoryBytes) {
      return this._oomSingleton;
    }
    this.allocatedHeapBytes += cost;

    const exc = this._makeFrozenException(safeType, cappedMsg, chain);
    if (this._vmExceptionCache.size < MAX_VM_EXCEPTION_CACHE) {
      this._vmExceptionCache.set(cacheKey, exc);
    }
    return exc;
  }

  _arrayElementByteSize(elemType) {
    switch (elemType) {
      case 'Z':
      case 'B':
        return 1;
      case 'C':
      case 'S':
        return 2;
      case 'I':
      case 'F':
        return 4;
      case 'J':
      case 'D':
        return 8;
      default:
        return 8; // Object / nested-array reference slot budget
    }
  }

  _primitiveArrayElementWidth(elemType) {
    switch (elemType) {
      case 'Z':
      case 'B':
        return 1;
      case 'C':
      case 'S':
        return 2;
      case 'I':
      case 'F':
        return 4;
      case 'J':
      case 'D':
        return 8;
      default:
        return 0;
    }
  }

  checkHeapBudget(bytes, _reason = 'Heap allocation') {
    if (typeof bytes !== 'number' || !Number.isFinite(bytes) || bytes < 0) {
      throw new DalvikGuestException(this._oomSingleton);
    }
    const amount = Math.trunc(bytes);
    const usedBytes = this.allocatedHeapBytes + this.activeStackBytes;
    if (
      amount > this.maxSingleArrayBytes ||
      usedBytes + amount > this.maxMemoryBytes
    ) {
      throw new DalvikGuestException(this._oomSingleton);
    }
    return amount;
  }

  chargeHeap(bytes, reason = 'Heap allocation') {
    const amount = this.checkHeapBudget(bytes, reason);
    this.allocatedHeapBytes += amount;
    return amount;
  }

  createArray(arrayType, length) {
    if (!Number.isInteger(length) || length < 0) {
      throw new DalvikGuestException(
        this.createException('Ljava/lang/NegativeArraySizeException;', `Negative array length: ${length}`)
      );
    }
    const elemType = arrayType.startsWith('[') ? arrayType.slice(1) : 'Ljava/lang/Object;';
    const elemBytes = this._arrayElementByteSize(elemType);
    const bytesNeeded =
      length === 0 ? VM_EMPTY_ARRAY_HEADER_BYTES : VM_ARRAY_HEADER_BYTES + length * elemBytes;
    this.chargeHeap(bytesNeeded, `Array allocation of ${length} elements`);

    let data;
    if (length === 0) {
      switch (elemType) {
        case 'Z':
        case 'B':
          data = EMPTY_INT8;
          break;
        case 'C':
          data = EMPTY_UINT16;
          break;
        case 'S':
          data = EMPTY_INT16;
          break;
        case 'I':
          data = EMPTY_INT32;
          break;
        case 'J':
          data = EMPTY_BIGINT64;
          break;
        case 'F':
          data = EMPTY_FLOAT32;
          break;
        case 'D':
          data = EMPTY_FLOAT64;
          break;
        default:
          data = EMPTY_OBJ_ARR;
          break;
      }
    } else {
      switch (elemType) {
        case 'Z':
        case 'B':
          data = new Int8Array(length);
          break;
        case 'C':
          data = new Uint16Array(length);
          break;
        case 'S':
          data = new Int16Array(length);
          break;
        case 'I':
          data = new Int32Array(length);
          break;
        case 'J':
          data = new BigInt64Array(length);
          break;
        case 'F':
          data = new Float32Array(length);
          break;
        case 'D':
          data = new Float64Array(length);
          break;
        default:
          data = new Array(length).fill(null);
          break;
      }
    }
    return {
      __dalvikType: 'array',
      classType: arrayType,
      elementType: elemType,
      id: this._nextObjId++,
      length,
      data,
    };
  }

  createClassObject(targetType) {
    let clsObj = this._classObjects.get(targetType);
    if (!clsObj) {
      clsObj = {
        __dalvikType: 'class',
        classType: 'Ljava/lang/Class;',
        targetType,
        id: this._nextObjId++,
        fields: null,
      };
      this._classObjects.set(targetType, clsObj);
    }
    return clsObj;
  }

  _defaultValueForType(typeDesc) {
    if (typeDesc === 'J') return 0n;
    if (typeDesc === 'F' || typeDesc === 'D') return 0;
    if (typeDesc.startsWith('L') || typeDesc.startsWith('[')) return null;
    return 0;
  }

  getObjectType(val) {
    if (val === null || val === undefined) return null;
    if (typeof val === 'string') return 'Ljava/lang/String;';
    if (typeof val === 'object' && typeof val.classType === 'string') return val.classType;
    return null;
  }

  isAssignableTo(subType, superType) {
    if (!subType || !superType) return false;
    if (subType === superType || superType === 'Ljava/lang/Object;') return true;

    const cacheKey = `${subType}\0${superType}`;
    const cached = this._assignableCache.get(cacheKey);
    if (cached !== undefined) return cached;

    let sub = subType;
    let sup = superType;
    // Iteratively peel matching array dimensions to avoid stack recursion on deep descriptors
    while (sub.startsWith('[') && sup.startsWith('[')) {
      if (sub === sup) {
        if (this._assignableCache.size < 4096) this._assignableCache.set(cacheKey, true);
        return true;
      }
      sub = sub.slice(1);
      sup = sup.slice(1);
      const subIsRef = sub.startsWith('L') || sub.startsWith('[');
      const supIsRef = sup.startsWith('L') || sup.startsWith('[');
      if (!subIsRef || !supIsRef) {
        const res = sub === sup;
        if (this._assignableCache.size < 4096) this._assignableCache.set(cacheKey, res);
        return res;
      }
    }
    if (sub === sup || sup === 'Ljava/lang/Object;') {
      if (this._assignableCache.size < 4096) this._assignableCache.set(cacheKey, true);
      return true;
    }

    if (sub.startsWith('[')) {
      const res = sup === 'Ljava/lang/Cloneable;' || sup === 'Ljava/io/Serializable;';
      if (this._assignableCache.size < 4096) this._assignableCache.set(cacheKey, res);
      return res;
    }
    if (sup.startsWith('[')) {
      if (this._assignableCache.size < 4096) this._assignableCache.set(cacheKey, false);
      return false;
    }

    const visited = new Set();
    const queue = [sub];
    let result = false;
    while (queue.length > 0) {
      const cur = queue.shift();
      if (!cur || visited.has(cur)) continue;
      visited.add(cur);
      if (cur === sup) {
        result = true;
        break;
      }

      const def = this.classesByName.get(cur);
      if (def) {
        if (def.superclassType) queue.push(def.superclassType);
        for (const iface of def.interfaces ?? []) queue.push(iface);
      } else {
        if (Object.prototype.hasOwnProperty.call(BUILTIN_SUPERCLASS, cur)) {
          queue.push(BUILTIN_SUPERCLASS[cur]);
        }
        if (Object.prototype.hasOwnProperty.call(BUILTIN_INTERFACES, cur)) {
          for (const iface of BUILTIN_INTERFACES[cur]) queue.push(iface);
        }
      }
    }
    if (this._assignableCache.size < 4096) this._assignableCache.set(cacheKey, result);
    return result;
  }

  _getStaticStore(classType) {
    let store = this.staticFields.get(classType);
    if (!store) {
      store = Object.create(null);
      const def = this.classesByName.get(classType);
      if (def) {
        for (const sf of def.staticFields) {
          store[sf.name] = sf.initialValue !== undefined ? sf.initialValue : this._defaultValueForType(sf.type);
        }
      }
      this.staticFields.set(classType, store);
    }
    return store;
  }

  _ensureClassInitialized(classType, triggeringFrame = null) {
    if (this.initializedClasses.has(classType)) return false;
    this.initializedClasses.add(classType);
    this._getStaticStore(classType);
    const def = this.classesByName.get(classType);
    if (!def) return false;
    const clinit = def.methods.get('<clinit>()V');
    if (clinit && clinit.code) {
      // Rewind triggering instruction so it runs cleanly after <clinit> returns
      if (triggeringFrame) {
        triggeringFrame.pc = triggeringFrame.currentInsnPc;
      }
      this._pushFrame(clinit, [], null);
      // Always return true when <clinit> was attempted so callers stop executing the triggering
      // instruction whether <clinit> pushed cleanly OR unwound an exception (e.g. StackOverflowError).
      return true;
    }
    return false;
  }

  findMethod(classType, signature, { includeSuper = true, directOnly = false } = {}) {
    let cur = classType;
    const seen = new Set();
    while (cur && !seen.has(cur)) {
      seen.add(cur);
      const def = this.classesByName.get(cur);
      if (def) {
        const m = def.methods.get(signature);
        if (m && (!directOnly || m.isDirect)) {
          return m;
        }
        if (!includeSuper) break;
        cur = def.superclassType;
      } else {
        break;
      }
    }
    return null;
  }

  findMethodByName(classType, methodName, { includeSuper = true } = {}) {
    let cur = classType;
    const seen = new Set();
    while (cur && !seen.has(cur)) {
      seen.add(cur);
      const def = this.classesByName.get(cur);
      if (def) {
        for (const m of def.methods.values()) {
          if (m.name === methodName) return m;
        }
        if (!includeSuper) break;
        cur = def.superclassType;
      } else {
        break;
      }
    }
    return null;
  }

  _illegalInsn(message, pc = 0, details = undefined) {
    return new IllegalInstructionError(message, {
      code: ERROR_CODES.E_ILLEGAL_INSTRUCTION,
      pc,
      arch: 'dalvik',
      pid: this.pid,
      ...(details ? { details } : {}),
    });
  }

  _checkInsnUnits(frame, pc, width) {
    if (pc + width > frame.insns.length) {
      throw this._illegalInsn(
        `Truncated Dalvik instruction at pc=${pc} (need ${width} units, len=${frame.insns.length})`,
        pc
      );
    }
  }

  _checkReg(frame, reg) {
    if (reg < 0 || reg >= frame.code.registersSize) {
      throw this._illegalInsn(
        `Dalvik register v${reg} out of bounds (registersSize=${frame.code.registersSize})`,
        frame.currentInsnPc
      );
    }
    return reg;
  }

  _checkWideReg(frame, reg) {
    if (reg < 0 || reg + 1 >= frame.code.registersSize) {
      throw this._illegalInsn(
        `Dalvik wide register pair v${reg}:v${reg + 1} out of bounds (registersSize=${frame.code.registersSize})`,
        frame.currentInsnPc
      );
    }
    return reg;
  }

  _getString(frame, idx) {
    if (idx < 0 || idx >= frame.dex.strings.length) {
      throw this._illegalInsn(
        `Invalid DEX string index ${idx} (count=${frame.dex.strings.length})`,
        frame.currentInsnPc
      );
    }
    return frame.dex.strings[idx];
  }

  _getType(frame, idx) {
    if (idx < 0 || idx >= frame.dex.types.length) {
      throw this._illegalInsn(
        `Invalid DEX type index ${idx} (count=${frame.dex.types.length})`,
        frame.currentInsnPc
      );
    }
    return frame.dex.types[idx];
  }

  _getField(frame, idx) {
    if (idx < 0 || idx >= frame.dex.fields.length) {
      throw this._illegalInsn(
        `Invalid DEX field index ${idx} (count=${frame.dex.fields.length})`,
        frame.currentInsnPc
      );
    }
    return frame.dex.fields[idx];
  }

  _getMethod(frame, idx) {
    if (idx < 0 || idx >= frame.dex.methods.length) {
      throw this._illegalInsn(
        `Invalid DEX method index ${idx} (count=${frame.dex.methods.length})`,
        frame.currentInsnPc
      );
    }
    return frame.dex.methods[idx];
  }

  _createFrame(method, args = [], receiver = null) {
    const code = method.code;
    if (!code) {
      throw new IllegalInstructionError(`Method ${method.key} has no bytecode (abstract or native)`, {
        code: ERROR_CODES.E_ILLEGAL_INSTRUCTION,
        arch: 'dalvik',
        pid: this.pid,
      });
    }

    const paramTypes = method.proto.params;
    let requiredIns = method.isStatic ? 0 : 1;
    for (let i = 0; i < paramTypes.length; i++) {
      const pType = paramTypes[i];
      requiredIns += pType === 'J' || pType === 'D' ? 2 : 1;
    }
    if (requiredIns > code.insSize || code.insSize > code.registersSize) {
      throw this._illegalInsn(
        `Method ${method.key} parameter slots (${requiredIns}) exceed insSize (${code.insSize}) / registersSize (${code.registersSize})`,
        0
      );
    }

    const intRegs = new Int32Array(code.registersSize);
    const refRegs = new Array(code.registersSize).fill(null);

    // Place incoming parameters p0..p(insSize-1) at top registers v(registersSize - insSize)..v(registersSize - 1)
    let regIdx = code.registersSize - code.insSize;
    if (!method.isStatic) {
      this._writeRefToArrays(intRegs, refRegs, regIdx, receiver);
      regIdx += 1;
    }

    for (let i = 0; i < paramTypes.length; i++) {
      const pType = paramTypes[i];
      const val = i < args.length ? args[i] : this._defaultValueForType(pType);
      if (pType === 'J') {
        this._writeLongToArrays(
          intRegs,
          refRegs,
          regIdx,
          typeof val === 'bigint' ? BigInt.asIntN(64, val) : floatToJavaLong(toSafeNumber(val))
        );
        regIdx += 2;
      } else if (pType === 'D') {
        this._writeLongToArrays(intRegs, refRegs, regIdx, doubleToLongBits(toSafeNumber(val)));
        regIdx += 2;
      } else if (pType === 'F') {
        intRegs[regIdx] = floatToIntBits(toSafeNumber(val));
        refRegs[regIdx] = null;
        regIdx += 1;
      } else if (pType.startsWith('L') || pType.startsWith('[')) {
        this._writeRefToArrays(intRegs, refRegs, regIdx, val ?? null);
        regIdx += 1;
      } else {
        intRegs[regIdx] = toInt32(val);
        refRegs[regIdx] = null;
        regIdx += 1;
      }
    }

    return {
      method,
      dex: method.dex,
      code,
      insns: code.insns,
      pc: 0,
      currentInsnPc: -1,
      intRegs,
      refRegs,
      pendingException: null,
    };
  }

  _writeRefToArrays(intRegs, refRegs, reg, ref) {
    if (ref === null || ref === undefined) {
      intRegs[reg] = 0;
      refRegs[reg] = null;
    } else {
      refRegs[reg] = ref;
      intRegs[reg] = typeof ref === 'object' && typeof ref.id === 'number' ? ref.id : 1;
    }
  }

  _writeLongToArrays(intRegs, refRegs, reg, bigVal) {
    const safeBig = typeof bigVal === 'bigint' ? bigVal : floatToJavaLong(toSafeNumber(bigVal));
    SCRATCH_DV.setBigInt64(0, BigInt.asIntN(64, safeBig), true);
    intRegs[reg] = SCRATCH_DV.getInt32(0, true);
    intRegs[reg + 1] = SCRATCH_DV.getInt32(4, true);
    refRegs[reg] = null;
    refRegs[reg + 1] = null;
  }

  _readLong(frame, reg) {
    this._checkWideReg(frame, reg);
    SCRATCH_DV.setInt32(0, frame.intRegs[reg], true);
    SCRATCH_DV.setInt32(4, frame.intRegs[reg + 1], true);
    return SCRATCH_DV.getBigInt64(0, true);
  }

  _writeLong(frame, reg, bigVal) {
    this._checkWideReg(frame, reg);
    this._writeLongToArrays(frame.intRegs, frame.refRegs, reg, bigVal);
  }

  _readDouble(frame, reg) {
    this._checkWideReg(frame, reg);
    SCRATCH_DV.setInt32(0, frame.intRegs[reg], true);
    SCRATCH_DV.setInt32(4, frame.intRegs[reg + 1], true);
    return SCRATCH_DV.getFloat64(0, true);
  }

  _writeDouble(frame, reg, dVal) {
    this._checkWideReg(frame, reg);
    SCRATCH_DV.setFloat64(0, toSafeNumber(dVal), true);
    frame.intRegs[reg] = SCRATCH_DV.getInt32(0, true);
    frame.intRegs[reg + 1] = SCRATCH_DV.getInt32(4, true);
    frame.refRegs[reg] = null;
    frame.refRegs[reg + 1] = null;
  }

  _writeRef(frame, reg, ref) {
    this._checkReg(frame, reg);
    this._writeRefToArrays(frame.intRegs, frame.refRegs, reg, ref);
  }

  _writeInt(frame, reg, val) {
    this._checkReg(frame, reg);
    frame.intRegs[reg] = toInt32(val);
    frame.refRegs[reg] = null;
  }

  _popFrame() {
    const popped = this.callStack.pop();
    if (popped) {
      this.activeStackBytes = Math.max(0, this.activeStackBytes - (popped.stackBytes || 0));
    }
    if (this.callStack.length === 0) {
      this.activeStackBytes = 0;
    }
    return popped;
  }

  _pushFrame(method, args = [], receiver = null) {
    const code = method?.code;
    if (!code) {
      throw new IllegalInstructionError(`Method ${method?.key ?? 'unknown'} has no bytecode (abstract or native)`, {
        code: ERROR_CODES.E_ILLEGAL_INSTRUCTION,
        arch: 'dalvik',
        pid: this.pid,
      });
    }
    if (this.callStack.length >= this.maxCallDepth) {
      this._unwindException(this._soeSingleton);
      return false;
    }
    const frameBytes = 64 + code.registersSize * 12;
    const usedBytes = this.allocatedHeapBytes + this.activeStackBytes;
    if (frameBytes > this.maxSingleArrayBytes || this.activeStackBytes + frameBytes > this.maxMemoryBytes) {
      this._unwindException(this._soeSingleton);
      return false;
    }
    if (usedBytes + frameBytes > this.maxMemoryBytes) {
      this._unwindException(this._oomSingleton);
      return false;
    }
    const frame = this._createFrame(method, args, receiver);
    frame.stackBytes = frameBytes;
    this.activeStackBytes += frameBytes;
    this.callStack.push(frame);
    return true;
  }

  /**
   * Starts a Dalvik method invocation by pushing its initial frame onto the call stack.
   */
  startMethod(classType, signatureOrName, args = [], receiver = null) {
    this.lastUncaughtException = null;
    this.lastReturnValue = undefined;
    let method = this.findMethod(classType, signatureOrName, { includeSuper: true });
    if (!method && !signatureOrName.includes('(')) {
      method = this.findMethodByName(classType, signatureOrName, { includeSuper: true });
    }
    if (!method) {
      throw new IllegalInstructionError(`Dalvik method not found: ${classType}->${signatureOrName}`, {
        code: ERROR_CODES.E_UNRESOLVED_IMPORT,
        arch: 'dalvik',
        pid: this.pid,
      });
    }
    // Push target method first, then <clinit> on top if uninitialized so <clinit> executes before target!
    const ok = this._pushFrame(method, args, receiver);
    if (!ok) return false;
    if (!this.initializedClasses.has(classType)) {
      this._ensureClassInitialized(classType, null);
      if (this.callStack.length === 0 || this.lastUncaughtException) {
        return false;
      }
    }
    return true;
  }

  /**
   * Synchronously runs a method to completion (up to `maxInstructions`), convenient for direct testing.
   */
  invokeMethod(classType, signatureOrName, args = [], { receiver = null, maxInstructions = 100_000 } = {}) {
    this.startMethod(classType, signatureOrName, args, receiver);
    const res = this.step(maxInstructions);
    return res;
  }

  _unwindException(exObj) {
    while (this.callStack.length > 0) {
      const frame = this.callStack[this.callStack.length - 1];
      const throwPc = frame.currentInsnPc;
      const tries = frame.code.tries;
      if (tries && tries.length > 0) {
        const exType = this.getObjectType(exObj);
        for (const t of tries) {
          if (throwPc >= t.startAddr && throwPc < t.endAddr) {
            for (const h of t.handlers) {
              if (this.isAssignableTo(exType, h.type)) {
                frame.pendingException = exObj;
                frame.pc = h.addr;
                return true;
              }
            }
            if (t.catchAllAddr !== null) {
              frame.pendingException = exObj;
              frame.pc = t.catchAllAddr;
              return true;
            }
          }
        }
      }
      this._popFrame();
    }
    this.lastUncaughtException = exObj;
    return false;
  }

  _throwGuest(classType, message) {
    const ex = this.createException(classType, message);
    return this._unwindException(ex);
  }

  _extractCallArgs(frame, argRegs, paramTypes, isStatic) {
    let requiredSlots = isStatic ? 0 : 1;
    for (let i = 0; i < paramTypes.length; i++) {
      const pType = paramTypes[i];
      requiredSlots += pType === 'J' || pType === 'D' ? 2 : 1;
    }
    if (argRegs.length !== requiredSlots) {
      throw this._illegalInsn(
        `Invoke argument register count (${argRegs.length}) does not match required parameter slots (${requiredSlots})`,
        frame.currentInsnPc
      );
    }
    for (let i = 0; i < argRegs.length; i++) {
      this._checkReg(frame, argRegs[i]);
    }

    let idx = 0;
    let receiver = null;
    if (!isStatic) {
      receiver = frame.refRegs[argRegs[idx]];
      idx += 1;
    }
    const args = new Array(paramTypes.length);
    for (let i = 0; i < paramTypes.length; i++) {
      const pType = paramTypes[i];
      if (pType === 'J') {
        const loReg = argRegs[idx];
        const hiReg = argRegs[idx + 1];
        SCRATCH_DV.setInt32(0, frame.intRegs[loReg], true);
        SCRATCH_DV.setInt32(4, frame.intRegs[hiReg], true);
        args[i] = SCRATCH_DV.getBigInt64(0, true);
        idx += 2;
      } else if (pType === 'D') {
        const loReg = argRegs[idx];
        const hiReg = argRegs[idx + 1];
        SCRATCH_DV.setInt32(0, frame.intRegs[loReg], true);
        SCRATCH_DV.setInt32(4, frame.intRegs[hiReg], true);
        args[i] = SCRATCH_DV.getFloat64(0, true);
        idx += 2;
      } else if (pType === 'F') {
        args[i] = intBitsToFloat(frame.intRegs[argRegs[idx]]);
        idx += 1;
      } else if (pType === 'Z') {
        args[i] = frame.intRegs[argRegs[idx]] !== 0;
        idx += 1;
      } else if (pType.startsWith('L') || pType.startsWith('[')) {
        args[i] = frame.refRegs[argRegs[idx]];
        idx += 1;
      } else {
        args[i] = frame.intRegs[argRegs[idx]] | 0;
        idx += 1;
      }
    }
    return { receiver, args };
  }

  _storeNativeResult(returnType, value, pc = 0) {
    if (returnType === 'V') return;
    if (returnType === 'J') {
      this.lastResultWide =
        typeof value === 'bigint' ? BigInt.asIntN(64, value) : floatToJavaLong(toSafeNumber(value));
      this.lastResultRef = null;
    } else if (returnType === 'D') {
      this.lastResultWide = doubleToLongBits(toSafeNumber(value));
      this.lastResultRef = null;
    } else if (returnType === 'F') {
      this.lastResultInt = floatToIntBits(toSafeNumber(value));
      this.lastResultRef = null;
    } else if (returnType === 'Z') {
      this.lastResultInt = value ? 1 : 0;
      this.lastResultRef = null;
    } else if (returnType.startsWith('L') || returnType.startsWith('[')) {
      if (value === null || value === undefined) {
        this.lastResultRef = null;
        this.lastResultInt = 0;
      } else if (typeof value === 'string') {
        if (!this.isAssignableTo('Ljava/lang/String;', returnType)) {
          throw this._illegalInsn(
            `Incompatible string native return for reference return type ${returnType}`,
            pc
          );
        }
        this.lastResultRef = value;
        this.lastResultInt = 1;
      } else if (typeof value === 'object') {
        if (typeof value.__dalvikType !== 'string') {
          throw this._illegalInsn(
            `Invalid non-Dalvik object returned for reference return type ${returnType}`,
            pc
          );
        }
        this.lastResultRef = value;
        this.lastResultInt = typeof value.id === 'number' ? value.id : 1;
      } else {
        // Primitive JS value (bigint/number/boolean) returned for a reference descriptor:
        // box cleanly ONLY if assignable to returnType (e.g., Ljava/lang/Object; or matching wrapper);
        // otherwise reject forged primitive-to-reference descriptors!
        let boxedType;
        let boxedVal;
        if (typeof value === 'boolean') {
          boxedType = 'Ljava/lang/Boolean;';
          boxedVal = value;
        } else if (typeof value === 'bigint') {
          boxedType = 'Ljava/lang/Long;';
          boxedVal = BigInt.asIntN(64, value);
        } else if (typeof value === 'number') {
          if (returnType === 'Ljava/lang/Double;') {
            boxedType = 'Ljava/lang/Double;';
            boxedVal = value;
          } else if (returnType === 'Ljava/lang/Float;') {
            boxedType = 'Ljava/lang/Float;';
            boxedVal = Math.fround(value);
          } else if (returnType === 'Ljava/lang/Long;') {
            boxedType = 'Ljava/lang/Long;';
            boxedVal = floatToJavaLong(value);
          } else if (returnType === 'Ljava/lang/Short;') {
            boxedType = 'Ljava/lang/Short;';
            boxedVal = (toInt32(value) << 16) >> 16;
          } else if (returnType === 'Ljava/lang/Byte;') {
            boxedType = 'Ljava/lang/Byte;';
            boxedVal = (toInt32(value) << 24) >> 24;
          } else if (Number.isInteger(value) && value >= INT32_MIN && value <= INT32_MAX) {
            boxedType = 'Ljava/lang/Integer;';
            boxedVal = value | 0;
          } else {
            boxedType = 'Ljava/lang/Double;';
            boxedVal = value;
          }
        } else {
          throw this._illegalInsn(
            `Incompatible primitive native return (${typeof value}) for reference return type ${returnType}`,
            pc
          );
        }
        if (!this.isAssignableTo(boxedType, returnType)) {
          throw this._illegalInsn(
            `Incompatible primitive native return (${typeof value} -> ${boxedType}) for reference return type ${returnType}`,
            pc
          );
        }
        const boxed = this.createObject(boxedType, null, { value: boxedVal });
        this.lastResultRef = boxed;
        this.lastResultInt = boxed.id;
      }
    } else {
      this.lastResultInt = toInt32(value);
      this.lastResultRef = null;
    }
  }

  _checkFieldOpcode(op, baseOp, fieldType, pc) {
    const sub = op - baseOp;
    const fType = typeof fieldType === 'string' ? fieldType : '';
    const isWide = fType === 'J' || fType === 'D';
    const isRef = fType.startsWith('L') || fType.startsWith('[');
    if (sub === 1) {
      if (!isWide) {
        throw this._illegalInsn(`Incompatible wide field opcode 0x${op.toString(16)} for field type ${fType}`, pc);
      }
    } else if (sub === 2) {
      if (!isRef) {
        throw this._illegalInsn(`Incompatible object field opcode 0x${op.toString(16)} for field type ${fType}`, pc);
      }
    } else if (sub === 3) {
      if (fType !== 'Z' && fType !== 'B') {
        throw this._illegalInsn(`Incompatible boolean field opcode 0x${op.toString(16)} for field type ${fType}`, pc);
      }
    } else if (sub === 4) {
      if (fType !== 'B') {
        throw this._illegalInsn(`Incompatible byte field opcode 0x${op.toString(16)} for field type ${fType}`, pc);
      }
    } else if (sub === 5) {
      if (fType !== 'C') {
        throw this._illegalInsn(`Incompatible char field opcode 0x${op.toString(16)} for field type ${fType}`, pc);
      }
    } else if (sub === 6) {
      if (fType !== 'S') {
        throw this._illegalInsn(`Incompatible short field opcode 0x${op.toString(16)} for field type ${fType}`, pc);
      }
    } else if (isWide || isRef) {
      throw this._illegalInsn(`Incompatible field opcode 0x${op.toString(16)} for field type ${fType}`, pc);
    }
  }

  _handleInvoke(frame, kind, methodIdx, argRegs) {
    const methodRef = this._getMethod(frame, methodIdx);

    const isStatic = kind === 'static';
    const { receiver, args } = this._extractCallArgs(frame, argRegs, methodRef.proto.params, isStatic);

    if (!isStatic && (receiver === null || receiver === undefined)) {
      this._throwGuest('Ljava/lang/NullPointerException;', `Null receiver calling ${capExceptionId(methodRef.key)}`);
      return;
    }

    let runtimeClass = null;
    if (!isStatic) {
      if (typeof receiver !== 'object' && typeof receiver !== 'string') {
        this._throwGuest(
          'Ljava/lang/ClassCastException;',
          `Invalid receiver (${typeof receiver}) calling ${capExceptionId(methodRef.key)}`
        );
        return;
      }
      runtimeClass = this.getObjectType(receiver);
      if (!runtimeClass) {
        this._throwGuest(
          'Ljava/lang/ClassCastException;',
          `Invalid non-Dalvik receiver calling ${capExceptionId(methodRef.key)}`
        );
        return;
      }
      if (
        methodRef.name === '<init>' &&
        (typeof receiver !== 'object' || receiver.__dalvikType !== 'instance')
      ) {
        this._throwGuest(
          'Ljava/lang/ClassCastException;',
          `Cannot invoke constructor ${capExceptionId(methodRef.key)} on non-instance ${capExceptionId(runtimeClass)}`
        );
        return;
      }
      if (!this.isAssignableTo(runtimeClass, methodRef.classType)) {
        this._throwGuest(
          'Ljava/lang/ClassCastException;',
          `Receiver ${capExceptionId(runtimeClass)} is not assignable to ${capExceptionId(methodRef.classType)} calling ${capExceptionId(methodRef.key)}`
        );
        return;
      }
    }

    // Trigger <clinit> on static invoke if target DEX class not yet initialized
    if (isStatic && this.classesByName.has(methodRef.classType) && !this.initializedClasses.has(methodRef.classType)) {
      if (this._ensureClassInitialized(methodRef.classType, frame)) {
        return;
      }
    }

    let resolvedDexMethod = null;
    let bridgeTargetClass = methodRef.classType;

    if (kind === 'static') {
      resolvedDexMethod = this.findMethod(methodRef.classType, methodRef.signature, { includeSuper: true });
    } else if (kind === 'direct') {
      resolvedDexMethod = this.findMethod(methodRef.classType, methodRef.signature, {
        includeSuper: false,
        directOnly: true,
      });
    } else if (kind === 'super') {
      const callerSuper = frame.method.dex.classesByName.get(frame.method.classType)?.superclassType ?? methodRef.classType;
      if (!this.isAssignableTo(runtimeClass, callerSuper)) {
        this._throwGuest(
          'Ljava/lang/ClassCastException;',
          `Receiver ${capExceptionId(runtimeClass)} is not assignable to superclass ${capExceptionId(callerSuper)} calling ${capExceptionId(methodRef.key)}`
        );
        return;
      }
      bridgeTargetClass = callerSuper;
      resolvedDexMethod = this.findMethod(callerSuper, methodRef.signature, { includeSuper: true });
    } else {
      // virtual / interface: dispatch on runtime receiver class
      bridgeTargetClass = runtimeClass;
      resolvedDexMethod = this.findMethod(runtimeClass, methodRef.signature, { includeSuper: true });
    }

    if (resolvedDexMethod && resolvedDexMethod.code) {
      this._pushFrame(resolvedDexMethod, args, isStatic ? null : receiver);
      return;
    }

    // Delegate to Android/Java host Framework Bridge
    if (this.bridge && typeof this.bridge.invoke === 'function') {
      this.lastNativeCall = `${bridgeTargetClass}->${methodRef.signature}`;
      try {
        const retVal = this.bridge.invoke({
          kind,
          classType: bridgeTargetClass,
          declaredClassType: methodRef.classType,
          methodName: methodRef.name,
          descriptor: methodRef.descriptor,
          signature: methodRef.signature,
          proto: methodRef.proto,
          receiver,
          args,
          vm: this,
        });
        this._storeNativeResult(methodRef.proto.returnType, retVal, frame.currentInsnPc);
        return;
      } catch (err) {
        if (err instanceof DalvikGuestException) {
          this._unwindException(err.exception);
          return;
        }
        throw err;
      }
    }

    // Minimal Object.<init> fallback when running standalone DalvikVM without Framework Bridge
    if (methodRef.name === '<init>' && methodRef.classType === 'Ljava/lang/Object;') {
      return;
    }

    throw new IllegalInstructionError(`Unresolved Dalvik method: ${bridgeTargetClass}->${methodRef.signature}`, {
      code: ERROR_CODES.E_UNIMPLEMENTED_API,
      pc: frame.currentInsnPc,
      arch: 'dalvik',
      pid: this.pid,
    });
  }

  _intDiv(a, b) {
    const x = a | 0;
    const y = b | 0;
    if (y === 0) {
      this._throwGuest('Ljava/lang/ArithmeticException;', '/ by zero');
      return null;
    }
    if (x === INT32_MIN && y === -1) return INT32_MIN;
    return Math.trunc(x / y) | 0;
  }

  _intRem(a, b) {
    const x = a | 0;
    const y = b | 0;
    if (y === 0) {
      this._throwGuest('Ljava/lang/ArithmeticException;', '/ by zero');
      return null;
    }
    if (x === INT32_MIN && y === -1) return 0;
    return (x % y) | 0;
  }

  _longDiv(a, b) {
    if (b === 0n) {
      this._throwGuest('Ljava/lang/ArithmeticException;', '/ by zero');
      return null;
    }
    if (a === INT64_MIN && b === -1n) return INT64_MIN;
    return BigInt.asIntN(64, a / b);
  }

  _longRem(a, b) {
    if (b === 0n) {
      this._throwGuest('Ljava/lang/ArithmeticException;', '/ by zero');
      return null;
    }
    if (a === INT64_MIN && b === -1n) return 0n;
    return BigInt.asIntN(64, a % b);
  }

  _buildUncaughtFault(executed, pc) {
    const ex = this.lastUncaughtException;
    const exType = capExceptionId(this.getObjectType(ex) || 'Ljava/lang/Throwable;');
    const rawMsg = (typeof ex === 'object' && ex?.fields?.detailMessage) || (typeof ex === 'string' ? ex : exType);
    const msg = capExceptionMessage(rawMsg);
    const fault = new IllegalInstructionError(`Uncaught Dalvik exception ${exType}: ${msg}`, {
      code: ERROR_CODES.E_ILLEGAL_INSTRUCTION,
      pc,
      arch: 'dalvik',
      pid: this.pid,
      details: { exceptionType: exType, message: msg },
    });
    return {
      status: 'FAULT',
      instructionsExecuted: executed,
      fault,
      exception: ex,
    };
  }

  /**
   * Executes up to `budget` Dalvik bytecode instructions strictly synchronously.
   * Returns `{ status: 'YIELD'|'EXITED'|'FAULT', instructionsExecuted, returnValue?, exitCode?, fault?, exception? }`.
   */
  step(budget = 1000) {
    const maxSteps = Number.isFinite(budget) && budget >= 0 ? Math.trunc(budget) : 0;
    let executed = 0;
    this._stepExternalWork = 0;

    if (this.callStack.length === 0) {
      if (this.lastUncaughtException) {
        return this._buildUncaughtFault(0, 0);
      }
      return {
        status: 'EXITED',
        instructionsExecuted: 0,
        returnValue: this.lastReturnValue,
        exitCode: 0,
      };
    }

    while (executed + this._stepExternalWork < maxSteps && this.callStack.length > 0) {
      if (this.totalInstructionsExecuted >= this.maxTotalInstructions) {
        const quotaErr = new QuotaExceededError(
          `Dalvik VM exceeded total instruction quota (${this.maxTotalInstructions})`,
          {
            code: ERROR_CODES.E_CPU_QUOTA,
            quotaType: 'cpu',
            limit: this.maxTotalInstructions,
            actual: this.totalInstructionsExecuted,
            pid: this.pid,
            signal: 'SIGXCPU',
          }
        );
        return { status: 'FAULT', instructionsExecuted: executed, fault: quotaErr };
      }

      const frame = this.callStack[this.callStack.length - 1];
      const insns = frame.insns;
      const pc = frame.pc;
      if (pc < 0 || pc >= insns.length) {
        const fault = new IllegalInstructionError(`Dalvik PC out of bounds: ${pc} (len=${insns.length})`, {
          code: ERROR_CODES.E_ILLEGAL_INSTRUCTION,
          pc,
          arch: 'dalvik',
          pid: this.pid,
        });
        return { status: 'FAULT', instructionsExecuted: executed, fault };
      }

      frame.currentInsnPc = pc;
      const unit0 = insns[pc];
      const op = unit0 & 0xff;
      const AA = (unit0 >>> 8) & 0xff;
      const vA4 = AA & 0x0f;
      const vB4 = (AA >>> 4) & 0x0f;

      executed += 1;
      this.totalInstructionsExecuted += 1;

      try {
        switch (op) {
          // 0x00 nop (reject pseudo-op payloads 0x0100/0x0200/0x0300 or any non-zero high byte!)
          case 0x00:
            if (unit0 !== 0x0000) {
              throw this._illegalInsn(
                `Cannot execute Dalvik pseudo-op payload 0x${unit0.toString(16).padStart(4, '0')} at pc=${pc}`,
                pc,
                { unit0 }
              );
            }
            frame.pc = pc + 1;
            break;

          // 0x01 move vA, vB; 0x07 move-object vA, vB
          case 0x01:
          case 0x07:
            this._checkReg(frame, vA4);
            this._checkReg(frame, vB4);
            frame.intRegs[vA4] = frame.intRegs[vB4];
            frame.refRegs[vA4] = frame.refRegs[vB4];
            frame.pc = pc + 1;
            break;

          // 0x02 move/from16, 0x08 move-object/from16
          case 0x02:
          case 0x08: {
            this._checkInsnUnits(frame, pc, 2);
            const vBBBB = insns[pc + 1];
            this._checkReg(frame, AA);
            this._checkReg(frame, vBBBB);
            frame.intRegs[AA] = frame.intRegs[vBBBB];
            frame.refRegs[AA] = frame.refRegs[vBBBB];
            frame.pc = pc + 2;
            break;
          }

          // 0x03 move/16, 0x09 move-object/16
          case 0x03:
          case 0x09: {
            this._checkInsnUnits(frame, pc, 3);
            const vAAAA = insns[pc + 1];
            const vBBBB = insns[pc + 2];
            this._checkReg(frame, vAAAA);
            this._checkReg(frame, vBBBB);
            frame.intRegs[vAAAA] = frame.intRegs[vBBBB];
            frame.refRegs[vAAAA] = frame.refRegs[vBBBB];
            frame.pc = pc + 3;
            break;
          }

          // 0x04 move-wide (read both halves before writing for overlapping pairs!)
          case 0x04: {
            this._checkWideReg(frame, vA4);
            this._checkWideReg(frame, vB4);
            const lo = frame.intRegs[vB4];
            const hi = frame.intRegs[vB4 + 1];
            frame.intRegs[vA4] = lo;
            frame.intRegs[vA4 + 1] = hi;
            frame.refRegs[vA4] = null;
            frame.refRegs[vA4 + 1] = null;
            frame.pc = pc + 1;
            break;
          }

          // 0x05 move-wide/from16 (read both halves before writing for overlapping pairs!)
          case 0x05: {
            this._checkInsnUnits(frame, pc, 2);
            const vBBBB = insns[pc + 1];
            this._checkWideReg(frame, AA);
            this._checkWideReg(frame, vBBBB);
            const lo = frame.intRegs[vBBBB];
            const hi = frame.intRegs[vBBBB + 1];
            frame.intRegs[AA] = lo;
            frame.intRegs[AA + 1] = hi;
            frame.refRegs[AA] = null;
            frame.refRegs[AA + 1] = null;
            frame.pc = pc + 2;
            break;
          }

          // 0x06 move-wide/16 (read both halves before writing for overlapping pairs!)
          case 0x06: {
            this._checkInsnUnits(frame, pc, 3);
            const vAAAA = insns[pc + 1];
            const vBBBB = insns[pc + 2];
            this._checkWideReg(frame, vAAAA);
            this._checkWideReg(frame, vBBBB);
            const lo = frame.intRegs[vBBBB];
            const hi = frame.intRegs[vBBBB + 1];
            frame.intRegs[vAAAA] = lo;
            frame.intRegs[vAAAA + 1] = hi;
            frame.refRegs[vAAAA] = null;
            frame.refRegs[vAAAA + 1] = null;
            frame.pc = pc + 3;
            break;
          }

          // 0x0A move-result
          case 0x0a:
            this._writeInt(frame, AA, this.lastResultInt);
            frame.pc = pc + 1;
            break;

          // 0x0B move-result-wide
          case 0x0b:
            this._writeLong(frame, AA, this.lastResultWide);
            frame.pc = pc + 1;
            break;

          // 0x0C move-result-object
          case 0x0c:
            this._writeRef(frame, AA, this.lastResultRef);
            frame.pc = pc + 1;
            break;

          // 0x0D move-exception
          case 0x0d:
            this._writeRef(frame, AA, frame.pendingException);
            frame.pendingException = null;
            frame.pc = pc + 1;
            break;

          // 0x0E return-void
          case 0x0e:
            this._popFrame();
            if (this.callStack.length === 0) {
              this.lastReturnValue = undefined;
            }
            break;

          // 0x0F return
          case 0x0f: {
            this._checkReg(frame, AA);
            const retInt = frame.intRegs[AA];
            const retType = frame.method.proto.returnType;
            this.lastResultInt = retInt;
            this.lastResultRef = null;
            this._popFrame();
            if (this.callStack.length === 0) {
              this.lastReturnValue =
                retType === 'F' ? intBitsToFloat(retInt) : retType === 'Z' ? retInt !== 0 : retInt;
            }
            break;
          }

          // 0x10 return-wide
          case 0x10: {
            const retWide = this._readLong(frame, AA);
            const retType = frame.method.proto.returnType;
            this.lastResultWide = retWide;
            this.lastResultRef = null;
            this._popFrame();
            if (this.callStack.length === 0) {
              this.lastReturnValue = retType === 'D' ? longBitsToDouble(retWide) : retWide;
            }
            break;
          }

          // 0x11 return-object
          case 0x11: {
            this._checkReg(frame, AA);
            const retObj = frame.refRegs[AA];
            this.lastResultRef = retObj;
            this.lastResultInt = retObj === null ? 0 : 1;
            this._popFrame();
            if (this.callStack.length === 0) {
              this.lastReturnValue = retObj;
            }
            break;
          }

          // 0x12 const/4 vA, #+B
          case 0x12: {
            const sB = (vB4 << 28) >> 28;
            this._writeInt(frame, vA4, sB);
            frame.pc = pc + 1;
            break;
          }

          // 0x13 const/16 vAA, #+BBBB
          case 0x13: {
            this._checkInsnUnits(frame, pc, 2);
            const sBBBB = (insns[pc + 1] << 16) >> 16;
            this._writeInt(frame, AA, sBBBB);
            frame.pc = pc + 2;
            break;
          }

          // 0x14 const vAA, #+BBBBBBBB
          case 0x14: {
            this._checkInsnUnits(frame, pc, 3);
            const val = (insns[pc + 1] | (insns[pc + 2] << 16)) | 0;
            this._writeInt(frame, AA, val);
            frame.pc = pc + 3;
            break;
          }

          // 0x15 const/high16 vAA, #+BBBB0000
          case 0x15: {
            this._checkInsnUnits(frame, pc, 2);
            const val = (insns[pc + 1] << 16) | 0;
            this._writeInt(frame, AA, val);
            frame.pc = pc + 2;
            break;
          }

          // 0x16 const-wide/16
          case 0x16: {
            this._checkInsnUnits(frame, pc, 2);
            const sBBBB = (insns[pc + 1] << 16) >> 16;
            this._writeLong(frame, AA, BigInt(sBBBB));
            frame.pc = pc + 2;
            break;
          }

          // 0x17 const-wide/32
          case 0x17: {
            this._checkInsnUnits(frame, pc, 3);
            const val = (insns[pc + 1] | (insns[pc + 2] << 16)) | 0;
            this._writeLong(frame, AA, BigInt(val));
            frame.pc = pc + 3;
            break;
          }

          // 0x18 const-wide (51l)
          case 0x18: {
            this._checkInsnUnits(frame, pc, 5);
            const lo = (insns[pc + 1] | (insns[pc + 2] << 16)) >>> 0;
            const hi = (insns[pc + 3] | (insns[pc + 4] << 16)) >>> 0;
            this._writeLong(frame, AA, BigInt.asIntN(64, (BigInt(hi) << 32n) | BigInt(lo)));
            frame.pc = pc + 5;
            break;
          }

          // 0x19 const-wide/high16
          case 0x19: {
            this._checkInsnUnits(frame, pc, 2);
            const val = BigInt.asIntN(64, BigInt(insns[pc + 1]) << 48n);
            this._writeLong(frame, AA, val);
            frame.pc = pc + 2;
            break;
          }

          // 0x1A const-string
          case 0x1a: {
            this._checkInsnUnits(frame, pc, 2);
            const str = this._getString(frame, insns[pc + 1]);
            this._writeRef(frame, AA, str);
            frame.pc = pc + 2;
            break;
          }

          // 0x1B const-string/jumbo
          case 0x1b: {
            this._checkInsnUnits(frame, pc, 3);
            const strIdx = (insns[pc + 1] | (insns[pc + 2] << 16)) >>> 0;
            const str = this._getString(frame, strIdx);
            this._writeRef(frame, AA, str);
            frame.pc = pc + 3;
            break;
          }

          // 0x1C const-class
          case 0x1c: {
            this._checkInsnUnits(frame, pc, 2);
            const typeDesc = this._getType(frame, insns[pc + 1]);
            this._writeRef(frame, AA, this.createClassObject(typeDesc));
            frame.pc = pc + 2;
            break;
          }

          // 0x1D monitor-enter, 0x1E monitor-exit
          case 0x1d:
          case 0x1e: {
            this._checkReg(frame, AA);
            if (frame.refRegs[AA] === null) {
              this._throwGuest('Ljava/lang/NullPointerException;', 'Monitor on null reference');
            } else {
              frame.pc = pc + 1;
            }
            break;
          }

          // 0x1F check-cast
          case 0x1f: {
            this._checkInsnUnits(frame, pc, 2);
            this._checkReg(frame, AA);
            const targetType = this._getType(frame, insns[pc + 1]);
            const obj = frame.refRegs[AA];
            if (obj !== null && !this.isAssignableTo(this.getObjectType(obj), targetType)) {
              this._throwGuest(
                'Ljava/lang/ClassCastException;',
                `Cannot cast ${capExceptionId(this.getObjectType(obj))} to ${capExceptionId(targetType)}`
              );
            } else {
              frame.pc = pc + 2;
            }
            break;
          }

          // 0x20 instance-of
          case 0x20: {
            this._checkInsnUnits(frame, pc, 2);
            this._checkReg(frame, vA4);
            this._checkReg(frame, vB4);
            const targetType = this._getType(frame, insns[pc + 1]);
            const obj = frame.refRegs[vB4];
            const ok = obj !== null && this.isAssignableTo(this.getObjectType(obj), targetType);
            this._writeInt(frame, vA4, ok ? 1 : 0);
            frame.pc = pc + 2;
            break;
          }

          // 0x21 array-length
          case 0x21: {
            this._checkReg(frame, vA4);
            this._checkReg(frame, vB4);
            const arr = frame.refRegs[vB4];
            if (arr === null) {
              this._throwGuest('Ljava/lang/NullPointerException;', 'array-length on null');
            } else if (typeof arr !== 'object' || arr.__dalvikType !== 'array') {
              throw this._illegalInsn('array-length target is not an array', pc);
            } else {
              this._writeInt(frame, vA4, arr.length);
              frame.pc = pc + 1;
            }
            break;
          }

          // 0x22 new-instance
          case 0x22: {
            this._checkInsnUnits(frame, pc, 2);
            this._checkReg(frame, AA);
            const classType = this._getType(frame, insns[pc + 1]);
            if (!classType.startsWith('L')) {
              throw this._illegalInsn(`new-instance requires class descriptor, got ${classType}`, pc);
            }
            if (this.classesByName.has(classType) && !this.initializedClasses.has(classType)) {
              if (this._ensureClassInitialized(classType, frame)) break;
            }
            const obj = this.createObject(classType);
            this._writeRef(frame, AA, obj);
            frame.pc = pc + 2;
            break;
          }

          // 0x23 new-array
          case 0x23: {
            this._checkInsnUnits(frame, pc, 2);
            this._checkReg(frame, vA4);
            this._checkReg(frame, vB4);
            const arrType = this._getType(frame, insns[pc + 1]);
            if (!arrType.startsWith('[')) {
              throw this._illegalInsn(`new-array requires array type descriptor, got ${arrType}`, pc);
            }
            const len = frame.intRegs[vB4] | 0;
            if (len < 0) {
              this._throwGuest('Ljava/lang/NegativeArraySizeException;', `Negative array length: ${len}`);
              break;
            }
            this._writeRef(frame, vA4, this.createArray(arrType, len));
            frame.pc = pc + 2;
            break;
          }

          // 0x24 filled-new-array (35c), 0x25 filled-new-array/range (3rc)
          case 0x24:
          case 0x25: {
            this._checkInsnUnits(frame, pc, 3);
            const arrType = this._getType(frame, insns[pc + 1]);
            if (!arrType.startsWith('[')) {
              throw this._illegalInsn(`filled-new-array requires array type descriptor, got ${arrType}`, pc);
            }
            let argRegs;
            if (op === 0x24) {
              const count = (unit0 >>> 12) & 0x0f;
              if (count > 5) {
                throw this._illegalInsn(`Invalid 35c filled-new-array register count ${count} (> 5)`, pc);
              }
              const G = (unit0 >>> 8) & 0x0f;
              const u2 = insns[pc + 2];
              argRegs = [u2 & 0xf, (u2 >>> 4) & 0xf, (u2 >>> 8) & 0xf, (u2 >>> 12) & 0xf, G].slice(0, count);
              for (let i = 0; i < argRegs.length; i++) {
                this._checkReg(frame, argRegs[i]);
              }
            } else {
              const first = insns[pc + 2];
              if (AA > 0 && first + AA > frame.code.registersSize) {
                throw this._illegalInsn(
                  `Dalvik 3rc filled-new-array register range v${first}..v${first + AA - 1} out of bounds (registersSize=${frame.code.registersSize})`,
                  pc
                );
              }
              argRegs = Array.from({ length: AA }, (_, k) => first + k);
            }
            const elemType = arrType.slice(1);
            if (elemType === 'J' || elemType === 'D') {
              throw this._illegalInsn(`filled-new-array does not support wide element type ${arrType}`, pc);
            }
            const isRefElem = elemType.startsWith('L') || elemType.startsWith('[');
            if (isRefElem && elemType !== 'Ljava/lang/Object;') {
              let storeErr = null;
              for (let i = 0; i < argRegs.length; i++) {
                const val = frame.refRegs[argRegs[i]];
                if (val !== null && val !== undefined) {
                  const valType = this.getObjectType(val);
                  if (!this.isAssignableTo(valType, elemType)) {
                    storeErr = `Cannot store ${capExceptionId(valType)} into array of ${capExceptionId(elemType)}`;
                    break;
                  }
                }
              }
              if (storeErr) {
                this._throwGuest('Ljava/lang/ArrayStoreException;', storeErr);
                break;
              }
            }
            const arr = this.createArray(arrType, argRegs.length);
            for (let i = 0; i < argRegs.length; i++) {
              if (isRefElem) arr.data[i] = frame.refRegs[argRegs[i]];
              else if (arr.elementType === 'F') arr.data[i] = intBitsToFloat(frame.intRegs[argRegs[i]]);
              else arr.data[i] = frame.intRegs[argRegs[i]];
            }
            this.lastResultRef = arr;
            this.lastResultInt = arr.id;
            frame.pc = pc + 3;
            break;
          }

          // 0x26 fill-array-data (31t)
          case 0x26: {
            this._checkInsnUnits(frame, pc, 3);
            this._checkReg(frame, AA);
            const arr = frame.refRegs[AA];
            if (arr === null) {
              this._throwGuest('Ljava/lang/NullPointerException;', 'fill-array-data on null');
              break;
            }
            if (typeof arr !== 'object' || arr.__dalvikType !== 'array') {
              throw this._illegalInsn('fill-array-data target is not an array', pc);
            }
            const relOff = (insns[pc + 1] | (insns[pc + 2] << 16)) | 0;
            const pay = pc + relOff;
            if (pay < 0 || pay + 4 > insns.length || insns[pay] !== 0x0300) {
              throw this._illegalInsn('Invalid fill-array-data payload', pc);
            }
            const elemWidth = insns[pay + 1];
            const expectedWidth = this._primitiveArrayElementWidth(arr.elementType);
            if (
              expectedWidth === 0 ||
              (elemWidth !== 1 && elemWidth !== 2 && elemWidth !== 4 && elemWidth !== 8) ||
              elemWidth !== expectedWidth
            ) {
              throw this._illegalInsn(
                `Invalid fill-array-data element_width=${elemWidth} for array type ${arr.classType}`,
                pc
              );
            }
            const size = (insns[pay + 2] | (insns[pay + 3] << 16)) >>> 0;
            const unitsNeeded = Math.ceil((size * elemWidth) / 2);
            if (pay + 4 + unitsNeeded > insns.length || size > arr.length) {
              throw this._illegalInsn(
                `fill-array-data payload out of bounds (size=${size}, elemWidth=${elemWidth}, arrLen=${arr.length}, insnsLen=${insns.length})`,
                pc
              );
            }
            const dataBase = pay + 4;
            if (elemWidth === 1) {
              const isBool = arr.elementType === 'Z';
              for (let i = 0; i < size; i++) {
                const w = insns[dataBase + (i >>> 1)];
                const b = (i & 1) === 0 ? w & 0xff : (w >>> 8) & 0xff;
                arr.data[i] = isBool ? (b !== 0 ? 1 : 0) : (b << 24) >> 24;
              }
            } else if (elemWidth === 2) {
              const isChar = arr.elementType === 'C';
              for (let i = 0; i < size; i++) {
                const w = insns[dataBase + i];
                arr.data[i] = isChar ? w : (w << 16) >> 16;
              }
            } else if (elemWidth === 4) {
              const isFloat = arr.elementType === 'F';
              for (let i = 0; i < size; i++) {
                const p = dataBase + i * 2;
                const bits = (insns[p] | (insns[p + 1] << 16)) | 0;
                arr.data[i] = isFloat ? intBitsToFloat(bits) : bits;
              }
            } else {
              const isDouble = arr.elementType === 'D';
              for (let i = 0; i < size; i++) {
                const p = dataBase + i * 4;
                const lo = (insns[p] | (insns[p + 1] << 16)) >>> 0;
                const hi = (insns[p + 2] | (insns[p + 3] << 16)) >>> 0;
                const bits = BigInt.asIntN(64, (BigInt(hi) << 32n) | BigInt(lo));
                arr.data[i] = isDouble ? longBitsToDouble(bits) : bits;
              }
            }
            frame.pc = pc + 3;
            break;
          }

          // 0x27 throw vAA
          case 0x27: {
            this._checkReg(frame, AA);
            const exObj = frame.refRegs[AA];
            if (exObj === null) {
              this._throwGuest('Ljava/lang/NullPointerException;', 'throw null');
            } else {
              this._unwindException(exObj);
            }
            break;
          }

          // 0x28 goto (10t)
          case 0x28: {
            const off = (AA << 24) >> 24;
            frame.pc = pc + off;
            break;
          }

          // 0x29 goto/16 (20t)
          case 0x29: {
            this._checkInsnUnits(frame, pc, 2);
            const off = (insns[pc + 1] << 16) >> 16;
            frame.pc = pc + off;
            break;
          }

          // 0x2A goto/32 (30t)
          case 0x2a: {
            this._checkInsnUnits(frame, pc, 3);
            const off = (insns[pc + 1] | (insns[pc + 2] << 16)) | 0;
            frame.pc = pc + off;
            break;
          }

          // 0x2B packed-switch (31t)
          case 0x2b: {
            this._checkInsnUnits(frame, pc, 3);
            this._checkReg(frame, AA);
            const val = frame.intRegs[AA] | 0;
            const relOff = (insns[pc + 1] | (insns[pc + 2] << 16)) | 0;
            const pay = pc + relOff;
            if (pay < 0 || pay + 4 > insns.length || insns[pay] !== 0x0100) {
              throw this._illegalInsn('Invalid packed-switch payload', pc);
            }
            const size = insns[pay + 1];
            if (pay + 4 + size * 2 > insns.length) {
              throw this._illegalInsn(
                `Truncated packed-switch payload (size=${size}, pay=${pay}, len=${insns.length})`,
                pc
              );
            }
            const firstKey = (insns[pay + 2] | (insns[pay + 3] << 16)) | 0;
            const idx = val - firstKey;
            if (idx >= 0 && idx < size) {
              const tPos = pay + 4 + idx * 2;
              const target = (insns[tPos] | (insns[tPos + 1] << 16)) | 0;
              frame.pc = pc + target;
            } else {
              frame.pc = pc + 3;
            }
            break;
          }

          // 0x2C sparse-switch (31t)
          case 0x2c: {
            this._checkInsnUnits(frame, pc, 3);
            this._checkReg(frame, AA);
            const val = frame.intRegs[AA] | 0;
            const relOff = (insns[pc + 1] | (insns[pc + 2] << 16)) | 0;
            const pay = pc + relOff;
            if (pay < 0 || pay + 2 > insns.length || insns[pay] !== 0x0200) {
              throw this._illegalInsn('Invalid sparse-switch payload', pc);
            }
            const size = insns[pay + 1];
            if (pay + 2 + size * 4 > insns.length) {
              throw this._illegalInsn(
                `Truncated sparse-switch payload (size=${size}, pay=${pay}, len=${insns.length})`,
                pc
              );
            }
            const keysBase = pay + 2;
            const targetsBase = keysBase + size * 2;
            let lo = 0;
            let hi = size - 1;
            let matched = false;
            while (lo <= hi) {
              const mid = (lo + hi) >>> 1;
              const kPos = keysBase + mid * 2;
              const key = (insns[kPos] | (insns[kPos + 1] << 16)) | 0;
              if (key === val) {
                const tPos = targetsBase + mid * 2;
                const target = (insns[tPos] | (insns[tPos + 1] << 16)) | 0;
                frame.pc = pc + target;
                matched = true;
                break;
              }
              if (key < val) lo = mid + 1;
              else hi = mid - 1;
            }
            if (!matched) frame.pc = pc + 3;
            break;
          }

          // 0x2D..0x31 comparisons
          case 0x2d: // cmpl-float
          case 0x2e: { // cmpg-float
            this._checkInsnUnits(frame, pc, 2);
            const vBB = insns[pc + 1] & 0xff;
            const vCC = (insns[pc + 1] >>> 8) & 0xff;
            this._checkReg(frame, AA);
            this._checkReg(frame, vBB);
            this._checkReg(frame, vCC);
            const a = intBitsToFloat(frame.intRegs[vBB]);
            const b = intBitsToFloat(frame.intRegs[vCC]);
            let res;
            if (Number.isNaN(a) || Number.isNaN(b)) res = op === 0x2d ? -1 : 1;
            else res = a < b ? -1 : a > b ? 1 : 0;
            this._writeInt(frame, AA, res);
            frame.pc = pc + 2;
            break;
          }
          case 0x2f: // cmpl-double
          case 0x30: { // cmpg-double
            this._checkInsnUnits(frame, pc, 2);
            const vBB = insns[pc + 1] & 0xff;
            const vCC = (insns[pc + 1] >>> 8) & 0xff;
            this._checkReg(frame, AA);
            const a = this._readDouble(frame, vBB);
            const b = this._readDouble(frame, vCC);
            let res;
            if (Number.isNaN(a) || Number.isNaN(b)) res = op === 0x2f ? -1 : 1;
            else res = a < b ? -1 : a > b ? 1 : 0;
            this._writeInt(frame, AA, res);
            frame.pc = pc + 2;
            break;
          }
          case 0x31: { // cmp-long
            this._checkInsnUnits(frame, pc, 2);
            const vBB = insns[pc + 1] & 0xff;
            const vCC = (insns[pc + 1] >>> 8) & 0xff;
            this._checkReg(frame, AA);
            const a = this._readLong(frame, vBB);
            const b = this._readLong(frame, vCC);
            this._writeInt(frame, AA, a < b ? -1 : a > b ? 1 : 0);
            frame.pc = pc + 2;
            break;
          }

          // 0x32..0x37 if-eq/ne/lt/ge/gt/le (22t)
          case 0x32:
          case 0x33:
          case 0x34:
          case 0x35:
          case 0x36:
          case 0x37: {
            this._checkInsnUnits(frame, pc, 2);
            this._checkReg(frame, vA4);
            this._checkReg(frame, vB4);
            const off = (insns[pc + 1] << 16) >> 16;
            const rA = frame.refRegs[vA4];
            const rB = frame.refRegs[vB4];
            const iA = frame.intRegs[vA4];
            const iB = frame.intRegs[vB4];
            let cond = false;
            if (op === 0x32) cond = rA !== null || rB !== null ? rA === rB : iA === iB;
            else if (op === 0x33) cond = rA !== null || rB !== null ? rA !== rB : iA !== iB;
            else if (op === 0x34) cond = iA < iB;
            else if (op === 0x35) cond = iA >= iB;
            else if (op === 0x36) cond = iA > iB;
            else cond = iA <= iB;
            frame.pc = cond ? pc + off : pc + 2;
            break;
          }

          // 0x38..0x3D if-eqz/nez/ltz/gez/gtz/lez (21t)
          case 0x38:
          case 0x39:
          case 0x3a:
          case 0x3b:
          case 0x3c:
          case 0x3d: {
            this._checkInsnUnits(frame, pc, 2);
            this._checkReg(frame, AA);
            const off = (insns[pc + 1] << 16) >> 16;
            const rA = frame.refRegs[AA];
            const iA = frame.intRegs[AA];
            let cond = false;
            if (op === 0x38) cond = rA === null && iA === 0;
            else if (op === 0x39) cond = rA !== null || iA !== 0;
            else if (op === 0x3a) cond = iA < 0;
            else if (op === 0x3b) cond = iA >= 0;
            else if (op === 0x3c) cond = iA > 0;
            else cond = iA <= 0;
            frame.pc = cond ? pc + off : pc + 2;
            break;
          }

          // 0x44..0x4A aget* (23x)
          case 0x44:
          case 0x45:
          case 0x46:
          case 0x47:
          case 0x48:
          case 0x49:
          case 0x4a: {
            this._checkInsnUnits(frame, pc, 2);
            const vBB = insns[pc + 1] & 0xff;
            const vCC = (insns[pc + 1] >>> 8) & 0xff;
            if (op === 0x45) this._checkWideReg(frame, AA);
            else this._checkReg(frame, AA);
            this._checkReg(frame, vBB);
            this._checkReg(frame, vCC);
            const arr = frame.refRegs[vBB];
            const idx = frame.intRegs[vCC] | 0;
            if (arr === null) {
              this._throwGuest('Ljava/lang/NullPointerException;', 'aget on null array');
              break;
            }
            if (typeof arr !== 'object' || arr.__dalvikType !== 'array') {
              throw this._illegalInsn('aget target is not an array', pc);
            }
            if (idx < 0 || idx >= arr.length) {
              this._throwGuest('Ljava/lang/ArrayIndexOutOfBoundsException;', `index ${idx}, length ${arr.length}`);
              break;
            }
            if (op === 0x45) {
              // aget-wide
              if (arr.elementType !== 'J' && arr.elementType !== 'D') {
                throw this._illegalInsn(`aget-wide on non-wide array type ${arr.classType}`, pc);
              }
              if (arr.elementType === 'D') this._writeDouble(frame, AA, arr.data[idx]);
              else this._writeLong(frame, AA, BigInt(arr.data[idx]));
            } else if (op === 0x46) {
              // aget-object
              if (!arr.elementType.startsWith('L') && !arr.elementType.startsWith('[')) {
                throw this._illegalInsn(`aget-object on primitive array type ${arr.classType}`, pc);
              }
              this._writeRef(frame, AA, arr.data[idx]);
            } else if (op === 0x44 && arr.elementType === 'F') {
              this._writeInt(frame, AA, floatToIntBits(arr.data[idx]));
            } else {
              if (arr.elementType === 'J' || arr.elementType === 'D' || arr.elementType.startsWith('L') || arr.elementType.startsWith('[')) {
                throw this._illegalInsn(`Incompatible aget opcode 0x${op.toString(16)} for array type ${arr.classType}`, pc);
              }
              this._writeInt(frame, AA, arr.data[idx] | 0);
            }
            frame.pc = pc + 2;
            break;
          }

          // 0x4B..0x51 aput* (23x)
          case 0x4b:
          case 0x4c:
          case 0x4d:
          case 0x4e:
          case 0x4f:
          case 0x50:
          case 0x51: {
            this._checkInsnUnits(frame, pc, 2);
            const vBB = insns[pc + 1] & 0xff;
            const vCC = (insns[pc + 1] >>> 8) & 0xff;
            if (op === 0x4c) this._checkWideReg(frame, AA);
            else this._checkReg(frame, AA);
            this._checkReg(frame, vBB);
            this._checkReg(frame, vCC);
            const arr = frame.refRegs[vBB];
            const idx = frame.intRegs[vCC] | 0;
            if (arr === null) {
              this._throwGuest('Ljava/lang/NullPointerException;', 'aput on null array');
              break;
            }
            if (typeof arr !== 'object' || arr.__dalvikType !== 'array') {
              throw this._illegalInsn('aput target is not an array', pc);
            }
            if (idx < 0 || idx >= arr.length) {
              this._throwGuest('Ljava/lang/ArrayIndexOutOfBoundsException;', `index ${idx}, length ${arr.length}`);
              break;
            }
            if (op === 0x4c) {
              if (arr.elementType !== 'J' && arr.elementType !== 'D') {
                throw this._illegalInsn(`aput-wide on non-wide array type ${arr.classType}`, pc);
              }
              if (arr.elementType === 'D') arr.data[idx] = this._readDouble(frame, AA);
              else arr.data[idx] = this._readLong(frame, AA);
            } else if (op === 0x4d) {
              if (!arr.elementType.startsWith('L') && !arr.elementType.startsWith('[')) {
                throw this._illegalInsn(`aput-object on primitive array type ${arr.classType}`, pc);
              }
              const val = frame.refRegs[AA];
              if (val !== null && val !== undefined) {
                const valType = this.getObjectType(val);
                if (!this.isAssignableTo(valType, arr.elementType)) {
                  this._throwGuest(
                    'Ljava/lang/ArrayStoreException;',
                    `Cannot store ${capExceptionId(valType)} into array of ${capExceptionId(arr.elementType)}`
                  );
                  break;
                }
              }
              arr.data[idx] = val ?? null;
            } else if (op === 0x4b && arr.elementType === 'F') {
              arr.data[idx] = intBitsToFloat(frame.intRegs[AA]);
            } else if (op === 0x4e) {
              if (arr.elementType !== 'Z' && arr.elementType !== 'B') {
                throw this._illegalInsn(`aput-boolean on incompatible array type ${arr.classType}`, pc);
              }
              arr.data[idx] = frame.intRegs[AA] !== 0 ? 1 : 0;
            } else {
              if (arr.elementType === 'J' || arr.elementType === 'D' || arr.elementType.startsWith('L') || arr.elementType.startsWith('[')) {
                throw this._illegalInsn(`Incompatible aput opcode 0x${op.toString(16)} for array type ${arr.classType}`, pc);
              }
              arr.data[idx] = frame.intRegs[AA];
            }
            frame.pc = pc + 2;
            break;
          }

          // 0x52..0x58 iget* (22c)
          case 0x52:
          case 0x53:
          case 0x54:
          case 0x55:
          case 0x56:
          case 0x57:
          case 0x58: {
            this._checkInsnUnits(frame, pc, 2);
            if (op === 0x53) this._checkWideReg(frame, vA4);
            else this._checkReg(frame, vA4);
            this._checkReg(frame, vB4);
            const fRef = this._getField(frame, insns[pc + 1]);
            this._checkFieldOpcode(op, 0x52, fRef.type, pc);
            const obj = frame.refRegs[vB4];
            if (obj === null) {
              this._throwGuest('Ljava/lang/NullPointerException;', 'iget on null object');
              break;
            }
            const val = obj.fields ? obj.fields[fRef.name] : undefined;
            if (op === 0x53) {
              if (fRef.type === 'D') this._writeDouble(frame, vA4, toSafeNumber(val));
              else {
                const bigVal =
                  typeof val === 'bigint'
                    ? val
                    : typeof val === 'number'
                      ? floatToJavaLong(val)
                      : 0n;
                this._writeLong(frame, vA4, bigVal);
              }
            } else if (op === 0x54) {
              this._writeRef(frame, vA4, val ?? null);
            } else if (op === 0x52 && fRef.type === 'F') {
              this._writeInt(frame, vA4, floatToIntBits(toSafeNumber(val)));
            } else {
              this._writeInt(frame, vA4, toInt32(val));
            }
            frame.pc = pc + 2;
            break;
          }

          // 0x59..0x5F iput* (22c)
          case 0x59:
          case 0x5a:
          case 0x5b:
          case 0x5c:
          case 0x5d:
          case 0x5e:
          case 0x5f: {
            this._checkInsnUnits(frame, pc, 2);
            if (op === 0x5a) this._checkWideReg(frame, vA4);
            else this._checkReg(frame, vA4);
            this._checkReg(frame, vB4);
            const fRef = this._getField(frame, insns[pc + 1]);
            this._checkFieldOpcode(op, 0x59, fRef.type, pc);
            const obj = frame.refRegs[vB4];
            if (obj === null) {
              this._throwGuest('Ljava/lang/NullPointerException;', 'iput on null object');
              break;
            }
            if (typeof obj !== 'object') {
              throw this._illegalInsn(`iput target is not a mutable object instance`, pc);
            }
            if (Object.isFrozen(obj) || (obj.fields && Object.isFrozen(obj.fields))) {
              frame.pc = pc + 2;
              break;
            }
            const needsFieldsObj = !obj.fields;
            const isNewProp = needsFieldsObj || !(fRef.name in obj.fields);
            const addBytes = (needsFieldsObj ? 128 : 0) + (isNewProp ? 128 : 0);
            if (addBytes > 0) {
              this.chargeHeap(addBytes, `iput ${capExceptionId(fRef.name)}`);
            }
            if (needsFieldsObj) {
              obj.fields = Object.create(null);
            }
            if (op === 0x5a) {
              obj.fields[fRef.name] = fRef.type === 'D' ? this._readDouble(frame, vA4) : this._readLong(frame, vA4);
            } else if (op === 0x5b) {
              obj.fields[fRef.name] = frame.refRegs[vA4];
            } else if (op === 0x59 && fRef.type === 'F') {
              obj.fields[fRef.name] = intBitsToFloat(frame.intRegs[vA4]);
            } else if (op === 0x5c) {
              obj.fields[fRef.name] = frame.intRegs[vA4] !== 0;
            } else if (op === 0x5d) {
              obj.fields[fRef.name] = (frame.intRegs[vA4] << 24) >> 24;
            } else if (op === 0x5e) {
              obj.fields[fRef.name] = frame.intRegs[vA4] & 0xffff;
            } else if (op === 0x5f) {
              obj.fields[fRef.name] = (frame.intRegs[vA4] << 16) >> 16;
            } else {
              obj.fields[fRef.name] = frame.intRegs[vA4] | 0;
            }
            frame.pc = pc + 2;
            break;
          }

          // 0x60..0x66 sget* (21c)
          case 0x60:
          case 0x61:
          case 0x62:
          case 0x63:
          case 0x64:
          case 0x65:
          case 0x66: {
            this._checkInsnUnits(frame, pc, 2);
            if (op === 0x61) this._checkWideReg(frame, AA);
            else this._checkReg(frame, AA);
            const fRef = this._getField(frame, insns[pc + 1]);
            this._checkFieldOpcode(op, 0x60, fRef.type, pc);
            if (this.classesByName.has(fRef.classType) && !this.initializedClasses.has(fRef.classType)) {
              if (this._ensureClassInitialized(fRef.classType, frame)) break;
            }
            let val;
            if (!this.classesByName.has(fRef.classType) && this.bridge?.getStaticField) {
              val = this.bridge.getStaticField(fRef.classType, fRef.name, fRef.type);
            } else {
              const store = this._getStaticStore(fRef.classType);
              val = store[fRef.name];
            }
            if (op === 0x61) {
              if (fRef.type === 'D') this._writeDouble(frame, AA, toSafeNumber(val));
              else {
                const bigVal =
                  typeof val === 'bigint'
                    ? val
                    : typeof val === 'number'
                      ? floatToJavaLong(val)
                      : 0n;
                this._writeLong(frame, AA, bigVal);
              }
            } else if (op === 0x62) {
              this._writeRef(frame, AA, val ?? null);
            } else if (op === 0x60 && fRef.type === 'F') {
              this._writeInt(frame, AA, floatToIntBits(toSafeNumber(val)));
            } else {
              this._writeInt(frame, AA, toInt32(val));
            }
            frame.pc = pc + 2;
            break;
          }

          // 0x67..0x6D sput* (21c)
          case 0x67:
          case 0x68:
          case 0x69:
          case 0x6a:
          case 0x6b:
          case 0x6c:
          case 0x6d: {
            this._checkInsnUnits(frame, pc, 2);
            if (op === 0x68) this._checkWideReg(frame, AA);
            else this._checkReg(frame, AA);
            const fRef = this._getField(frame, insns[pc + 1]);
            this._checkFieldOpcode(op, 0x67, fRef.type, pc);
            if (this.classesByName.has(fRef.classType) && !this.initializedClasses.has(fRef.classType)) {
              if (this._ensureClassInitialized(fRef.classType, frame)) break;
            }
            const store = this._getStaticStore(fRef.classType);
            if (op === 0x68) {
              store[fRef.name] = fRef.type === 'D' ? this._readDouble(frame, AA) : this._readLong(frame, AA);
            } else if (op === 0x69) {
              store[fRef.name] = frame.refRegs[AA];
            } else if (op === 0x67 && fRef.type === 'F') {
              store[fRef.name] = intBitsToFloat(frame.intRegs[AA]);
            } else if (op === 0x6a) {
              store[fRef.name] = frame.intRegs[AA] !== 0;
            } else if (op === 0x6b) {
              store[fRef.name] = (frame.intRegs[AA] << 24) >> 24;
            } else if (op === 0x6c) {
              store[fRef.name] = frame.intRegs[AA] & 0xffff;
            } else if (op === 0x6d) {
              store[fRef.name] = (frame.intRegs[AA] << 16) >> 16;
            } else {
              store[fRef.name] = frame.intRegs[AA] | 0;
            }
            frame.pc = pc + 2;
            break;
          }

          // 0x6E..0x72 invoke-* (35c)
          case 0x6e:
          case 0x6f:
          case 0x70:
          case 0x71:
          case 0x72: {
            this._checkInsnUnits(frame, pc, 3);
            const count = (unit0 >>> 12) & 0x0f;
            if (count > 5) {
              throw this._illegalInsn(`Invalid 35c invoke register count ${count} (> 5)`, pc);
            }
            const G = (unit0 >>> 8) & 0x0f;
            const methodIdx = insns[pc + 1];
            const u2 = insns[pc + 2];
            const argRegs = [u2 & 0xf, (u2 >>> 4) & 0xf, (u2 >>> 8) & 0xf, (u2 >>> 12) & 0xf, G].slice(0, count);
            const kinds = ['virtual', 'super', 'direct', 'static', 'interface'];
            frame.pc = pc + 3;
            this._handleInvoke(frame, kinds[op - 0x6e], methodIdx, argRegs);
            break;
          }

          // 0x74..0x78 invoke-*/range (3rc)
          case 0x74:
          case 0x75:
          case 0x76:
          case 0x77:
          case 0x78: {
            this._checkInsnUnits(frame, pc, 3);
            const methodIdx = insns[pc + 1];
            const firstReg = insns[pc + 2];
            if (AA > 0 && firstReg + AA > frame.code.registersSize) {
              throw this._illegalInsn(
                `Dalvik 3rc invoke register range v${firstReg}..v${firstReg + AA - 1} out of bounds (registersSize=${frame.code.registersSize})`,
                pc
              );
            }
            const argRegs = Array.from({ length: AA }, (_, k) => firstReg + k);
            const kinds = ['virtual', 'super', 'direct', 'static', 'interface'];
            frame.pc = pc + 3;
            this._handleInvoke(frame, kinds[op - 0x74], methodIdx, argRegs);
            break;
          }

          // 0x7B..0x8F unary & conversions (12x)
          case 0x7b: this._checkReg(frame, vB4); this._writeInt(frame, vA4, (-frame.intRegs[vB4]) | 0); frame.pc = pc + 1; break;
          case 0x7c: this._checkReg(frame, vB4); this._writeInt(frame, vA4, (~frame.intRegs[vB4]) | 0); frame.pc = pc + 1; break;
          case 0x7d: this._writeLong(frame, vA4, BigInt.asIntN(64, -this._readLong(frame, vB4))); frame.pc = pc + 1; break;
          case 0x7e: this._writeLong(frame, vA4, BigInt.asIntN(64, ~this._readLong(frame, vB4))); frame.pc = pc + 1; break;
          case 0x7f: this._checkReg(frame, vB4); this._writeInt(frame, vA4, floatToIntBits(-intBitsToFloat(frame.intRegs[vB4]))); frame.pc = pc + 1; break;
          case 0x80: this._writeDouble(frame, vA4, -this._readDouble(frame, vB4)); frame.pc = pc + 1; break;
          case 0x81: this._checkReg(frame, vB4); this._writeLong(frame, vA4, BigInt(frame.intRegs[vB4] | 0)); frame.pc = pc + 1; break;
          case 0x82: this._checkReg(frame, vB4); this._writeInt(frame, vA4, floatToIntBits(Math.fround(frame.intRegs[vB4] | 0))); frame.pc = pc + 1; break;
          case 0x83: this._checkReg(frame, vB4); this._writeDouble(frame, vA4, Number(frame.intRegs[vB4] | 0)); frame.pc = pc + 1; break;
          case 0x84: this._writeInt(frame, vA4, Number(BigInt.asIntN(32, this._readLong(frame, vB4)))); frame.pc = pc + 1; break;
          case 0x85: this._writeInt(frame, vA4, floatToIntBits(Math.fround(Number(this._readLong(frame, vB4))))); frame.pc = pc + 1; break;
          case 0x86: this._writeDouble(frame, vA4, Number(this._readLong(frame, vB4))); frame.pc = pc + 1; break;
          case 0x87: this._checkReg(frame, vB4); this._writeInt(frame, vA4, floatToJavaInt(intBitsToFloat(frame.intRegs[vB4]))); frame.pc = pc + 1; break;
          case 0x88: this._checkReg(frame, vB4); this._writeLong(frame, vA4, floatToJavaLong(intBitsToFloat(frame.intRegs[vB4]))); frame.pc = pc + 1; break;
          case 0x89: this._checkReg(frame, vB4); this._writeDouble(frame, vA4, intBitsToFloat(frame.intRegs[vB4])); frame.pc = pc + 1; break;
          case 0x8a: this._writeInt(frame, vA4, floatToJavaInt(this._readDouble(frame, vB4))); frame.pc = pc + 1; break;
          case 0x8b: this._writeLong(frame, vA4, floatToJavaLong(this._readDouble(frame, vB4))); frame.pc = pc + 1; break;
          case 0x8c: this._writeInt(frame, vA4, floatToIntBits(Math.fround(this._readDouble(frame, vB4)))); frame.pc = pc + 1; break;
          case 0x8d: this._checkReg(frame, vB4); this._writeInt(frame, vA4, (frame.intRegs[vB4] << 24) >> 24); frame.pc = pc + 1; break;
          case 0x8e: this._checkReg(frame, vB4); this._writeInt(frame, vA4, frame.intRegs[vB4] & 0xffff); frame.pc = pc + 1; break;
          case 0x8f: this._checkReg(frame, vB4); this._writeInt(frame, vA4, (frame.intRegs[vB4] << 16) >> 16); frame.pc = pc + 1; break;

          // 0x90..0x9A int binary ops (23x)
          case 0x90: case 0x91: case 0x92: case 0x93: case 0x94:
          case 0x95: case 0x96: case 0x97: case 0x98: case 0x99: case 0x9a: {
            this._checkInsnUnits(frame, pc, 2);
            const vBB = insns[pc + 1] & 0xff;
            const vCC = (insns[pc + 1] >>> 8) & 0xff;
            this._checkReg(frame, AA);
            this._checkReg(frame, vBB);
            this._checkReg(frame, vCC);
            const a = frame.intRegs[vBB] | 0;
            const b = frame.intRegs[vCC] | 0;
            let res;
            if (op === 0x90) res = (a + b) | 0;
            else if (op === 0x91) res = (a - b) | 0;
            else if (op === 0x92) res = Math.imul(a, b);
            else if (op === 0x93) { res = this._intDiv(a, b); if (res === null) break; }
            else if (op === 0x94) { res = this._intRem(a, b); if (res === null) break; }
            else if (op === 0x95) res = a & b;
            else if (op === 0x96) res = a | b;
            else if (op === 0x97) res = a ^ b;
            else if (op === 0x98) res = a << (b & 31);
            else if (op === 0x99) res = a >> (b & 31);
            else res = (a >>> (b & 31)) | 0;
            this._writeInt(frame, AA, res);
            frame.pc = pc + 2;
            break;
          }

          // 0x9B..0xA5 long binary ops (23x)
          case 0x9b: case 0x9c: case 0x9d: case 0x9e: case 0x9f:
          case 0xa0: case 0xa1: case 0xa2: case 0xa3: case 0xa4: case 0xa5: {
            this._checkInsnUnits(frame, pc, 2);
            const vBB = insns[pc + 1] & 0xff;
            const vCC = (insns[pc + 1] >>> 8) & 0xff;
            this._checkWideReg(frame, AA);
            const a = this._readLong(frame, vBB);
            let res;
            if (op === 0xa3 || op === 0xa4 || op === 0xa5) {
              this._checkReg(frame, vCC);
              const sh = BigInt(frame.intRegs[vCC] & 63);
              if (op === 0xa3) res = BigInt.asIntN(64, a << sh);
              else if (op === 0xa4) res = BigInt.asIntN(64, a >> sh);
              else res = BigInt.asIntN(64, BigInt.asUintN(64, a) >> sh);
            } else {
              const b = this._readLong(frame, vCC);
              if (op === 0x9b) res = BigInt.asIntN(64, a + b);
              else if (op === 0x9c) res = BigInt.asIntN(64, a - b);
              else if (op === 0x9d) res = BigInt.asIntN(64, a * b);
              else if (op === 0x9e) { res = this._longDiv(a, b); if (res === null) break; }
              else if (op === 0x9f) { res = this._longRem(a, b); if (res === null) break; }
              else if (op === 0xa0) res = a & b;
              else if (op === 0xa1) res = a | b;
              else res = a ^ b;
            }
            this._writeLong(frame, AA, res);
            frame.pc = pc + 2;
            break;
          }

          // 0xA6..0xAA float binary ops (23x)
          case 0xa6: case 0xa7: case 0xa8: case 0xa9: case 0xaa: {
            this._checkInsnUnits(frame, pc, 2);
            const vBB = insns[pc + 1] & 0xff;
            const vCC = (insns[pc + 1] >>> 8) & 0xff;
            this._checkReg(frame, AA);
            this._checkReg(frame, vBB);
            this._checkReg(frame, vCC);
            const a = intBitsToFloat(frame.intRegs[vBB]);
            const b = intBitsToFloat(frame.intRegs[vCC]);
            let res;
            if (op === 0xa6) res = Math.fround(a + b);
            else if (op === 0xa7) res = Math.fround(a - b);
            else if (op === 0xa8) res = Math.fround(a * b);
            else if (op === 0xa9) res = Math.fround(a / b);
            else res = Math.fround(a % b);
            this._writeInt(frame, AA, floatToIntBits(res));
            frame.pc = pc + 2;
            break;
          }

          // 0xAB..0xAF double binary ops (23x)
          case 0xab: case 0xac: case 0xad: case 0xae: case 0xaf: {
            this._checkInsnUnits(frame, pc, 2);
            const vBB = insns[pc + 1] & 0xff;
            const vCC = (insns[pc + 1] >>> 8) & 0xff;
            this._checkWideReg(frame, AA);
            const a = this._readDouble(frame, vBB);
            const b = this._readDouble(frame, vCC);
            let res;
            if (op === 0xab) res = a + b;
            else if (op === 0xac) res = a - b;
            else if (op === 0xad) res = a * b;
            else if (op === 0xae) res = a / b;
            else res = a % b;
            this._writeDouble(frame, AA, res);
            frame.pc = pc + 2;
            break;
          }

          // 0xB0..0xBA int/2addr (12x)
          case 0xb0: case 0xb1: case 0xb2: case 0xb3: case 0xb4:
          case 0xb5: case 0xb6: case 0xb7: case 0xb8: case 0xb9: case 0xba: {
            this._checkReg(frame, vA4);
            this._checkReg(frame, vB4);
            const a = frame.intRegs[vA4] | 0;
            const b = frame.intRegs[vB4] | 0;
            let res;
            if (op === 0xb0) res = (a + b) | 0;
            else if (op === 0xb1) res = (a - b) | 0;
            else if (op === 0xb2) res = Math.imul(a, b);
            else if (op === 0xb3) { res = this._intDiv(a, b); if (res === null) break; }
            else if (op === 0xb4) { res = this._intRem(a, b); if (res === null) break; }
            else if (op === 0xb5) res = a & b;
            else if (op === 0xb6) res = a | b;
            else if (op === 0xb7) res = a ^ b;
            else if (op === 0xb8) res = a << (b & 31);
            else if (op === 0xb9) res = a >> (b & 31);
            else res = (a >>> (b & 31)) | 0;
            this._writeInt(frame, vA4, res);
            frame.pc = pc + 1;
            break;
          }

          // 0xBB..0xC5 long/2addr (12x)
          case 0xbb: case 0xbc: case 0xbd: case 0xbe: case 0xbf:
          case 0xc0: case 0xc1: case 0xc2: case 0xc3: case 0xc4: case 0xc5: {
            const a = this._readLong(frame, vA4);
            let res;
            if (op === 0xc3 || op === 0xc4 || op === 0xc5) {
              this._checkReg(frame, vB4);
              const sh = BigInt(frame.intRegs[vB4] & 63);
              if (op === 0xc3) res = BigInt.asIntN(64, a << sh);
              else if (op === 0xc4) res = BigInt.asIntN(64, a >> sh);
              else res = BigInt.asIntN(64, BigInt.asUintN(64, a) >> sh);
            } else {
              const b = this._readLong(frame, vB4);
              if (op === 0xbb) res = BigInt.asIntN(64, a + b);
              else if (op === 0xbc) res = BigInt.asIntN(64, a - b);
              else if (op === 0xbd) res = BigInt.asIntN(64, a * b);
              else if (op === 0xbe) { res = this._longDiv(a, b); if (res === null) break; }
              else if (op === 0xbf) { res = this._longRem(a, b); if (res === null) break; }
              else if (op === 0xc0) res = a & b;
              else if (op === 0xc1) res = a | b;
              else res = a ^ b;
            }
            this._writeLong(frame, vA4, res);
            frame.pc = pc + 1;
            break;
          }

          // 0xC6..0xCA float/2addr (12x)
          case 0xc6: case 0xc7: case 0xc8: case 0xc9: case 0xca: {
            this._checkReg(frame, vA4);
            this._checkReg(frame, vB4);
            const a = intBitsToFloat(frame.intRegs[vA4]);
            const b = intBitsToFloat(frame.intRegs[vB4]);
            let res;
            if (op === 0xc6) res = Math.fround(a + b);
            else if (op === 0xc7) res = Math.fround(a - b);
            else if (op === 0xc8) res = Math.fround(a * b);
            else if (op === 0xc9) res = Math.fround(a / b);
            else res = Math.fround(a % b);
            this._writeInt(frame, vA4, floatToIntBits(res));
            frame.pc = pc + 1;
            break;
          }

          // 0xCB..0xCF double/2addr (12x)
          case 0xcb: case 0xcc: case 0xcd: case 0xce: case 0xcf: {
            const a = this._readDouble(frame, vA4);
            const b = this._readDouble(frame, vB4);
            let res;
            if (op === 0xcb) res = a + b;
            else if (op === 0xcc) res = a - b;
            else if (op === 0xcd) res = a * b;
            else if (op === 0xce) res = a / b;
            else res = a % b;
            this._writeDouble(frame, vA4, res);
            frame.pc = pc + 1;
            break;
          }

          // 0xD0..0xD7 int/lit16 (22s) — NOTE: 0xD1 rsub-int computes lit - vB!
          case 0xd0: case 0xd1: case 0xd2: case 0xd3:
          case 0xd4: case 0xd5: case 0xd6: case 0xd7: {
            this._checkInsnUnits(frame, pc, 2);
            this._checkReg(frame, vA4);
            this._checkReg(frame, vB4);
            const a = frame.intRegs[vB4] | 0;
            const lit = (insns[pc + 1] << 16) >> 16;
            let res;
            if (op === 0xd0) res = (a + lit) | 0;
            else if (op === 0xd1) res = (lit - a) | 0;
            else if (op === 0xd2) res = Math.imul(a, lit);
            else if (op === 0xd3) { res = this._intDiv(a, lit); if (res === null) break; }
            else if (op === 0xd4) { res = this._intRem(a, lit); if (res === null) break; }
            else if (op === 0xd5) res = a & lit;
            else if (op === 0xd6) res = a | lit;
            else res = a ^ lit;
            this._writeInt(frame, vA4, res);
            frame.pc = pc + 2;
            break;
          }

          // 0xD8..0xE2 int/lit8 (22b) — NOTE: 0xD9 rsub-int/lit8 computes lit - vB!
          case 0xd8: case 0xd9: case 0xda: case 0xdb: case 0xdc:
          case 0xdd: case 0xde: case 0xdf: case 0xe0: case 0xe1: case 0xe2: {
            this._checkInsnUnits(frame, pc, 2);
            const vBB = insns[pc + 1] & 0xff;
            const lit = (((insns[pc + 1] >>> 8) & 0xff) << 24) >> 24;
            this._checkReg(frame, AA);
            this._checkReg(frame, vBB);
            const a = frame.intRegs[vBB] | 0;
            let res;
            if (op === 0xd8) res = (a + lit) | 0;
            else if (op === 0xd9) res = (lit - a) | 0;
            else if (op === 0xda) res = Math.imul(a, lit);
            else if (op === 0xdb) { res = this._intDiv(a, lit); if (res === null) break; }
            else if (op === 0xdc) { res = this._intRem(a, lit); if (res === null) break; }
            else if (op === 0xdd) res = a & lit;
            else if (op === 0xde) res = a | lit;
            else if (op === 0xdf) res = a ^ lit;
            else if (op === 0xe0) res = a << (lit & 31);
            else if (op === 0xe1) res = a >> (lit & 31);
            else res = (a >>> (lit & 31)) | 0;
            this._writeInt(frame, AA, res);
            frame.pc = pc + 2;
            break;
          }

          default: {
            const err = new UnsupportedOpcodeError(
              `Unsupported Dalvik opcode 0x${op.toString(16).padStart(2, '0')} at pc=${pc} in ${frame.method.key}`,
              {
                code: ERROR_CODES.E_UNSUPPORTED_OPCODE,
                pc,
                opcode: op,
                arch: 'dalvik',
                pid: this.pid,
              }
            );
            return { status: 'FAULT', instructionsExecuted: executed, fault: err };
          }
        }
      } catch (err) {
        if (err instanceof DalvikGuestException) {
          this._unwindException(err.exception);
        } else {
          return { status: 'FAULT', instructionsExecuted: executed, fault: err };
        }
      }

      if (this.lastUncaughtException && this.callStack.length === 0) {
        return this._buildUncaughtFault(executed, pc);
      }
    }

    const reported = Math.min(maxSteps, executed + this._stepExternalWork);
    if (this.callStack.length === 0) {
      return {
        status: 'EXITED',
        instructionsExecuted: reported,
        returnValue: this.lastReturnValue,
        exitCode: 0,
      };
    }

    return {
      status: 'YIELD',
      instructionsExecuted: reported,
    };
  }

  getDebugState() {
    const top = this.callStack.length > 0 ? this.callStack[this.callStack.length - 1] : null;
    const registers = {};
    if (top) {
      const limit = Math.min(top.intRegs.length, 32);
      for (let i = 0; i < limit; i++) {
        registers[`v${i}`] = top.refRegs[i] !== null ? `[${this.getObjectType(top.refRegs[i])}]` : top.intRegs[i];
      }
      this._lastRegisters = { ...registers };
    } else if (this._lastRegisters && Object.keys(this._lastRegisters).length > 0) {
      Object.assign(registers, this._lastRegisters);
    } else {
      registers.v0 = this.lastResultInt ?? 0;
      registers.v1 = this.totalInstructionsExecuted;
    }
    return {
      arch: 'dalvik',
      pc: top ? top.pc : 0,
      sp: this.callStack.length,
      registers,
      instructionsExecuted: this.totalInstructionsExecuted,
      lastSyscall: this.lastNativeCall,
      stackTop: top ? top.method.key : null,
      callDepth: this.callStack.length,
    };
  }
}

export function createDalvikVM(opts = {}) {
  return new DalvikVM(opts);
}

export function registerDalvikCpu(cpuRegistry) {
  if (cpuRegistry && typeof cpuRegistry.register === 'function') {
    cpuRegistry.register('dalvik', createDalvikVM, { overwrite: true });
  }
  return createDalvikVM;
}
