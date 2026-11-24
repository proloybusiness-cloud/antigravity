/**
 * OmniOS Windows `.bat` / `.cmd` Batch Script Interpreter (`os/runtimes/windows/batch-runner.mjs`)
 * - Full Windows `cmd.exe` batch semantics: `@ECHO`, `ECHO`, `REM`/`::`, `SET`, `SET /A` (signed 32-bit
 *   recursive-descent evaluator), `SETLOCAL ENABLEDELAYEDEXPANSION`/`ENDLOCAL`, `%VAR%`/`!VAR!`,
 *   `%0..%9`, `%ERRORLEVEL%`, `IF [NOT] [/I] EXIST|DEFINED|ERRORLEVEL|==|EQU/NEQ/LSS/LEQ/GTR/GEQ`
 *   with `ELSE` & multi-line `(...)` blocks, `FOR` (`/L`, `/D`, `/F`, list), `GOTO`, `CALL :sub`,
 *   `EXIT [/B]`, VFS file commands (`DIR`/`CD`/`MKDIR`/`RMDIR`/`COPY`/`MOVE`/`DEL`/`TYPE`/`FIND`/`FINDSTR`),
 *   command chaining (`&`, `&&`, `||`), pipes (`|`), and redirection (`>`, `>>`, `<`, `2>`, `2>&1`, `nul`).
 * - CRITICAL Edge Case #18: Strictly preserves `.bat` vs `.cmd` `ERRORLEVEL` divergence:
 *   successful `SET`/`PATH`/`ASSOC`/`PROMPT` keeps prior `ERRORLEVEL` in `.bat`, resets to `0` in `.cmd`!
 * - Strictly synchronous, iterative, step-budgeted `IExecutionContext` (never exceeds `budget`,
 *   infinite `GOTO` or `FOR` loops trip M1 `SIGXCPU` cleanly).
 */

import { VfsError, ERROR_CODES } from '../../common/errors.mjs';
import { isPathWithinRoot, normalizePosixPath } from '../../vfs/path-translator.mjs';

const UTF8_DECODER = new TextDecoder('utf-8', { fatal: false });
const UTF8_ENCODER = new TextEncoder();

const BAT_PRESERVE_ERR_COMMANDS = new Set(['SET', 'PATH', 'ASSOC', 'PROMPT', 'DPATH', 'FTYPE']);
const MAX_CALL_DEPTH = 64;
const MAX_CMD_SUB_DEPTH = 8;
const MAX_FOR_TOKENS = 31;
const MAX_SETLOCAL_DEPTH = 64;
const MAX_ENV_VALUE_LEN = 32768;
const MAX_EXPANDED_LINE_LEN = 65536;
const MAX_TOTAL_ENV_BYTES = 262144; // 256 KiB total across this.env
const MAX_BATCH_FILE_BYTES = 32 * 1024 * 1024;
export const MAX_BATCH_VFS_WRITE_BYTES = 16 * 1024 * 1024; // 16 MiB cumulative non-root VFS write bytes per process
export const MAX_BATCH_VFS_PHYSICAL_WRITE_BYTES = 32 * 1024 * 1024; // 32 MiB cumulative non-root physical SQLite VFS blob rewrite bytes per process (symmetric with Android & Win32)
export const MAX_BATCH_VFS_AMPLIFIED_REWRITE_BYTES = 32 * 1024 * 1024; // 32 MiB exported alias retained for API continuity (all physical writes now strictly capped at 32 MiB)
export const MAX_BATCH_VFS_PHYSICAL_READ_BYTES = 64 * 1024 * 1024; // 64 MiB cumulative non-root physical SQLite VFS blob read bytes per process
const MAX_BATCH_READDIR_CACHE_BYTES = 4 * 1024 * 1024;     // 4 MiB bounded tick-local VFS readdir snapshot cache
export const MAX_BATCH_VFS_CREATE_OPS = 1024;              // Max cumulative non-root VFS file/dir creation ops per process
const MAX_PERMISSION_AUDIT_EVENTS = 256;                   // Max total PermissionBroker.checkPermission() calls per process
const MAX_PERMISSION_PROMPT_CALLS = 16;                    // Max 'prompt'-policy PermissionBroker.checkPermission() calls per process
const MAX_PERMISSION_CONTEXT_PATH_CHARS = 256;             // Max context.path chars forwarded to PermissionBroker
const MAX_BATCH_IO_BUFFER_BYTES = 4 * 1024 * 1024; // 4 MiB cumulative I/O buffer cap
const MAX_SCRIPT_BYTES = 4 * 1024 * 1024;          // 4 MiB max batch script source
const MAX_PAREN_NESTING_DEPTH = 64;                // Max nested `(...)` block depth
const MAX_FOR_F_LINES = 65536;                     // Max materialized lines per FOR /F
const MAX_ACTIVE_FOR_F_CELLS = 65536;              // Max total materialized FOR cells across all active frames + CMD /C
const MAX_ACTIVE_FOR_F_BYTES = 4 * 1024 * 1024;    // 4 MiB max total materialized FOR bytes across all active frames + CMD /C
const MAX_ACTIVE_SETLOCAL_BYTES = 4 * 1024 * 1024; // 4 MiB max total UTF-16 bytes across active SETLOCAL snapshots + CMD /C
const MAX_ARITH_DEPTH = 64;                        // Max SET /A nesting depth
const MAX_BATCH_WILDCARD_MASK_LEN = 4096;          // Max individual FOR /D path/wildcard mask length

function utf8ByteLength(str) {
  if (!str) return 0;
  if (typeof Buffer === 'function' && typeof Buffer.byteLength === 'function') {
    return Buffer.byteLength(str, 'utf8');
  }
  return UTF8_ENCODER.encode(str).byteLength;
}

function isBatchWhitespace(ch) {
  const code = ch.charCodeAt(0);
  if (code === 32 || code === 9 || code === 10 || code === 13 || code === 12 || code === 11) {
    return true;
  }
  return code >= 160 && /\s/.test(ch);
}

class BatchLimitError extends Error {
  constructor(message, { unwindToRoot = false, clearLocals = false } = {}) {
    super(message);
    this.name = 'BatchLimitError';
    this.isBatchLimitError = true;
    this.unwindToRoot = Boolean(unwindToRoot);
    this.clearLocals = Boolean(clearLocals);
  }
}

// ============================================================================
// SET /A 32-Bit Signed Integer Arithmetic Expression Evaluator
// ============================================================================

export function evaluateSetArithmetic(expr, envGet = () => '', envSet = () => {}) {
  const src = String(expr ?? '').trim();
  if (!src) {
    return { ok: false, value: 0, error: 'Missing operand.' };
  }

  let pos = 0;
  let arithDepth = 0;
  const len = src.length;

  const skipWs = () => {
    while (pos < len && /\s/.test(src[pos])) pos += 1;
  };

  const peek = () => (pos < len ? src[pos] : '');
  const peek2 = () => src.slice(pos, pos + 2);
  const peek3 = () => src.slice(pos, pos + 3);

  const readIdent = () => {
    const start = pos;
    while (pos < len && /[A-Za-z0-9_.$#@]/.test(src[pos])) pos += 1;
    return src.slice(start, pos);
  };

  const readNumber = () => {
    const start = pos;
    if (src[pos] === '0' && (src[pos + 1] === 'x' || src[pos + 1] === 'X')) {
      pos += 2;
      const hexStart = pos;
      while (pos < len && /[0-9a-fA-F]/.test(src[pos])) pos += 1;
      if (pos === hexStart) throw new Error('Invalid hex number');
      return parseInt(src.slice(hexStart, pos), 16) | 0;
    }
    if (src[pos] === '0' && pos + 1 < len && /[0-7]/.test(src[pos + 1])) {
      while (pos < len && /[0-7]/.test(src[pos])) pos += 1;
      return parseInt(src.slice(start, pos), 8) | 0;
    }
    while (pos < len && /[0-9]/.test(src[pos])) pos += 1;
    return parseInt(src.slice(start, pos), 10) | 0;
  };

  const getVarInt = (name) => {
    const raw = String(envGet(name) ?? '').trim();
    if (!raw) return 0;
    if (/^[+-]?0x[0-9a-fA-F]+$/i.test(raw)) return parseInt(raw, 16) | 0;
    const n = parseInt(raw, 10);
    return Number.isFinite(n) ? (n | 0) : 0;
  };

  const parseComma = () => {
    let val = parseAssign();
    skipWs();
    while (peek() === ',') {
      pos += 1;
      val = parseAssign();
      skipWs();
    }
    return val | 0;
  };

  const parseAssign = () => {
    skipWs();
    const savePos = pos;
    if (/[A-Za-z_]/.test(peek())) {
      const name = readIdent();
      skipWs();
      const op3 = peek3();
      const op2 = peek2();
      const op1 = peek();
      let assignOp = null;
      if (op3 === '<<=' || op3 === '>>=') {
        assignOp = op3;
        pos += 3;
      } else if (['+=', '-=', '*=', '/=', '%=', '&=', '^=', '|='].includes(op2)) {
        assignOp = op2;
        pos += 2;
      } else if (op1 === '=' && op2 !== '==') {
        assignOp = '=';
        pos += 1;
      }
      if (assignOp !== null) {
        if (++arithDepth > MAX_ARITH_DEPTH) {
          throw new Error('Expression nesting depth exceeded.');
        }
        let rhs;
        try {
          rhs = parseAssign() | 0;
        } finally {
          arithDepth -= 1;
        }
        let result;
        if (assignOp === '=') {
          result = rhs;
        } else {
          const cur = getVarInt(name);
          if (assignOp === '+=') result = (cur + rhs) | 0;
          else if (assignOp === '-=') result = (cur - rhs) | 0;
          else if (assignOp === '*=') result = Math.imul(cur, rhs);
          else if (assignOp === '/=') {
            if (rhs === 0) throw new Error('Divide by zero error.');
            result = Math.trunc(cur / rhs) | 0;
          } else if (assignOp === '%=') {
            if (rhs === 0) throw new Error('Divide by zero error.');
            result = (cur % rhs) | 0;
          } else if (assignOp === '<<=') result = (cur << (rhs & 31)) | 0;
          else if (assignOp === '>>=') result = (cur >> (rhs & 31)) | 0;
          else if (assignOp === '&=') result = (cur & rhs) | 0;
          else if (assignOp === '^=') result = (cur ^ rhs) | 0;
          else result = (cur | rhs) | 0;
        }
        envSet(name, String(result | 0));
        return result | 0;
      }
    }
    pos = savePos;
    return parseBitOr();
  };

  const parseBitOr = () => {
    let left = parseBitXor();
    skipWs();
    while (peek() === '|' && peek2() !== '|=') {
      pos += 1;
      left = (left | parseBitXor()) | 0;
      skipWs();
    }
    return left;
  };

  const parseBitXor = () => {
    let left = parseBitAnd();
    skipWs();
    while (peek() === '^' && peek2() !== '^=') {
      pos += 1;
      left = (left ^ parseBitAnd()) | 0;
      skipWs();
    }
    return left;
  };

  const parseBitAnd = () => {
    let left = parseShift();
    skipWs();
    while (peek() === '&' && peek2() !== '&=') {
      pos += 1;
      left = (left & parseShift()) | 0;
      skipWs();
    }
    return left;
  };

  const parseShift = () => {
    let left = parseAdd();
    skipWs();
    while ((peek2() === '<<' || peek2() === '>>') && peek3() !== '<<=' && peek3() !== '>>=') {
      const op = peek2();
      pos += 2;
      const right = parseAdd();
      left = op === '<<' ? ((left << (right & 31)) | 0) : ((left >> (right & 31)) | 0);
      skipWs();
    }
    return left;
  };

  const parseAdd = () => {
    let left = parseMul();
    skipWs();
    while ((peek() === '+' || peek() === '-') && peek2() !== '+=' && peek2() !== '-=') {
      const op = peek();
      pos += 1;
      const right = parseMul();
      left = op === '+' ? ((left + right) | 0) : ((left - right) | 0);
      skipWs();
    }
    return left;
  };

  const parseMul = () => {
    let left = parseUnary();
    skipWs();
    while (
      (peek() === '*' || peek() === '/' || peek() === '%') &&
      peek2() !== '*=' &&
      peek2() !== '/=' &&
      peek2() !== '%='
    ) {
      const op = peek();
      pos += 1;
      const right = parseUnary();
      if (op === '*') {
        left = Math.imul(left, right);
      } else if (op === '/') {
        if (right === 0) throw new Error('Divide by zero error.');
        left = Math.trunc(left / right) | 0;
      } else {
        if (right === 0) throw new Error('Divide by zero error.');
        left = (left % right) | 0;
      }
      skipWs();
    }
    return left;
  };

  const parseUnary = () => {
    skipWs();
    const ch = peek();
    if (ch === '+' || ch === '-' || ch === '~' || ch === '!') {
      if (++arithDepth > MAX_ARITH_DEPTH) {
        throw new Error('Expression nesting depth exceeded.');
      }
      try {
        pos += 1;
        if (ch === '+') return parseUnary() | 0;
        if (ch === '-') return (-parseUnary()) | 0;
        if (ch === '~') return (~parseUnary()) | 0;
        return parseUnary() === 0 ? 1 : 0;
      } finally {
        arithDepth -= 1;
      }
    }
    return parsePrimary();
  };

  const parsePrimary = () => {
    skipWs();
    if (peek() === '(') {
      if (++arithDepth > MAX_ARITH_DEPTH) {
        throw new Error('Expression nesting depth exceeded.');
      }
      try {
        pos += 1;
        const val = parseComma();
        skipWs();
        if (peek() !== ')') throw new Error('Missing closing parenthesis.');
        pos += 1;
        return val | 0;
      } finally {
        arithDepth -= 1;
      }
    }
    if (/[0-9]/.test(peek())) {
      return readNumber();
    }
    if (/[A-Za-z_]/.test(peek())) {
      const name = readIdent();
      return getVarInt(name);
    }
    throw new Error(`Invalid expression token at "${src.slice(pos, pos + 16)}"`);
  };

  try {
    const value = parseComma() | 0;
    skipWs();
    if (pos < len) {
      return { ok: false, value: 0, error: `Unexpected token "${src.slice(pos)}"` };
    }
    return { ok: true, value, error: null };
  } catch (err) {
    return { ok: false, value: 0, error: err.message };
  }
}

// ============================================================================
// Batch Lexical & Parsing Helpers
// ============================================================================

function unquote(str) {
  const t = String(str ?? '').trim();
  if (t.length >= 2 && t.startsWith('"') && t.endsWith('"')) {
    return t.slice(1, -1);
  }
  return t;
}

function tokenizeArgs(str) {
  const args = [];
  const parts = [];
  let segStart = 0;
  let hasContent = false;
  let inQuotes = false;
  const len = str.length;

  const flushSegment = (end) => {
    if (end > segStart) {
      parts.push(str.slice(segStart, end));
      hasContent = true;
    }
  };
  const commitArg = () => {
    if (hasContent) {
      args.push(parts.length === 1 ? parts[0] : parts.join(''));
      parts.length = 0;
      hasContent = false;
    }
  };

  for (let i = 0; i < len; i++) {
    const ch = str[i];
    if (ch === '^' && !inQuotes && i + 1 < len) {
      flushSegment(i);
      segStart = i + 1;
      hasContent = true;
      i += 1;
      continue;
    }
    if (ch === '"') {
      inQuotes = !inQuotes;
      hasContent = true;
      continue;
    }
    if (!inQuotes && isBatchWhitespace(ch)) {
      flushSegment(i);
      commitArg();
      segStart = i + 1;
      continue;
    }
  }
  flushSegment(len);
  commitArg();
  return args;
}

function escapeRegExp(str) {
  return String(str).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function replaceForVarBounded(body, vChar, value, maxLen = MAX_EXPANDED_LINE_LEN) {
  if (body.indexOf('%') === -1) return body;
  const esc = escapeRegExp(vChar);
  const valStr = String(value ?? '');
  const unquoted = unquote(valStr);
  const applyBounded = (text, rx, repl) => {
    let projected = text.length;
    let matched = false;
    rx.lastIndex = 0;
    let m;
    while ((m = rx.exec(text)) !== null) {
      matched = true;
      projected += repl.length - m[0].length;
      if (projected > maxLen) {
        throw new BatchLimitError(
          `Environment/command line length limit exceeded (FOR body length ${projected} > ${maxLen})`
        );
      }
    }
    if (!matched) return text;
    rx.lastIndex = 0;
    return text.replace(rx, () => repl);
  };
  let out = applyBounded(body, new RegExp(`%%?~${esc}`, 'g'), unquoted);
  out = applyBounded(out, new RegExp(`%%?${esc}`, 'g'), valStr);
  return out;
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

/**
 * Incrementally update parenthesis depth and quote state over a single newly added segment (strictly O(N)).
 */
function updateParenState(str, state) {
  for (let k = 0; k < str.length; k++) {
    const c = str[k];
    if (c === '^' && !state.inQ && k + 1 < str.length) { k += 1; continue; }
    if (c === '"') { state.inQ = !state.inQ; continue; }
    if (!state.inQ) {
      if (c === '(') {
        state.depth += 1;
        if (state.depth > state.maxDepth) state.maxDepth = state.depth;
      } else if (c === ')' && state.depth > 0) {
        state.depth -= 1;
      }
    }
  }
  return state;
}

/**
 * Split raw script text into logical lines (joining `^` continuations and multi-line `(...)` blocks),
 * in strictly linear O(N) time while preserving exact label targets (`:label`)!
 */
function parseScriptStatements(scriptText) {
  const rawText = String(scriptText ?? '');
  if (rawText.length > MAX_SCRIPT_BYTES) {
    throw new BatchLimitError(
      `Batch script size limit exceeded (${rawText.length} > ${MAX_SCRIPT_BYTES} bytes)`
    );
  }
  const rawLines = rawText.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
  const stmts = [];
  const labels = new Map(); // lowerLabel -> stmtIndex

  let i = 0;
  while (i < rawLines.length) {
    let line = rawLines[i];
    const startLineNo = i + 1;
    i += 1;

    // Join caret-escaped line continuations in O(N)
    if (line.endsWith('^') && !line.endsWith('^^') && i < rawLines.length) {
      const contParts = [line.slice(0, -1)];
      while (i < rawLines.length) {
        const nextLine = rawLines[i];
        i += 1;
        if (nextLine.endsWith('^') && !nextLine.endsWith('^^') && i < rawLines.length) {
          contParts.push(nextLine.slice(0, -1));
        } else {
          contParts.push(nextLine);
          break;
        }
      }
      line = contParts.join('');
    }

    const trimmed = line.trim();
    if (!trimmed) continue;

    // Label check (`:name`, but NOT `::` comment!)
    if (trimmed.startsWith(':') && !trimmed.startsWith('::')) {
      const labelMatch = /^:\s*([^\s:&|<>]+)/.exec(trimmed);
      if (labelMatch) {
        const lbl = labelMatch[1].toLowerCase();
        if (!labels.has(lbl)) {
          labels.set(lbl, stmts.length);
        }
      }
      stmts.push({ text: trimmed, lineNo: startLineNo, isLabel: true });
      continue;
    }

    // Skip paren merging on pure REM / :: comments
    const upperHead = trimmed.replace(/^@+/, '').trimStart().toUpperCase();
    const isComment = trimmed.startsWith('::') || upperHead === 'REM' || /^REM[\s\t]/i.test(upperHead);

    let full = line;
    if (!isComment) {
      const pState = updateParenState(line, { depth: 0, inQ: false, maxDepth: 0 });
      let parseError =
        pState.maxDepth > MAX_PAREN_NESTING_DEPTH
          ? `Maximum parenthesis nesting depth (${MAX_PAREN_NESTING_DEPTH}) exceeded`
          : null;
      const parts = [line];
      const seps = [];
      let lastPart = line;

      while (pState.depth > 0 && i < rawLines.length) {
        const nextLine = rawLines[i];
        i += 1;
        updateParenState(nextLine, pState);
        if (pState.maxDepth > MAX_PAREN_NESTING_DEPTH) {
          parseError = `Maximum parenthesis nesting depth (${MAX_PAREN_NESTING_DEPTH}) exceeded`;
        } else if (!parseError) {
          seps.push('\n');
          parts.push(nextLine);
          lastPart = nextLine;
        }
      }

      // Also merge trailing `ELSE (` on next line if the current block ended with `)` and next line starts with ELSE
      while (!parseError && i < rawLines.length) {
        const nextTrim = rawLines[i].trim();
        if (/^else\b/i.test(nextTrim) && lastPart.trimEnd().endsWith(')')) {
          const elseLine = rawLines[i];
          i += 1;
          updateParenState(elseLine, pState);
          if (pState.maxDepth > MAX_PAREN_NESTING_DEPTH) {
            parseError = `Maximum parenthesis nesting depth (${MAX_PAREN_NESTING_DEPTH}) exceeded`;
          } else {
            seps.push(' ');
            parts.push(elseLine);
            lastPart = elseLine;
          }
          while (pState.depth > 0 && i < rawLines.length) {
            const nextLine = rawLines[i];
            i += 1;
            updateParenState(nextLine, pState);
            if (pState.maxDepth > MAX_PAREN_NESTING_DEPTH) {
              parseError = `Maximum parenthesis nesting depth (${MAX_PAREN_NESTING_DEPTH}) exceeded`;
            } else if (!parseError) {
              seps.push('\n');
              parts.push(nextLine);
              lastPart = nextLine;
            }
          }
        } else {
          break;
        }
      }

      if (parseError) {
        stmts.push({ text: '', lineNo: startLineNo, isLabel: false, parseError });
        continue;
      }

      if (parts.length > 1) {
        const joined = [parts[0]];
        for (let p = 1; p < parts.length; p++) {
          joined.push(seps[p - 1], parts[p]);
        }
        full = joined.join('');
      }
    }

    stmts.push({ text: full, lineNo: startLineNo, isLabel: false });
  }

  return { stmts, labels };
}

/**
 * Split a statement by top-level chaining operators (`&`, `&&`, `||`) outside quotes & parentheses.
 */
function splitChainedCommands(line) {
  if (line.indexOf('&') === -1 && line.indexOf('|') === -1) {
    return [{ op: null, cmd: line.trim() }];
  }
  const parts = [];
  let segStart = 0;
  let inQ = false;
  let depth = 0;
  let nextOp = null; // null | '&' | '&&' | '||'
  const len = line.length;

  for (let i = 0; i < len; i++) {
    const c = line[i];
    if (c === '^' && !inQ && i + 1 < len) {
      i += 1;
      continue;
    }
    if (c === '"') {
      inQ = !inQ;
      continue;
    }
    if (!inQ) {
      if (c === '(') { depth += 1; continue; }
      if (c === ')') { depth = Math.max(0, depth - 1); continue; }
      if (depth === 0) {
        // Avoid splitting inside `2>&1` or `1>&2`
        if (c === '&' && i > 0 && line[i - 1] === '>') {
          continue;
        }
        if (c === '&' && line[i + 1] === '&') {
          parts.push({ op: nextOp, cmd: line.slice(segStart, i).trim() });
          nextOp = '&&';
          i += 1;
          segStart = i + 1;
          continue;
        }
        if (c === '|' && line[i + 1] === '|') {
          parts.push({ op: nextOp, cmd: line.slice(segStart, i).trim() });
          nextOp = '||';
          i += 1;
          segStart = i + 1;
          continue;
        }
        if (c === '&') {
          parts.push({ op: nextOp, cmd: line.slice(segStart, i).trim() });
          nextOp = '&';
          segStart = i + 1;
          continue;
        }
      }
    }
  }
  const tail = line.slice(segStart).trim();
  if (tail.length > 0 || parts.length === 0) {
    parts.push({ op: nextOp, cmd: tail });
  }
  return parts;
}

/**
 * Split a single command by top-level pipe `|` (not `||`).
 */
function splitPipeStages(cmd) {
  if (cmd.indexOf('|') === -1) {
    return [cmd.trim()];
  }
  const stages = [];
  let segStart = 0;
  let inQ = false;
  let depth = 0;
  const len = cmd.length;
  for (let i = 0; i < len; i++) {
    const c = cmd[i];
    if (c === '^' && !inQ && i + 1 < len) {
      i += 1;
      continue;
    }
    if (c === '"') { inQ = !inQ; continue; }
    if (!inQ) {
      if (c === '(') depth += 1;
      else if (c === ')') depth = Math.max(0, depth - 1);
      else if (depth === 0 && c === '|' && cmd[i + 1] !== '|') {
        stages.push(cmd.slice(segStart, i).trim());
        segStart = i + 1;
        continue;
      }
    }
  }
  const tail = cmd.slice(segStart).trim();
  if (tail.length > 0 || stages.length === 0) {
    stages.push(tail);
  }
  return stages;
}

/**
 * Extract top-level I/O redirections (`>`, `>>`, `<`, `2>`, `2>>`, `2>&1`) outside quotes & parens.
 */
function extractRedirections(cmd) {
  const redirs = {
    stdoutFile: null,
    stdoutAppend: false,
    stderrFile: null,
    stderrAppend: false,
    stderrToStdout: false,
    stdinFile: null,
  };
  if (cmd.indexOf('>') === -1 && cmd.indexOf('<') === -1) {
    return { command: cmd.trim(), redirs };
  }
  const parts = [];
  let segStart = 0;
  let inQ = false;
  let depth = 0;
  const len = cmd.length;

  const readTarget = (str, startIdx) => {
    let idx = startIdx;
    while (idx < str.length && isBatchWhitespace(str[idx])) idx += 1;
    const tokParts = [];
    let tokSegStart = idx;
    let q = false;
    while (idx < str.length) {
      const ch = str[idx];
      if (ch === '"') {
        if (idx > tokSegStart) tokParts.push(str.slice(tokSegStart, idx));
        q = !q;
        idx += 1;
        tokSegStart = idx;
        continue;
      }
      if (!q && (ch === '<' || ch === '>' || ch === '|' || ch === '&' || isBatchWhitespace(ch))) {
        break;
      }
      idx += 1;
    }
    if (idx > tokSegStart) tokParts.push(str.slice(tokSegStart, idx));
    return {
      target: tokParts.length === 0 ? '' : (tokParts.length === 1 ? tokParts[0] : tokParts.join('')),
      nextIdx: idx,
    };
  };

  for (let i = 0; i < len; i++) {
    const c = cmd[i];
    if (c === '^' && !inQ && i + 1 < len) {
      i += 1;
      continue;
    }
    if (c === '"') { inQ = !inQ; continue; }
    if (!inQ) {
      if (c === '(') { depth += 1; continue; }
      if (c === ')') { depth = Math.max(0, depth - 1); continue; }
      if (depth === 0) {
        const prevCh = i > 0 ? cmd[i - 1] : '';
        const atTokenStart =
          i === 0 ||
          isBatchWhitespace(prevCh) ||
          prevCh === '&' ||
          prevCh === '|' ||
          prevCh === '(' ||
          prevCh === ')';
        if (atTokenStart && c === '2' && cmd[i + 1] === '>' && cmd[i + 2] === '&' && cmd[i + 3] === '1') {
          if (i > segStart) parts.push(cmd.slice(segStart, i));
          redirs.stderrToStdout = true;
          i += 3;
          segStart = i + 1;
          continue;
        }
        if (atTokenStart && (c === '1' || c === '2') && cmd[i + 1] === '>') {
          if (i > segStart) parts.push(cmd.slice(segStart, i));
          const isErr = c === '2';
          const isAppend = cmd[i + 2] === '>';
          const { target, nextIdx } = readTarget(cmd, i + (isAppend ? 3 : 2));
          if (isErr) { redirs.stderrFile = target; redirs.stderrAppend = isAppend; }
          else { redirs.stdoutFile = target; redirs.stdoutAppend = isAppend; }
          i = nextIdx - 1;
          segStart = nextIdx;
          continue;
        }
        if (c === '>') {
          if (i > segStart) parts.push(cmd.slice(segStart, i));
          const isAppend = cmd[i + 1] === '>';
          const { target, nextIdx } = readTarget(cmd, i + (isAppend ? 2 : 1));
          redirs.stdoutFile = target;
          redirs.stdoutAppend = isAppend;
          i = nextIdx - 1;
          segStart = nextIdx;
          continue;
        }
        if (c === '<') {
          if (i > segStart) parts.push(cmd.slice(segStart, i));
          const { target, nextIdx } = readTarget(cmd, i + 1);
          redirs.stdinFile = target;
          i = nextIdx - 1;
          segStart = nextIdx;
          continue;
        }
      }
    }
  }
  if (segStart === 0) {
    return { command: cmd.trim(), redirs };
  }
  if (segStart < len) {
    parts.push(cmd.slice(segStart));
  }
  return { command: (parts.length === 1 ? parts[0] : parts.join('')).trim(), redirs };
}

/**
 * Extract a parenthesized block `( ... )` starting at `startIdx`, returning `{ inner, afterIdx }`.
 */
function extractParenBlock(str, startIdx) {
  let idx = startIdx;
  while (idx < str.length && /\s/.test(str[idx])) idx += 1;
  if (str[idx] !== '(') return null;
  let depth = 0;
  let inQ = false;
  const bodyStart = idx + 1;
  for (let i = idx; i < str.length; i++) {
    const c = str[i];
    if (c === '^' && !inQ && i + 1 < str.length) { i += 1; continue; }
    if (c === '"') { inQ = !inQ; continue; }
    if (!inQ) {
      if (c === '(') depth += 1;
      else if (c === ')') {
        depth -= 1;
        if (depth === 0) {
          return { inner: str.slice(bodyStart, i), afterIdx: i + 1 };
        }
      }
    }
  }
  return { inner: str.slice(bodyStart), afterIdx: str.length };
}

/**
 * Split an `IF <cond> <thenBranch> [ELSE <elseBranch>]` clause into `thenPart` and optional `elsePart`.
 */
function splitIfElse(rest) {
  const trimmed = rest.trimStart();
  if (trimmed.startsWith('(')) {
    const blk = extractParenBlock(trimmed, 0);
    if (blk) {
      const after = trimmed.slice(blk.afterIdx).trimStart();
      const elseMatch = /^else\b/i.exec(after);
      if (elseMatch) {
        const elseRaw = after.slice(elseMatch[0].length).trimStart();
        return { thenPart: `(${blk.inner})`, elsePart: elseRaw };
      }
      return { thenPart: `(${blk.inner})`, elsePart: null };
    }
  }
  // Single-line `IF cond cmd1 ELSE cmd2` (scan outside quotes/parens for word boundary ELSE)
  let inQ = false;
  let depth = 0;
  for (let i = 0; i < trimmed.length; i++) {
    const c = trimmed[i];
    if (c === '^' && !inQ && i + 1 < trimmed.length) { i += 1; continue; }
    if (c === '"') { inQ = !inQ; continue; }
    if (!inQ) {
      if (c === '(') depth += 1;
      else if (c === ')') depth = Math.max(0, depth - 1);
      else if (
        depth === 0 &&
        i > 0 &&
        /\s/.test(trimmed[i - 1]) &&
        /^else(?:\s|\(|$)/i.test(trimmed.slice(i))
      ) {
        return {
          thenPart: trimmed.slice(0, i).trim(),
          elsePart: trimmed.slice(i + 4).trim(),
        };
      }
    }
  }
  return { thenPart: trimmed, elsePart: null };
}

// ============================================================================
// BatchExecutionContext (Synchronous, Step-Budgeted IExecutionContext)
// ============================================================================

export class BatchExecutionContext {
  constructor({
    scriptText = '',
    scriptKind = 'bat',
    scriptName = 'script.bat',
    pcb = null,
    appRecord = null,
    services = {},
    args = [],
    env = {},
    subDepth = 0,
    maxSubDepth = MAX_CMD_SUB_DEPTH,
    stdoutSink = null,
    stderrSink = null,
    activeForBudget = null,
    activeLocalBudget = null,
    activeVfsBudget = null,
    activePermBudget = null,
  } = {}) {
    this.pcb = pcb;
    this.appRecord = appRecord ?? {};
    this.services = services;
    this.scriptName = scriptName;
    const lowerKind = String(scriptKind || '').toLowerCase();
    this.scriptKind = lowerKind === 'cmd' || String(scriptName).toLowerCase().endsWith('.cmd') ? 'cmd' : 'bat';
    this._subDepth = subDepth;
    this._maxSubDepth = maxSubDepth;
    this._stdoutSink = typeof stdoutSink === 'function' ? stdoutSink : null;
    this._stderrSink = typeof stderrSink === 'function' ? stderrSink : null;
    this._activeForBudget = activeForBudget || { cells: 0, bytes: 0 };
    this._activeLocalBudget = activeLocalBudget || { bytes: 0 };
    this._activeVfsBudget = activeVfsBudget || {
      writeBytes: 0,
      physicalWriteBytes: 0,
      amplifiedWriteBytes: 0,
      physicalReadBytes: 0,
      createOps: 0,
    };
    if (typeof this._activeVfsBudget.physicalWriteBytes !== 'number') {
      this._activeVfsBudget.physicalWriteBytes = 0;
    }
    if (typeof this._activeVfsBudget.amplifiedWriteBytes !== 'number') {
      this._activeVfsBudget.amplifiedWriteBytes = 0;
    }
    if (typeof this._activeVfsBudget.physicalReadBytes !== 'number') {
      this._activeVfsBudget.physicalReadBytes = 0;
    }
    this._pendingAppend = null;
    this._readdirCache = new Map();
    this._readdirCacheBytes = 0;
    this._symlinkResolveCache = new Map();
    this._activePermBudget = activePermBudget || {
      auditCount: 0,
      promptCount: 0,
      auditedKeys: new Set(),
    };
    this._activeForBudgetHit = false;
    this._stepTracker = null;
    this._pendingFault = null;
    this._suspendedSub = null;

    this.echoOn = true;
    this.delayedExpansion = false;
    this.errorLevel = 0;
    this.cwd = pcb?.cwd || appRecord?.dataDir || '/home/user';

    // Case-insensitive env map preserving original casing
    this.env = new Map();
    const initialEnv = {
      OS: 'Windows_NT',
      SYSTEMROOT: 'C:\\Windows',
      WINDIR: 'C:\\Windows',
      TEMP: 'C:\\Temp',
      TMP: 'C:\\Temp',
      USERPROFILE: 'C:\\Users\\user',
      PATH: 'C:\\Windows\\System32;C:\\Windows',
      PROMPT: '$P$G',
      ...(pcb?.env ?? {}),
      ...env,
    };
    for (const [k, v] of Object.entries(initialEnv)) {
      this.env.set(k.toUpperCase(), { name: k, value: String(v) });
    }
    this._localStack = [];

    let parsed;
    try {
      parsed = parseScriptStatements(scriptText);
    } catch (err) {
      if (err?.isBatchLimitError) {
        parsed = {
          stmts: [{ text: '', lineNo: 1, isLabel: false, parseError: err.message }],
          labels: new Map(),
        };
      } else {
        throw err;
      }
    }
    this._rootStmts = parsed.stmts;
    this._labels = parsed.labels;

    // Iterative execution stack (supports CALL :sub, multi-line (...) blocks, and budget-yielded FOR loops!)
    this._frames = [
      {
        kind: 'script',
        stmts: this._rootStmts,
        ip: 0,
        args: [scriptName, ...args.map(String)],
        argOffset: 0,
      },
    ];

    this.instructionsExecuted = 0;
    this.lastCommand = null;
    this.exited = false;
    this.exitCode = 0;
    this._disposed = false;
  }

  // ---- Environment & Expansion ----

  getEnv(name) {
    const key = String(name || '').toUpperCase();
    if (key === 'ERRORLEVEL') return String(this.errorLevel);
    if (key === 'CD') return this._winCwd();
    if (key === 'RANDOM') return String((this.instructionsExecuted * 1103515245 + 12345) & 0x7fff);
    if (key === 'DATE') return new Date().toISOString().slice(0, 10);
    if (key === 'TIME') return new Date().toISOString().slice(11, 19);
    const entry = this.env.get(key);
    return entry ? entry.value : undefined;
  }

  _envEntryBytes(name, value) {
    return (String(name).length + String(value).length) * 2 + 32;
  }

  _totalEnvBytes() {
    let total = 0;
    for (const entry of this.env.values()) {
      total += this._envEntryBytes(entry.name, entry.value);
    }
    return total;
  }

  setEnv(name, value) {
    const clean = String(name || '').trim();
    if (!clean) return;
    const key = clean.toUpperCase();
    if (value === undefined || value === null || value === '') {
      this.env.delete(key);
      return;
    }
    const valStr = String(value);
    if (valStr.length > MAX_ENV_VALUE_LEN) {
      throw new BatchLimitError(
        `Environment/command line length limit exceeded (variable ${clean} length ${valStr.length} > ${MAX_ENV_VALUE_LEN})`
      );
    }
    const existing = this.env.get(key);
    const existingBytes = existing ? this._envEntryBytes(existing.name, existing.value) : 0;
    const newBytes = this._envEntryBytes(clean, valStr);
    const projectedTotal = this._totalEnvBytes() - existingBytes + newBytes;
    if (projectedTotal > MAX_TOTAL_ENV_BYTES) {
      throw new BatchLimitError(
        `Environment/command line length limit exceeded (total environment size ${projectedTotal} > ${MAX_TOTAL_ENV_BYTES})`
      );
    }
    this.env.set(key, { name: clean, value: valStr });
  }

  _winCwd() {
    return this.services.vfs?.pathTranslator?.toPlatform?.(this.cwd, 'windows') || 'C:\\Users\\user';
  }

  _currentScriptFrame() {
    for (let i = this._frames.length - 1; i >= 0; i--) {
      if (this._frames[i].kind === 'script') return this._frames[i];
    }
    return this._frames[0];
  }

  _popLocalSnapshot() {
    if (this._localStack.length === 0) return null;
    const prev = this._localStack.pop();
    if (prev && prev.bytes) {
      this._activeLocalBudget.bytes = Math.max(0, this._activeLocalBudget.bytes - prev.bytes);
      prev.bytes = 0;
    }
    return prev;
  }

  _clearLocalStack() {
    while (this._localStack.length > 0) {
      this._popLocalSnapshot();
    }
  }

  _pushForFrame(frame, frameCells, frameBytes) {
    frame.forCells = frameCells;
    frame.forBytes = frameBytes;
    this._activeForBudget.cells += frameCells;
    this._activeForBudget.bytes += frameBytes;
    this._frames.push(frame);
  }

  _releaseFrame(frame) {
    if (!frame) return;
    if (frame.forCells) {
      this._activeForBudget.cells = Math.max(0, this._activeForBudget.cells - frame.forCells);
      frame.forCells = 0;
    }
    if (frame.forBytes) {
      this._activeForBudget.bytes = Math.max(0, this._activeForBudget.bytes - frame.forBytes);
      frame.forBytes = 0;
    }
    if (frame.kind === 'sub' && frame.sub) {
      if (typeof frame.sub._clearFrames === 'function') frame.sub._clearFrames();
      if (typeof frame.sub._clearLocalStack === 'function') frame.sub._clearLocalStack();
    }
  }

  _popFrame() {
    const frame = this._frames.pop();
    this._releaseFrame(frame);
    return frame;
  }

  _clearFrames() {
    while (this._frames.length > 0) {
      this._popFrame();
    }
  }

  _handleBatchLimitError(err) {
    this._writeStderr(`${err.message}\n`);
    this.errorLevel = 1;
    if (err?.clearLocals) {
      this._clearLocalStack();
    }
    if (err?.unwindToRoot) {
      this._activeForBudgetHit = true;
      while (this._frames.length > 1) {
        this._popFrame();
      }
    }
  }

  _expandVarExpr(rawExpr, keepLiteralIfMissing = false, delim = '%', nullIfMissing = false, maxLen = MAX_EXPANDED_LINE_LEN) {
    const expr = rawExpr;
    const ensureLen = (val) => {
      if (val.length > maxLen) {
        throw new BatchLimitError(
          `Environment/command line length limit exceeded (${val.length} > ${maxLen})`
        );
      }
      return val;
    };

    // Substring: VAR:~start,len
    const subMatch = /^([^:]+):~(-?\d+)(?:,(-?\d+))?$/.exec(expr);
    if (subMatch) {
      const rawVal = this.getEnv(subMatch[1]);
      if (rawVal === undefined && nullIfMissing) return null;
      const val = rawVal ?? '';
      const startRaw = parseInt(subMatch[2], 10);
      const start = startRaw < 0 ? Math.max(0, val.length + startRaw) : Math.min(val.length, startRaw);
      if (subMatch[3] === undefined) return ensureLen(val.slice(start));
      const lenRaw = parseInt(subMatch[3], 10);
      const end = lenRaw < 0 ? Math.max(start, val.length + lenRaw) : Math.min(val.length, start + lenRaw);
      return ensureLen(val.slice(start, end));
    }

    // Replacement: VAR:old=new (bounded & RegExp-free to prevent expansion bombs and `$&` quirks)
    const repMatch = /^([^:]+):([^=]*)=(.*)$/.exec(expr);
    if (repMatch) {
      const rawVal = this.getEnv(repMatch[1]);
      if (rawVal === undefined && nullIfMissing) return null;
      const val = rawVal ?? '';
      const oldSub = repMatch[2];
      const newSub = repMatch[3];
      if (!oldSub) return ensureLen(val);
      const valLower = val.toLowerCase();
      const oldLower = oldSub.toLowerCase();
      const oldLen = oldSub.length;
      const newLen = newSub.length;
      let matchCount = 0;
      let searchPos = 0;
      while (searchPos <= valLower.length - oldLen) {
        const idx = valLower.indexOf(oldLower, searchPos);
        if (idx === -1) break;
        matchCount += 1;
        searchPos = idx + oldLen;
      }
      const projectedLen = val.length + matchCount * (newLen - oldLen);
      if (projectedLen > maxLen) {
        throw new BatchLimitError(
          `Environment/command line length limit exceeded (expanded length ${projectedLen} > ${maxLen})`
        );
      }
      if (matchCount === 0) return ensureLen(val);
      const repParts = [];
      let cur = 0;
      while (cur <= valLower.length - oldLen) {
        const idx = valLower.indexOf(oldLower, cur);
        if (idx === -1) break;
        if (idx > cur) repParts.push(val.slice(cur, idx));
        if (newSub) repParts.push(newSub);
        cur = idx + oldLen;
      }
      if (cur < val.length) repParts.push(val.slice(cur));
      return repParts.length === 1 ? repParts[0] : repParts.join('');
    }

    const found = this.getEnv(expr);
    if (found !== undefined) return ensureLen(found);
    if (nullIfMissing) return null;
    return ensureLen(keepLiteralIfMissing ? `${delim}${expr}${delim}` : '');
  }

  _expandPercent(text) {
    if (text.length > MAX_EXPANDED_LINE_LEN) {
      throw new BatchLimitError(
        `Environment/command line length limit exceeded (${text.length} > ${MAX_EXPANDED_LINE_LEN})`
      );
    }
    if (text.indexOf('%') === -1) return text;

    const frame = this._currentScriptFrame();
    const args = frame?.args ?? [this.scriptName];
    const offset = frame?.argOffset ?? 0;
    const parts = [];
    let outLen = 0;
    const appendPiece = (piece) => {
      if (!piece) return;
      if (outLen + piece.length > MAX_EXPANDED_LINE_LEN) {
        throw new BatchLimitError(
          `Environment/command line length limit exceeded (${outLen + piece.length} > ${MAX_EXPANDED_LINE_LEN})`
        );
      }
      parts.push(piece);
      outLen += piece.length;
    };

    let i = 0;
    const len = text.length;
    while (i < len) {
      const pct = text.indexOf('%', i);
      if (pct === -1) {
        appendPiece(text.slice(i));
        break;
      }
      if (pct > i) {
        appendPiece(text.slice(i, pct));
      }
      i = pct;
      // `%%` -> preserve as `%%` for FOR loop vars; collapsed later in _collapseDoublePercent
      if (text[i + 1] === '%') {
        appendPiece('%%');
        i += 2;
        continue;
      }
      if (text[i + 1] === '*') {
        const restArgs = args.slice(1 + offset);
        let joinedLen = restArgs.length > 0 ? restArgs.length - 1 : 0;
        for (let aIdx = 0; aIdx < restArgs.length; aIdx++) {
          joinedLen += restArgs[aIdx].length;
          if (outLen + joinedLen > MAX_EXPANDED_LINE_LEN) {
            throw new BatchLimitError(
              `Environment/command line length limit exceeded (${outLen + joinedLen} > ${MAX_EXPANDED_LINE_LEN})`
            );
          }
        }
        appendPiece(restArgs.join(' '));
        i += 2;
        continue;
      }
      if (text[i + 1] === '~' && i + 2 < len && text[i + 2] >= '0' && text[i + 2] <= '9') {
        const idx = text.charCodeAt(i + 2) - 48;
        const val = idx === 0 ? (args[0] ?? '') : (args[idx + offset] ?? '');
        appendPiece(unquote(val));
        i += 3;
        continue;
      }
      if (i + 1 < len && text[i + 1] >= '0' && text[i + 1] <= '9') {
        const idx = text.charCodeAt(i + 1) - 48;
        appendPiece(idx === 0 ? (args[0] ?? '') : (args[idx + offset] ?? ''));
        i += 2;
        continue;
      }
      const close = text.indexOf('%', i + 1);
      if (close !== -1 && close > i + 1 && !/[\r\n]/.test(text.slice(i + 1, close))) {
        const expr = text.slice(i + 1, close);
        const remaining = MAX_EXPANDED_LINE_LEN - outLen;
        if (this._subDepth > 0) {
          // Command-line / CMD /C mode: keep literal `%` when var is undefined so FOR `%i` vars are never swallowed
          const expanded = this._expandVarExpr(expr, true, '%', true, remaining);
          if (expanded !== null) {
            appendPiece(expanded);
            i = close + 1;
            continue;
          }
          appendPiece('%');
          i += 1;
          continue;
        }
        appendPiece(this._expandVarExpr(expr, false, '%', false, remaining));
        i = close + 1;
        continue;
      }
      appendPiece('%');
      i += 1;
    }
    return parts.length === 0 ? '' : (parts.length === 1 ? parts[0] : parts.join(''));
  }

  _expandDelayed(text) {
    if (text.length > MAX_EXPANDED_LINE_LEN) {
      throw new BatchLimitError(
        `Environment/command line length limit exceeded (${text.length} > ${MAX_EXPANDED_LINE_LEN})`
      );
    }
    if (!this.delayedExpansion || text.indexOf('!') === -1) return text;
    const parts = [];
    let outLen = 0;
    const appendPiece = (piece) => {
      if (!piece) return;
      if (outLen + piece.length > MAX_EXPANDED_LINE_LEN) {
        throw new BatchLimitError(
          `Environment/command line length limit exceeded (${outLen + piece.length} > ${MAX_EXPANDED_LINE_LEN})`
        );
      }
      parts.push(piece);
      outLen += piece.length;
    };

    let i = 0;
    const len = text.length;
    while (i < len) {
      const bang = text.indexOf('!', i);
      if (bang === -1) {
        appendPiece(text.slice(i));
        break;
      }
      if (bang > i && text[bang - 1] === '^') {
        if (bang - 1 > i) {
          appendPiece(text.slice(i, bang - 1));
        }
        appendPiece('!');
        i = bang + 1;
        continue;
      }
      if (bang > i) {
        appendPiece(text.slice(i, bang));
      }
      const close = text.indexOf('!', bang + 1);
      if (close !== -1 && close > bang + 1 && !/[\r\n]/.test(text.slice(bang + 1, close))) {
        const expr = text.slice(bang + 1, close);
        const remaining = MAX_EXPANDED_LINE_LEN - outLen;
        appendPiece(this._expandVarExpr(expr, false, '!', false, remaining));
        i = close + 1;
        continue;
      }
      appendPiece('!');
      i = bang + 1;
    }
    return parts.length === 0 ? '' : (parts.length === 1 ? parts[0] : parts.join(''));
  }

  _collapseDoublePercent(text) {
    return text.indexOf('%%') === -1 ? text : text.replace(/%%/g, '%');
  }

  // ---- VFS Sandbox + Shared User Space Helper (Landmine #2) ----

  _isRootUid() {
    return (this.pcb?.uid ?? 1000) === 0;
  }

  _checkVfsWriteQuota(addBytes, createOps = 0, physicalBytes = addBytes, amplifiedBytes = 0) {
    if (this._isRootUid()) return;
    const bytes = Number.isFinite(addBytes) && addBytes > 0 ? Math.trunc(addBytes) : 0;
    const creates = Number.isFinite(createOps) && createOps > 0 ? Math.trunc(createOps) : 0;
    const physBytes = Number.isFinite(physicalBytes) && physicalBytes > 0 ? Math.trunc(physicalBytes) : 0;
    const ampBytes = Number.isFinite(amplifiedBytes) && amplifiedBytes > 0 ? Math.trunc(amplifiedBytes) : 0;
    if (bytes > 0 && this._activeVfsBudget.writeBytes + bytes > MAX_BATCH_VFS_WRITE_BYTES) {
      throw new BatchLimitError(
        `Disk full: batch VFS write quota exceeded (${this._activeVfsBudget.writeBytes + bytes} > ${MAX_BATCH_VFS_WRITE_BYTES} bytes)`,
        { unwindToRoot: true }
      );
    }
    if (
      physBytes > 0 &&
      this._activeVfsBudget.physicalWriteBytes + physBytes > MAX_BATCH_VFS_PHYSICAL_WRITE_BYTES
    ) {
      throw new BatchLimitError(
        `Disk full: batch VFS write quota exceeded (physical ${this._activeVfsBudget.physicalWriteBytes + physBytes} > ${MAX_BATCH_VFS_PHYSICAL_WRITE_BYTES} bytes)`,
        { unwindToRoot: true }
      );
    }
    if (
      ampBytes > 0 &&
      this._activeVfsBudget.amplifiedWriteBytes + ampBytes > MAX_BATCH_VFS_AMPLIFIED_REWRITE_BYTES
    ) {
      throw new BatchLimitError(
        `Disk full: batch VFS write quota exceeded (amplified rewrite ${this._activeVfsBudget.amplifiedWriteBytes + ampBytes} > ${MAX_BATCH_VFS_AMPLIFIED_REWRITE_BYTES} bytes)`,
        { unwindToRoot: true }
      );
    }
    if (creates > 0 && this._activeVfsBudget.createOps + creates > MAX_BATCH_VFS_CREATE_OPS) {
      throw new BatchLimitError(
        `Disk full: batch VFS file/directory creation quota exceeded (${this._activeVfsBudget.createOps + creates} > ${MAX_BATCH_VFS_CREATE_OPS})`,
        { unwindToRoot: true }
      );
    }
  }

  _recordVfsWriteQuota(addBytes, createOps = 0, physicalBytes = addBytes, amplifiedBytes = 0) {
    if (this._isRootUid()) return;
    const bytes = Number.isFinite(addBytes) && addBytes > 0 ? Math.trunc(addBytes) : 0;
    const creates = Number.isFinite(createOps) && createOps > 0 ? Math.trunc(createOps) : 0;
    const physBytes = Number.isFinite(physicalBytes) && physicalBytes > 0 ? Math.trunc(physicalBytes) : 0;
    const ampBytes = Number.isFinite(amplifiedBytes) && amplifiedBytes > 0 ? Math.trunc(amplifiedBytes) : 0;
    if (bytes > 0) this._activeVfsBudget.writeBytes += bytes;
    if (physBytes > 0) this._activeVfsBudget.physicalWriteBytes += physBytes;
    if (ampBytes > 0) this._activeVfsBudget.amplifiedWriteBytes += ampBytes;
    if (creates > 0) this._activeVfsBudget.createOps += creates;
  }

  _checkVfsReadQuota(byteCount) {
    if (this._isRootUid()) return;
    const bytes = Number.isFinite(byteCount) && byteCount > 0 ? Math.trunc(byteCount) : 0;
    if (
      bytes > 0 &&
      this._activeVfsBudget.physicalReadBytes + bytes > MAX_BATCH_VFS_PHYSICAL_READ_BYTES
    ) {
      throw new BatchLimitError(
        `Batch VFS read quota exceeded (physical ${this._activeVfsBudget.physicalReadBytes + bytes} > ${MAX_BATCH_VFS_PHYSICAL_READ_BYTES} bytes)`,
        { unwindToRoot: true }
      );
    }
  }

  _recordVfsReadQuota(byteCount) {
    if (this._isRootUid()) return;
    const bytes = Number.isFinite(byteCount) && byteCount > 0 ? Math.trunc(byteCount) : 0;
    if (bytes > 0) {
      this._activeVfsBudget.physicalReadBytes += bytes;
    }
  }

  _consumeVfsReadQuota(byteCount) {
    this._checkVfsReadQuota(byteCount);
    this._recordVfsReadQuota(byteCount);
  }

  _invalidateReaddirCache() {
    this._readdirCache.clear();
    this._readdirCacheBytes = 0;
    this._symlinkResolveCache.clear();
  }

  _readdirCached(canonicalPath, vfsCtx) {
    const cacheKey = `${vfsCtx?.uid ?? (this.pcb?.uid ?? 1000)}\0${vfsCtx?.sandboxRoot ?? ''}\0${String(canonicalPath).toLowerCase()}`;
    const cached = this._readdirCache.get(cacheKey);
    if (cached) {
      return {
        entries: cached.entries,
        nameBytes: cached.nameBytes,
        maskCache: cached.maskCache,
        fromCache: true,
      };
    }
    if (
      !this._isRootUid() &&
      this._activeVfsBudget.physicalReadBytes >= MAX_BATCH_VFS_PHYSICAL_READ_BYTES
    ) {
      throw new BatchLimitError(
        `Batch VFS read quota exceeded (physical ${this._activeVfsBudget.physicalReadBytes} >= ${MAX_BATCH_VFS_PHYSICAL_READ_BYTES} bytes)`,
        { unwindToRoot: true }
      );
    }
    const rawEntries = this.services.vfs.readdir(canonicalPath, vfsCtx);
    const list = Array.isArray(rawEntries) ? rawEntries : [];
    const entries = new Array(list.length);
    let nameBytes = 0;
    for (let i = 0; i < list.length; i += 1) {
      const e = list[i];
      const name = typeof e?.name === 'string' ? e.name : '';
      if (name.length > 0) {
        nameBytes += utf8ByteLength(name);
      }
      entries[i] = {
        name,
        nameLower: name.toLowerCase(),
        type: e?.type,
        size: e?.size ?? 0,
      };
    }
    const scanCost = Math.max(256, entries.length * 256 + nameBytes);
    if (!this._isRootUid()) {
      this._recordVfsReadQuota(scanCost);
      if (this._activeVfsBudget.physicalReadBytes > MAX_BATCH_VFS_PHYSICAL_READ_BYTES) {
        throw new BatchLimitError(
          `Batch VFS read quota exceeded (physical ${this._activeVfsBudget.physicalReadBytes} > ${MAX_BATCH_VFS_PHYSICAL_READ_BYTES} bytes)`,
          { unwindToRoot: true }
        );
      }
    }
    let maskCache = null;
    if (scanCost <= MAX_BATCH_READDIR_CACHE_BYTES) {
      if (this._readdirCacheBytes + scanCost > MAX_BATCH_READDIR_CACHE_BYTES) {
        this._invalidateReaddirCache();
      }
      maskCache = new Map();
      this._readdirCache.set(cacheKey, {
        entries,
        nameBytes,
        costBytes: scanCost,
        maskCache,
      });
      this._readdirCacheBytes += scanCost;
    }
    return { entries, nameBytes, maskCache, fromCache: false };
  }

  _matchDirEntriesCached(dirSnap, maskLower, dirsOnly = false) {
    const entries = dirSnap.entries;
    const maskCache = dirSnap.maskCache;
    if (!dirsOnly && maskLower === '*') {
      return { matches: entries, cacheHit: true };
    }
    const cacheKey = (dirsOnly ? 'D:' : 'A:') + maskLower;
    if (maskCache) {
      const cached = maskCache.get(cacheKey);
      if (cached) {
        return { matches: cached, cacheHit: true };
      }
    }
    if (maskLower !== '*' && maskLower !== '*.*') {
      const filterCost = Math.max(64, entries.length * 64 + maskLower.length * 8);
      this._checkVfsReadQuota(filterCost);
      this._recordVfsReadQuota(filterCost);
    }
    let matches;
    if (maskLower === '*') {
      matches = [];
      for (let i = 0; i < entries.length; i += 1) {
        if (!dirsOnly || entries[i].type === 'dir') {
          matches.push(entries[i]);
        }
      }
    } else {
      const matcher = compileWildcardMatcherLower(maskLower);
      matches = [];
      for (let i = 0; i < entries.length; i += 1) {
        const e = entries[i];
        if ((!dirsOnly || e.type === 'dir') && matcher(e.nameLower)) {
          matches.push(e);
        }
      }
    }
    if (maskCache) {
      if (maskCache.size >= 32 && (maskLower === '*' || maskLower === '*.*')) {
        const oldestKey = maskCache.keys().next().value;
        if (oldestKey !== undefined) maskCache.delete(oldestKey);
      }
      if (maskCache.size < 32) {
        maskCache.set(cacheKey, matches);
      }
    }
    return { matches, cacheHit: false };
  }

  _expandForDPattern(pat, isMultiPattern, onMatch) {
    const cleanPat = unquote(pat);
    const norm = cleanPat.replace(/\//g, '\\');
    const slash = norm.lastIndexOf('\\');
    const dirPart = slash === -1 ? '.' : (norm.slice(0, slash) || '\\');
    const mask = (slash === -1 ? norm : norm.slice(slash + 1)) || '*';
    if (cleanPat.length > MAX_BATCH_WILDCARD_MASK_LEN || mask.length > MAX_BATCH_WILDCARD_MASK_LEN) {
      throw new BatchLimitError(
        `Batch FOR /D wildcard mask length limit exceeded (${Math.max(cleanPat.length, mask.length)} > ${MAX_BATCH_WILDCARD_MASK_LEN} chars)`,
        { unwindToRoot: true }
      );
    }
    const maskLower = mask.toLowerCase().replace(/\*+/g, '*');
    try {
      const { canonicalPath, vfsCtx } = this._resolveVfsPath(dirPart, 'read');
      const dirSnap = this._readdirCached(canonicalPath, vfsCtx);
      const { matches, cacheHit } = this._matchDirEntriesCached(dirSnap, maskLower, true);
      if (isMultiPattern && (cacheHit || maskLower === '*' || maskLower === '*.*')) {
        const hitCost = Math.max(64, maskLower.length * 4);
        this._checkVfsReadQuota(hitCost);
        this._recordVfsReadQuota(hitCost);
      }
      if (!cacheHit && this._stepTracker && dirSnap.entries.length >= 64) {
        const rem = this._stepTracker.maxSteps - this._stepTracker.executed;
        if (rem > 0) {
          const workUnits = Math.min(rem, Math.floor(dirSnap.entries.length / 64));
          if (workUnits > 0) {
            this._stepTracker.executed += workUnits;
            this.instructionsExecuted += workUnits;
          }
        }
      }
      const prefix = slash === -1 ? null : norm.slice(0, slash);
      for (let i = 0; i < matches.length; i += 1) {
        const e = matches[i];
        const item = prefix === null ? e.name : `${prefix}\\${e.name}`;
        onMatch(item);
      }
    } catch (err) {
      if (err?.isBatchLimitError) throw err;
      void err;
    }
  }

  _flushPendingAppend() {
    const pending = this._pendingAppend;
    if (!pending) return;
    this._pendingAppend = null;
    if (pending.totalBytes <= 0 || pending.chunks.length === 0) return;

    let combined;
    if (pending.chunks.length === 1) {
      combined = pending.chunks[0];
    } else {
      combined = new Uint8Array(pending.totalBytes);
      let offset = 0;
      for (let i = 0; i < pending.chunks.length; i += 1) {
        combined.set(pending.chunks[i], offset);
        offset += pending.chunks[i].byteLength;
      }
    }
    pending.chunks.length = 0;

    try {
      let curSize = pending.existingSize;
      try {
        const st = this.services.vfs.stat(pending.canonicalPath, pending.vfsCtx);
        if (typeof st?.size === 'number' && Number.isFinite(st.size)) {
          curSize = st.size;
        }
      } catch (stErr) {
        if (stErr?.code !== ERROR_CODES.ENOENT) throw stErr;
        curSize = 0;
      }
      const nextFileBytes = curSize + combined.byteLength;
      if (nextFileBytes > MAX_BATCH_FILE_BYTES) {
        throw new BatchLimitError(
          `Batch file size limit exceeded (${nextFileBytes} > ${MAX_BATCH_FILE_BYTES} bytes)`
        );
      }
      // Logical writeBytes was already recorded incrementally while buffering; enforce & commit physicalWriteBytes now
      this._checkVfsWriteQuota(0, 0, nextFileBytes, 0);
      this.services.vfs.writeFile(pending.canonicalPath, combined, { ...pending.vfsCtx, append: true });
      this._invalidateReaddirCache();
      this._recordVfsWriteQuota(0, 0, nextFileBytes, 0);
    } catch (err) {
      if (err?.isBatchLimitError) throw err;
      this._writeStderr(`Redirection error: ${err?.message || String(err)}\n`);
      this.errorLevel = 1;
    }
  }

  _flushPendingAppendSafe() {
    if (!this._pendingAppend) return true;
    try {
      this._flushPendingAppend();
      return true;
    } catch (err) {
      if (err?.isBatchLimitError) {
        this._handleBatchLimitError(err);
        return false;
      }
      this._writeStderr(`Redirection error: ${err?.message || String(err)}\n`);
      this.errorLevel = 1;
      return false;
    }
  }

  _checkCapSync(capability, context = null) {
    const permissions = this.services.permissions;
    const appId = this.pcb?.appId || this.appRecord?.appId || `pid-${this.pcb?.pid ?? 0}`;
    const uid = this.pcb?.uid ?? 1000;
    if (!permissions || uid === 0) return true;

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
      const g = permissions.getGrant(appId, capability);
      if (g && typeof g.state === 'string') state = g.state;
    }
    if (state === null && typeof permissions.getDefaultPolicy === 'function') {
      state = permissions.getDefaultPolicy(capability);
    } else if (state === null && permissions._defaultPolicies) {
      state = permissions._defaultPolicies[capability] ?? 'deny';
    }

    const effectivePolicy =
      state === 'allow' || state === 'deny' || state === 'prompt' ? state : 'deny';

    if (typeof permissions.checkPermission === 'function') {
      const budget = this._activePermBudget;
      const isPrompt = effectivePolicy === 'prompt';
      const dedupKey = `${capability}:${effectivePolicy}`;
      const alreadyAudited = budget.auditedKeys.has(dedupKey);
      const withinTotalCap = budget.auditCount < MAX_PERMISSION_AUDIT_EVENTS;
      const allowedPrompt =
        !isPrompt || (budget.promptCount < MAX_PERMISSION_PROMPT_CALLS && !alreadyAudited);

      if (withinTotalCap && allowedPrompt) {
        budget.auditCount += 1;
        if (isPrompt) {
          budget.promptCount += 1;
        }
        budget.auditedKeys.add(dedupKey);
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
          if (p && typeof p.catch === 'function') p.catch((err) => { void err; });
        } catch (err) {
          void err;
        }
      }
    }
    if (effectivePolicy === 'deny') return false;
    if (effectivePolicy === 'allow') return true;
    return uid === 1000;
  }

  _ownAppRoot(appId) {
    if (!appId || typeof appId !== 'string') return null;
    if (appId.includes('/') || appId.includes('\\') || appId === '.' || appId === '..') {
      return null;
    }
    return `/var/appdata/windows/${appId}`;
  }

  _isAccessDeniedErr(err) {
    const c = err?.code;
    return (
      c === ERROR_CODES.EACCES ||
      c === ERROR_CODES.EPERM ||
      c === ERROR_CODES.E_PATH_TRAVERSAL ||
      c === ERROR_CODES.E_SANDBOX_VIOLATION
    );
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
    if (!vfs) throw new VfsError('VFS unavailable', { code: ERROR_CODES.EIO });
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
        throw new VfsError(`Permission denied (fs.read.user)`, { code: ERROR_CODES.EACCES, path: winPath });
      }
      if (checkWrite && !this._checkCapSync('fs.write.user', { path: canonicalPath, mode: accessMode })) {
        throw new VfsError(`Permission denied (fs.write.user)`, { code: ERROR_CODES.EACCES, path: winPath });
      }
      if (isLexicalSharedUser) {
        return {
          canonicalPath,
          isSharedUser: true,
          vfsCtx: {
            uid: uid === 0 ? 0 : 1000,
            gid: gid === 0 ? 0 : 1000,
            pid: this.pcb?.pid,
            platform: 'windows',
            appId,
            cwd: this.cwd,
            sandboxRoot: '/home/user',
          },
        };
      }
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

  _writeStdout(text) {
    if (!text) return;
    if (this._stdoutSink) {
      this._stdoutSink(text);
      return;
    }
    if (this.services.processManager && this.pcb) {
      this.services.processManager.writeStdout(this.pcb.pid, text);
    }
  }

  _writeStderr(text) {
    if (!text) return;
    if (this._stderrSink) {
      this._stderrSink(text);
      return;
    }
    if (this.services.processManager && this.pcb) {
      this.services.processManager.writeStderr(this.pcb.pid, text);
    }
  }

  // ---- Step-Budgeted Execution Loop (100% Synchronous!) ----

  step(budget = 1000) {
    const maxSteps = Math.max(0, Math.trunc(budget));
    const tracker = { executed: 0, maxSteps };
    const prevTracker = this._stepTracker;
    this._stepTracker = tracker;
    this._pendingFault = null;

    try {
      while (tracker.executed < maxSteps) {
        if (this._pendingFault) {
          const fault = this._pendingFault;
          this._pendingFault = null;
          this._clearLocalStack();
          return { status: 'FAULT', fault, instructionsExecuted: tracker.executed };
        }
        if (this.exited || this._frames.length === 0) {
          this.exited = true;
          this._clearLocalStack();
          return {
            status: 'EXITED',
            exitCode: this.exitCode,
            instructionsExecuted: tracker.executed,
          };
        }

        const frame = this._frames[this._frames.length - 1];

        if (frame.kind === 'sub') {
          const rem = maxSteps - tracker.executed;
          if (rem <= 0) break;
          let subRes;
          try {
            subRes = frame.sub.step(rem);
          } catch (err) {
            if (err?.isBatchLimitError) {
              this._popFrame();
              this._handleBatchLimitError(err);
              continue;
            }
            this._popFrame();
            throw err;
          }
          tracker.executed += subRes.instructionsExecuted;
          this.instructionsExecuted += subRes.instructionsExecuted;
          if (subRes.status === 'FAULT') {
            this._popFrame();
            this._clearLocalStack();
            return { status: 'FAULT', fault: subRes.fault, instructionsExecuted: tracker.executed };
          }
          if (subRes.status === 'EXITED') {
            const subBudgetHit = Boolean(frame.sub._activeForBudgetHit);
            this._invalidateReaddirCache();
            this._popFrame();
            this.errorLevel = frame.sub.errorLevel;
            if (subBudgetHit) {
              this._activeForBudgetHit = true;
              while (this._frames.length > 1) {
                this._popFrame();
              }
            } else if (typeof frame.onComplete === 'function') {
              try {
                frame.onComplete();
              } catch (err) {
                if (err?.isBatchLimitError) {
                  this._handleBatchLimitError(err);
                } else {
                  throw err;
                }
              }
            }
            if (this._pendingFault) {
              const fault = this._pendingFault;
              this._pendingFault = null;
              this._clearLocalStack();
              return { status: 'FAULT', fault, instructionsExecuted: tracker.executed };
            }
            if (this.exited) {
              this._clearLocalStack();
              return { status: 'EXITED', exitCode: this.exitCode, instructionsExecuted: tracker.executed };
            }
          } else if (subRes.instructionsExecuted === 0) {
            break;
          }
          continue;
        }

        if (frame.kind === 'chain') {
          if (frame.idx >= frame.items.length) {
            this._popFrame();
            continue;
          }
          const item = frame.items[frame.idx++];
          if (item.op === '&&' && this.errorLevel !== 0) continue;
          if (item.op === '||' && this.errorLevel === 0) continue;
          if (!item.cmd) continue;
          tracker.executed += 1;
          this.instructionsExecuted += 1;
          try {
            const chainOutcome = this._runSingleChainEntry(item.cmd, frame.suppressEcho);
            if (chainOutcome.jumped) {
              const framePos = this._frames.indexOf(frame);
              if (framePos !== -1) {
                this._releaseFrame(this._frames[framePos]);
                this._frames.splice(framePos, 1);
              }
            }
          } catch (err) {
            if (err?.isBatchLimitError) {
              this._handleBatchLimitError(err);
            } else {
              throw err;
            }
          }
          if (this._pendingFault) {
            const fault = this._pendingFault;
            this._pendingFault = null;
            this._clearLocalStack();
            return { status: 'FAULT', fault, instructionsExecuted: tracker.executed };
          }
          if (this.exited) {
            this._clearLocalStack();
            return { status: 'EXITED', exitCode: this.exitCode, instructionsExecuted: tracker.executed };
          }
          continue;
        }

        if (frame.kind === 'forL') {
          const done = frame.step > 0 ? frame.cur > frame.end : frame.cur < frame.end;
          if (done) {
            this._popFrame();
            continue;
          }
          const valStr = String(frame.cur);
          frame.cur += frame.step;
          tracker.executed += 1;
          this.instructionsExecuted += 1;
          try {
            const body = replaceForVarBounded(frame.bodyTemplate, frame.varName, valStr);
            this._pushInlineCommands(body, false);
          } catch (err) {
            if (err?.isBatchLimitError) {
              this._writeStderr(`${err.message}\n`);
              this.errorLevel = 1;
            } else {
              throw err;
            }
          }
          continue;
        }

        if (frame.kind === 'forD') {
          if (frame.patIndex >= frame.patterns.length) {
            const { varName, items, bodyTemplate, forCells, forBytes } = frame;
            if (items.length > 0) {
              frame.forCells = 0;
              frame.forBytes = 0;
              this._frames.pop();
              this._frames.push({
                kind: 'for',
                varName,
                items,
                index: 0,
                bodyTemplate,
                tokenVars: null,
                forCells,
                forBytes,
              });
            } else {
              this._popFrame();
            }
            continue;
          }
          const pat = frame.patterns[frame.patIndex++];
          tracker.executed += 1;
          this.instructionsExecuted += 1;
          try {
            this._expandForDPattern(pat, true, (item) => {
              const itemCells = 1;
              const itemBytes = 16 + utf8ByteLength(item);
              if (
                this._activeForBudget.cells + itemCells > MAX_ACTIVE_FOR_F_CELLS ||
                this._activeForBudget.bytes + itemBytes > MAX_ACTIVE_FOR_F_BYTES
              ) {
                throw new BatchLimitError(
                  `Batch active FOR budget exceeded (cells=${this._activeForBudget.cells + itemCells}/${MAX_ACTIVE_FOR_F_CELLS}, bytes=${this._activeForBudget.bytes + itemBytes}/${MAX_ACTIVE_FOR_F_BYTES})`,
                  { unwindToRoot: true }
                );
              }
              frame.forCells += itemCells;
              frame.forBytes += itemBytes;
              this._activeForBudget.cells += itemCells;
              this._activeForBudget.bytes += itemBytes;
              frame.items.push(item);
            });
          } catch (err) {
            if (err?.isBatchLimitError) {
              if (!err.unwindToRoot) {
                this._popFrame();
              }
              this._handleBatchLimitError(err);
            } else {
              throw err;
            }
          }
          continue;
        }

        if (frame.kind === 'for') {
          if (frame.index >= frame.items.length) {
            this._popFrame();
            continue;
          }
          const item = frame.items[frame.index++];
          tracker.executed += 1;
          this.instructionsExecuted += 1;
          // Substitute loop variable `%%i` / `%i` (and tokens `%%j`, `%%k` for FOR /F!)
          try {
            let body = frame.bodyTemplate;
            if (frame.tokenVars && Array.isArray(item)) {
              for (let t = 0; t < frame.tokenVars.length; t++) {
                const vChar = frame.tokenVars[t];
                const val = item[t] ?? '';
                body = replaceForVarBounded(body, vChar, val);
              }
            } else {
              body = replaceForVarBounded(body, frame.varName, String(item ?? ''));
            }
            this._pushInlineCommands(body, false);
          } catch (err) {
            if (err?.isBatchLimitError) {
              this._writeStderr(`${err.message}\n`);
              this.errorLevel = 1;
            } else {
              throw err;
            }
          }
          continue;
        }

        if (frame.ip >= frame.stmts.length) {
          this._popFrame();
          continue;
        }

        const stmt = frame.stmts[frame.ip++];
        if (stmt.isLabel) continue;

        tracker.executed += 1;
        this.instructionsExecuted += 1;

        // Expand %VAR% at parse time ONLY for top-level script statements (block sub-statements already had %VAR% expanded)
        try {
          if (stmt.parseError) {
            throw new BatchLimitError(stmt.parseError);
          }
          const expanded = frame.kind === 'script' ? this._expandPercent(stmt.text) : stmt.text;
          this._executeStatement(expanded);
        } catch (err) {
          if (err?.isBatchLimitError) {
            this._handleBatchLimitError(err);
          } else {
            throw err;
          }
        }

        if (this._pendingFault) {
          const fault = this._pendingFault;
          this._pendingFault = null;
          this._clearLocalStack();
          return { status: 'FAULT', fault, instructionsExecuted: tracker.executed };
        }
        if (this.exited) {
          this._clearLocalStack();
          return {
            status: 'EXITED',
            exitCode: this.exitCode,
            instructionsExecuted: tracker.executed,
          };
        }
      }

      if (this._frames.length === 0) {
        this.exited = true;
        this._clearLocalStack();
        return { status: 'EXITED', exitCode: this.exitCode, instructionsExecuted: tracker.executed };
      }

      return {
        status: 'YIELD',
        instructionsExecuted: tracker.executed,
      };
    } finally {
      this._flushPendingAppendSafe();
      this._invalidateReaddirCache();
      this._stepTracker = prevTracker;
    }
  }

  _blockFrameDepth() {
    let depth = 0;
    for (let i = 0; i < this._frames.length; i++) {
      if (this._frames[i].kind === 'block') depth += 1;
    }
    return depth;
  }

  _pushInlineCommands(rawBody, expandPercentNow = false) {
    const text = expandPercentNow ? this._expandPercent(rawBody) : rawBody;
    const trimmed = text.trim();
    if (!trimmed) return;
    if (this._blockFrameDepth() >= MAX_PAREN_NESTING_DEPTH) {
      throw new BatchLimitError(`Maximum parenthesis nesting depth (${MAX_PAREN_NESTING_DEPTH}) exceeded`);
    }
    if (trimmed.startsWith('(') && trimmed.endsWith(')')) {
      const blk = extractParenBlock(trimmed, 0);
      if (blk && blk.afterIdx >= trimmed.length) {
        const subStmts = parseScriptStatements(blk.inner).stmts;
        if (subStmts.length > 0) {
          this._frames.push({ kind: 'block', stmts: subStmts, ip: 0 });
        }
        return;
      }
    }
    this._frames.push({
      kind: 'block',
      stmts: [{ text: trimmed, lineNo: 0, isLabel: false }],
      ip: 0,
    });
  }

  _runSingleChainEntry(rawSingle, suppressEcho) {
    let single = rawSingle;
    let localSuppress = suppressEcho;
    while (single.startsWith('@')) {
      localSuppress = true;
      single = single.slice(1).trimStart();
    }
    if (!single || single.startsWith('::')) return { jumped: false, suspended: false };
    if (/^IF(?:\s|\(|$)/i.test(single)) {
      this._executeIf(single);
      return { jumped: true, suspended: false };
    }
    if (/^FOR(?:\s|$)/i.test(single)) {
      this._executeFor(single);
      return { jumped: true, suspended: false };
    }

    if (this.echoOn && !localSuppress) {
      this._writeStdout(`${this._winCwd()}>${single}\n`);
    }

    return this._executePipeline(single);
  }

  _executeStatement(rawLine) {
    let trimmed = rawLine.trim();
    if (!trimmed) return;

    // Handle parenthesized compound block `( cmd1 \n cmd2 )`
    if (trimmed.startsWith('(')) {
      if (this._blockFrameDepth() >= MAX_PAREN_NESTING_DEPTH) {
        throw new BatchLimitError(`Maximum parenthesis nesting depth (${MAX_PAREN_NESTING_DEPTH}) exceeded`);
      }
      const blk = extractParenBlock(trimmed, 0);
      if (blk && blk.afterIdx >= trimmed.length) {
        const subStmts = parseScriptStatements(blk.inner).stmts;
        if (subStmts.length > 0) {
          this._frames.push({ kind: 'block', stmts: subStmts, ip: 0 });
        }
        return;
      }
    }

    // Strip leading `@` echo suppression
    let suppressEcho = false;
    while (trimmed.startsWith('@')) {
      suppressEcho = true;
      trimmed = trimmed.slice(1).trimStart();
    }
    if (!trimmed || trimmed.startsWith('::')) return;

    const upperHead = trimmed.toUpperCase();
    if (upperHead === 'REM' || /^REM[\s\t]/i.test(upperHead)) return;

    // Control-flow statements `IF` and `FOR` own their entire trailing line/block (don't split their internal `&`!)
    if (/^IF(?:\s|\(|$)/i.test(trimmed)) {
      this._executeIf(trimmed);
      return;
    }
    if (/^FOR(?:\s|$)/i.test(trimmed)) {
      this._executeFor(trimmed);
      return;
    }

    // Split top-level chaining (`&`, `&&`, `||`)
    const chain = splitChainedCommands(trimmed);
    for (let i = 0; i < chain.length; i++) {
      if (this.exited || this._pendingFault) return;
      const { op, cmd } = chain[i];
      if (op === '&&' && this.errorLevel !== 0) continue;
      if (op === '||' && this.errorLevel === 0) continue;
      if (!cmd) continue;

      const outcome = this._runSingleChainEntry(cmd, suppressEcho);
      if (outcome.suspended) {
        if (i + 1 < chain.length) {
          // Run remaining chained commands right after the suspended sub-context finishes
          const chainFrame = {
            kind: 'chain',
            items: chain.slice(i + 1),
            idx: 0,
            suppressEcho,
          };
          this._frames.splice(Math.max(0, this._frames.length - 1), 0, chainFrame);
        }
        return;
      }
      if (outcome.jumped || outcome.limitExceeded) return;
    }
  }

  _executePipeStages(stages, initialStdin = null) {
    let pipeInput = initialStdin;
    for (let i = 0; i < stages.length; i++) {
      const isLast = i === stages.length - 1;
      const res = this._executeSingleCommand(stages[i], {
        stdinText: pipeInput,
        captureStdout: !isLast,
        allowSuspend: true,
      });
      if (res.limitExceeded) {
        return { jumped: false, suspended: false, limitExceeded: true };
      }
      if (res.suspended) {
        const susp = this._suspendedSub;
        this._suspendedSub = null;
        const remainingStages = stages.slice(i + 1);
        this._frames.push({
          kind: 'sub',
          sub: susp.sub,
          onComplete: () => {
            susp.flushRedirs();
            if (!susp.wasLimitHit?.() && remainingStages.length > 0 && !this.exited && !this._pendingFault) {
              this._executePipeStages(remainingStages, susp.getCapturedStdout());
            }
          },
        });
        return { jumped: false, suspended: true };
      }
      if (res.jumped || this.exited || this._pendingFault) {
        return { jumped: true, suspended: false };
      }
      pipeInput = res.capturedStdout ?? '';
    }
    return { jumped: false, suspended: false };
  }

  _executePipeline(cmdStr) {
    const stages = splitPipeStages(cmdStr);
    return this._executePipeStages(stages, null);
  }

  _executeSingleCommand(rawCmd, { stdinText = null, captureStdout = false, allowSuspend = true } = {}) {
    // Execution-time delayed expansion `!VAR!` and `%%` collapse
    let delayed;
    try {
      delayed = this._collapseDoublePercent(this._expandDelayed(rawCmd));
    } catch (err) {
      if (err?.isBatchLimitError) {
        this._writeStderr(`${err.message}\n`);
        this.errorLevel = 1;
        return { jumped: false, suspended: false, limitExceeded: true, capturedStdout: '' };
      }
      throw err;
    }
    const { command, redirs } = extractRedirections(delayed);
    if (!command) return { jumped: false, suspended: false, limitExceeded: false, capturedStdout: '' };

    // Read stdin redirection if `< file` (with pre-read size & physical read quota caps)
    let effectiveStdin = stdinText;
    if (redirs.stdinFile) {
      try {
        this._flushPendingAppend();
        const { canonicalPath, vfsCtx } = this._resolveVfsPath(redirs.stdinFile, 'read');
        const st = this.services.vfs.stat(canonicalPath, vfsCtx);
        const fileSize = typeof st?.size === 'number' && Number.isFinite(st.size) ? st.size : 0;
        if (fileSize > MAX_BATCH_IO_BUFFER_BYTES) {
          throw new BatchLimitError(
            `Batch I/O buffer limit exceeded reading stdin redirection (${fileSize} > ${MAX_BATCH_IO_BUFFER_BYTES} bytes)`
          );
        }
        this._checkVfsReadQuota(fileSize);
        effectiveStdin = String(this.services.vfs.readFile(canonicalPath, { ...vfsCtx, encoding: 'utf8' }));
        this._recordVfsReadQuota(fileSize > 0 ? fileSize : utf8ByteLength(effectiveStdin));
        if (effectiveStdin.length > MAX_BATCH_IO_BUFFER_BYTES) {
          throw new BatchLimitError(
            `Batch I/O buffer limit exceeded reading stdin redirection (${effectiveStdin.length} > ${MAX_BATCH_IO_BUFFER_BYTES} bytes)`
          );
        }
      } catch (err) {
        if (err?.isBatchLimitError) {
          this._handleBatchLimitError(err);
          return { jumped: false, suspended: false, limitExceeded: true, capturedStdout: '' };
        }
        const msg = this._isAccessDeniedErr(err)
          ? `Access is denied: ${redirs.stdinFile}\n`
          : `The system cannot find the file specified: ${redirs.stdinFile}\n`;
        this._writeStderr(msg);
        this.errorLevel = 1;
        return { jumped: false, suspended: false, limitExceeded: false, capturedStdout: '' };
      }
    }

    const stdoutIsNul = Boolean(redirs.stdoutFile && redirs.stdoutFile.toUpperCase() === 'NUL');
    const stderrIsNul = Boolean(redirs.stderrFile && redirs.stderrFile.toUpperCase() === 'NUL');
    let stdoutBuf = '';
    let stderrBuf = '';
    let stdoutBytes = 0;
    let stderrBytes = 0;

    const emitOut = (s) => {
      const str = String(s);
      if (captureStdout || redirs.stdoutFile) {
        if (!captureStdout && stdoutIsNul) return;
        const addBytes = utf8ByteLength(str);
        if (
          stdoutBytes + addBytes > MAX_BATCH_IO_BUFFER_BYTES ||
          stdoutBuf.length + str.length > MAX_BATCH_IO_BUFFER_BYTES
        ) {
          throw new BatchLimitError(
            `Batch I/O buffer limit exceeded (stdout > ${MAX_BATCH_IO_BUFFER_BYTES} bytes)`
          );
        }
        stdoutBytes += addBytes;
        stdoutBuf += str;
      } else {
        this._writeStdout(str);
      }
    };
    emitOut.isNul =
      (!captureStdout && stdoutIsNul) ||
      (!captureStdout && !redirs.stdoutFile && Boolean(this._stdoutSink?.isNul));
    const emitErr = (s) => {
      const str = String(s);
      if (redirs.stderrToStdout) {
        emitOut(str);
      } else if (redirs.stderrFile) {
        if (stderrIsNul) return;
        const addBytes = utf8ByteLength(str);
        if (
          stderrBytes + addBytes > MAX_BATCH_IO_BUFFER_BYTES ||
          stderrBuf.length + str.length > MAX_BATCH_IO_BUFFER_BYTES
        ) {
          throw new BatchLimitError(
            `Batch I/O buffer limit exceeded (stderr > ${MAX_BATCH_IO_BUFFER_BYTES} bytes)`
          );
        }
        stderrBytes += addBytes;
        stderrBuf += str;
      } else {
        this._writeStderr(str);
      }
    };
    const writeRedirFile = (targetFile, content, isAppend) => {
      const chunk = UTF8_ENCODER.encode(content);
      const addBytes = chunk.byteLength;

      // Ultra-fast same-step coalescing when appending again to the exact same non-shared-user targetFile & cwd
      if (
        isAppend &&
        this._pendingAppend &&
        !this._pendingAppend.isSharedUser &&
        this._pendingAppend.rawTargetFile === targetFile &&
        this._pendingAppend.cwd === this.cwd
      ) {
        if (addBytes === 0) {
          return;
        }
        const nextFileBytes = this._pendingAppend.existingSize + this._pendingAppend.totalBytes + addBytes;
        if (nextFileBytes > MAX_BATCH_FILE_BYTES) {
          throw new BatchLimitError(
            `Batch file size limit exceeded (${nextFileBytes} > ${MAX_BATCH_FILE_BYTES} bytes)`
          );
        }
        this._checkVfsWriteQuota(addBytes, 0, nextFileBytes, 0);
        this._recordVfsWriteQuota(addBytes, 0, 0, 0);
        this._pendingAppend.chunks.push(chunk);
        this._pendingAppend.totalBytes += addBytes;
        if (this._isRootUid() && this._pendingAppend.totalBytes >= 8 * 1024 * 1024) {
          this._flushPendingAppend();
        }
        return;
      }

      const { canonicalPath, vfsCtx, isSharedUser } = this._resolveVfsPath(targetFile, 'write');

      // Fast-path coalescing for consecutive `>>` appends targeting the same canonical file
      if (isAppend && this._pendingAppend && this._pendingAppend.canonicalPath === canonicalPath) {
        if (addBytes === 0) {
          return;
        }
        const nextFileBytes = this._pendingAppend.existingSize + this._pendingAppend.totalBytes + addBytes;
        if (nextFileBytes > MAX_BATCH_FILE_BYTES) {
          throw new BatchLimitError(
            `Batch file size limit exceeded (${nextFileBytes} > ${MAX_BATCH_FILE_BYTES} bytes)`
          );
        }
        // Check logical write quota & prospective physical flush size before buffering
        this._checkVfsWriteQuota(addBytes, 0, nextFileBytes, 0);
        this._recordVfsWriteQuota(addBytes, 0, 0, 0);
        this._pendingAppend.chunks.push(chunk);
        this._pendingAppend.totalBytes += addBytes;
        if (this._isRootUid() && this._pendingAppend.totalBytes >= 8 * 1024 * 1024) {
          this._flushPendingAppend();
        }
        return;
      }

      // Flush any pending buffered append to a different file or before a non-append (`>`) overwrite
      if (this._pendingAppend) {
        this._flushPendingAppend();
      }

      let exists = false;
      let existingSize = 0;
      let existingStat = null;
      try {
        const st = this.services.vfs.stat(canonicalPath, vfsCtx);
        if (st.type === 'dir') {
          throw new VfsError(`Is a directory: ${canonicalPath}`, {
            code: ERROR_CODES.EISDIR,
            path: canonicalPath,
          });
        }
        exists = true;
        existingStat = st;
        existingSize = typeof st?.size === 'number' && Number.isFinite(st.size) ? st.size : 0;
      } catch (stErr) {
        if (stErr?.code !== ERROR_CODES.ENOENT) throw stErr;
      }

      if (isAppend && exists && addBytes === 0) {
        return;
      }

      const nextFileBytes = isAppend ? existingSize + addBytes : addBytes;
      if (nextFileBytes > MAX_BATCH_FILE_BYTES) {
        throw new BatchLimitError(
          `Batch file size limit exceeded (${nextFileBytes} > ${MAX_BATCH_FILE_BYTES} bytes)`
        );
      }

      const isVirtualMount =
        canonicalPath === '/proc' ||
        canonicalPath.startsWith('/proc/') ||
        canonicalPath === '/dev' ||
        canonicalPath.startsWith('/dev/');

      if (isAppend && exists && !isVirtualMount && existingStat?.type === 'file') {
        const canWriteExisting =
          vfsCtx.uid === 0 ||
          (existingStat.uid === vfsCtx.uid
            ? (existingStat.mode & 0o200) !== 0
            : existingStat.gid === vfsCtx.gid
              ? (existingStat.mode & 0o020) !== 0
              : (existingStat.mode & 0o002) !== 0);
        if (canWriteExisting) {
          this._checkVfsWriteQuota(addBytes, 0, nextFileBytes, 0);
          this._recordVfsWriteQuota(addBytes, 0, 0, 0);
          this._pendingAppend = {
            rawTargetFile: targetFile,
            cwd: this.cwd,
            isSharedUser: Boolean(isSharedUser),
            canonicalPath,
            vfsCtx,
            existingSize,
            chunks: [chunk],
            totalBytes: addBytes,
          };
          if (this._isRootUid() && this._pendingAppend.totalBytes >= 8 * 1024 * 1024) {
            this._flushPendingAppend();
          }
          return;
        }
      }

      const createOps = exists ? 0 : 1;
      this._checkVfsWriteQuota(addBytes, createOps, nextFileBytes, 0);
      this.services.vfs.writeFile(canonicalPath, chunk, { ...vfsCtx, append: isAppend });
      this._invalidateReaddirCache();
      this._recordVfsWriteQuota(addBytes, createOps, nextFileBytes, 0);
    };
    let redirLimitHit = false;
    const flushRedirs = () => {
      if (redirs.stdoutFile && !stdoutIsNul) {
        try {
          writeRedirFile(redirs.stdoutFile, stdoutBuf, redirs.stdoutAppend);
        } catch (err) {
          if (err?.isBatchLimitError) {
            this._handleBatchLimitError(err);
            redirLimitHit = true;
            return;
          }
          this._writeStderr(`Redirection error: ${err.message}\n`);
          this.errorLevel = 1;
        }
      }
      if (redirs.stderrFile && !stderrIsNul) {
        try {
          writeRedirFile(redirs.stderrFile, stderrBuf, redirs.stderrAppend);
        } catch (err) {
          if (err?.isBatchLimitError) {
            this._handleBatchLimitError(err);
            redirLimitHit = true;
            return;
          }
          this._writeStderr(`Redirection error: ${err.message}\n`);
          this.errorLevel = 1;
        }
      }
    };

    let jumped = false;
    try {
      jumped = this._dispatchBuiltin(command, {
        stdinText: effectiveStdin,
        emitOut,
        emitErr,
        allowSuspend,
      });
    } catch (err) {
      if (err?.isBatchLimitError) {
        this._handleBatchLimitError(err);
        return { jumped: false, suspended: false, limitExceeded: true, capturedStdout: '' };
      }
      throw err;
    }

    if (this._suspendedSub) {
      this._suspendedSub.flushRedirs = flushRedirs;
      this._suspendedSub.wasLimitHit = () => redirLimitHit;
      this._suspendedSub.getCapturedStdout = () => stdoutBuf;
      return { jumped: false, suspended: true, limitExceeded: false, capturedStdout: '' };
    }

    flushRedirs();

    if (redirLimitHit) {
      return { jumped: false, suspended: false, limitExceeded: true, capturedStdout: '' };
    }

    return { jumped, suspended: false, limitExceeded: false, capturedStdout: stdoutBuf };
  }

  _applyBatCmdSuccess(cmdUpper) {
    // CRITICAL Edge Case #18:
    // In `.cmd`, successful SET/PATH/ASSOC/PROMPT resets ERRORLEVEL to 0!
    // In `.bat`, successful SET/PATH/ASSOC/PROMPT PRESERVES prior ERRORLEVEL unchanged!
    if (BAT_PRESERVE_ERR_COMMANDS.has(cmdUpper)) {
      if (this.scriptKind === 'cmd') {
        this.errorLevel = 0;
      }
      return;
    }
    this.errorLevel = 0;
  }

  _dispatchBuiltin(command, { stdinText, emitOut, emitErr, allowSuspend = true }) {
    const trimmed = command.trim();
    if (!trimmed) return false;

    // Extract command verb (handle `ECHO.` / `ECHO:` / `CD..` / `CD\`) without regex-scanning giant arg payloads
    let verb = '';
    let argStr = '';
    const head16 = trimmed.slice(0, 16);
    const echoDot = /^echo([.:\/\\+])/i.exec(head16);
    const cdSpecial = !echoDot ? /^(cd|chdir)(\.\.|\\)/i.exec(head16) : null;
    if (echoDot) {
      verb = 'ECHO';
      const rest = trimmed.slice(5);
      argStr = echoDot[1] === '.' && rest === '' ? '\x00EMPTY_LINE' : rest;
    } else if (cdSpecial) {
      verb = 'CD';
      argStr = trimmed.slice(cdSpecial[1].length);
    } else {
      let wsIdx = 0;
      const tLen = trimmed.length;
      while (wsIdx < tLen && !isBatchWhitespace(trimmed[wsIdx])) wsIdx += 1;
      verb = trimmed.slice(0, wsIdx).toUpperCase();
      if (wsIdx < tLen) {
        let argStart = wsIdx + 1;
        while (argStart < tLen && isBatchWhitespace(trimmed[argStart])) argStart += 1;
        argStr = trimmed.slice(argStart);
      }
    }

    this.lastCommand = verb;

    // ---- ECHO ----
    if (verb === 'ECHO') {
      if (argStr === '\x00EMPTY_LINE') {
        emitOut('\n');
        return false;
      }
      const cleanArg = argStr.trim();
      if (cleanArg.toUpperCase() === 'OFF') {
        this.echoOn = false;
        return false;
      }
      if (cleanArg.toUpperCase() === 'ON') {
        this.echoOn = true;
        return false;
      }
      if (argStr === '') {
        emitOut(`ECHO is ${this.echoOn ? 'on' : 'off'}.\n`);
        return false;
      }
      emitOut(`${argStr}\n`);
      return false;
    }

    // ---- REM ----
    if (verb === 'REM') return false;

    // ---- SET (CRITICAL Edge Case #18!) ----
    if (verb === 'SET') {
      const a = argStr.trim();
      if (!a) {
        for (const entry of this.env.values()) {
          emitOut(`${entry.name}=${entry.value}\n`);
        }
        this._applyBatCmdSuccess('SET');
        return false;
      }
      if (/^\/a\b/i.test(a)) {
        let exprStr = a.slice(2).trim();
        if (exprStr.startsWith('"') && exprStr.endsWith('"')) {
          exprStr = exprStr.slice(1, -1);
        }
        const res = evaluateSetArithmetic(
          exprStr,
          (k) => this.getEnv(k) ?? '0',
          (k, v) => this.setEnv(k, v)
        );
        if (!res.ok) {
          emitErr(`${res.error}\n`);
          this.errorLevel = 1;
          return false;
        }
        this._applyBatCmdSuccess('SET');
        return false;
      }

      // Handle `SET "VAR=VAL"` vs `SET VAR=VAL`
      let assign = a;
      if (assign.startsWith('"')) {
        const endQ = assign.lastIndexOf('"');
        if (endQ > 0) assign = assign.slice(1, endQ);
      }
      const eqIdx = assign.indexOf('=');
      if (eqIdx === -1) {
        // Prefix query `SET prefix`
        const prefix = assign.toUpperCase();
        let matched = false;
        for (const [k, entry] of this.env.entries()) {
          if (k.startsWith(prefix)) {
            emitOut(`${entry.name}=${entry.value}\n`);
            matched = true;
          }
        }
        if (!matched) {
          emitErr(`Environment variable ${assign} not defined\n`);
          this.errorLevel = 1;
        } else {
          this._applyBatCmdSuccess('SET');
        }
        return false;
      }

      const varName = assign.slice(0, eqIdx).trim();
      const varVal = assign.slice(eqIdx + 1);
      if (!varName) {
        this.errorLevel = 1;
        return false;
      }
      this.setEnv(varName, varVal);
      this._applyBatCmdSuccess('SET');
      return false;
    }

    // ---- PATH / ASSOC / PROMPT (also follow Edge Case #18 .bat vs .cmd rule!) ----
    if (verb === 'PATH') {
      const a = argStr.trim();
      if (!a) {
        emitOut(`PATH=${this.getEnv('PATH') ?? ''}\n`);
      } else {
        this.setEnv('PATH', a.startsWith('=') ? a.slice(1) : a);
      }
      this._applyBatCmdSuccess('PATH');
      return false;
    }
    if (verb === 'PROMPT') {
      this.setEnv('PROMPT', argStr.trim() || '$P$G');
      this._applyBatCmdSuccess('PROMPT');
      return false;
    }
    if (verb === 'ASSOC') {
      this._applyBatCmdSuccess('ASSOC');
      return false;
    }

    // ---- SETLOCAL / ENDLOCAL ----
    if (verb === 'SETLOCAL') {
      if (this._localStack.length >= MAX_SETLOCAL_DEPTH) {
        emitErr('Maximum setlocal recursion level reached.\n');
        this.errorLevel = 1;
        return false;
      }
      const snapBytes = this._totalEnvBytes() + 64;
      if (this._activeLocalBudget.bytes + snapBytes > MAX_ACTIVE_SETLOCAL_BYTES) {
        throw new BatchLimitError(
          `Batch active SETLOCAL snapshot budget exceeded (${this._activeLocalBudget.bytes + snapBytes} > ${MAX_ACTIVE_SETLOCAL_BYTES} bytes)`,
          { unwindToRoot: true, clearLocals: true }
        );
      }
      const snap = new Map();
      for (const [k, v] of this.env.entries()) snap.set(k, { ...v });
      this._activeLocalBudget.bytes += snapBytes;
      this._localStack.push({
        env: snap,
        delayedExpansion: this.delayedExpansion,
        cwd: this.cwd,
        bytes: snapBytes,
      });
      const opts = argStr.toUpperCase();
      if (opts.includes('ENABLEDELAYEDEXPANSION')) this.delayedExpansion = true;
      if (opts.includes('DISABLEDELAYEDEXPANSION')) this.delayedExpansion = false;
      this.errorLevel = 0;
      return false;
    }
    if (verb === 'ENDLOCAL') {
      const prev = this._popLocalSnapshot();
      if (prev) {
        this.env = prev.env;
        this.delayedExpansion = prev.delayedExpansion;
        this.cwd = prev.cwd;
      }
      this.errorLevel = 0;
      return false;
    }

    // ---- GOTO ----
    if (verb === 'GOTO') {
      const rawTarget = argStr.trim().split(/\s+/)[0] || '';
      const target = rawTarget.replace(/^:/, '').toLowerCase();
      // Unwind any block/for frames up to the enclosing script frame
      while (this._frames.length > 1 && this._frames[this._frames.length - 1].kind !== 'script') {
        this._popFrame();
      }
      const frame = this._frames[this._frames.length - 1];
      if (target === 'eof') {
        frame.ip = frame.stmts.length;
        return true;
      }
      if (!this._labels.has(target)) {
        emitErr(`The system cannot find the batch label specified - ${rawTarget}\n`);
        this.errorLevel = 1;
        this.exited = true;
        this.exitCode = 1;
        this._clearFrames();
        this._clearLocalStack();
        return true;
      }
      frame.ip = this._labels.get(target);
      return true;
    }

    // ---- CALL :sub [args...] ----
    if (verb === 'CALL') {
      const tokens = tokenizeArgs(argStr.trim());
      if (tokens.length === 0) {
        this.errorLevel = 0;
        return false;
      }
      const targetRaw = tokens[0];
      if (targetRaw.startsWith(':')) {
        const lbl = targetRaw.slice(1).toLowerCase();
        if (!this._labels.has(lbl)) {
          emitErr(`The system cannot find the batch label specified - ${targetRaw}\n`);
          this.errorLevel = 1;
          return false;
        }
        const scriptDepth = this._frames.filter((f) => f.kind === 'script').length;
        if (scriptDepth >= MAX_CALL_DEPTH) {
          emitErr('Maximum batch CALL recursion depth exceeded\n');
          this.errorLevel = 1;
          return false;
        }
        this._frames.push({
          kind: 'script',
          stmts: this._rootStmts,
          ip: this._labels.get(lbl),
          args: [targetRaw, ...tokens.slice(1)],
          argOffset: 0,
        });
        return true;
      }
      // `CALL <builtin>` re-evaluates after a second round of expansion
      this._pushInlineCommands(argStr.trim(), false);
      return true;
    }

    // ---- EXIT [/B] [code] ----
    if (verb === 'EXIT') {
      const tokens = tokenizeArgs(argStr.trim());
      let isLocal = false;
      let codeVal = this.errorLevel;
      for (const tok of tokens) {
        if (tok.toUpperCase() === '/B') {
          isLocal = true;
        } else {
          const parsed = parseInt(tok, 10);
          if (Number.isFinite(parsed)) codeVal = parsed | 0;
        }
      }
      this.errorLevel = codeVal;
      if (isLocal) {
        // Exit current script/CALL frame
        while (this._frames.length > 0) {
          const popped = this._popFrame();
          if (popped.kind === 'script') break;
        }
        if (this._frames.length === 0) {
          this.exited = true;
          this.exitCode = codeVal;
          this._clearLocalStack();
        }
        return true;
      }
      this.exited = true;
      this.exitCode = codeVal;
      this._clearFrames();
      this._clearLocalStack();
      return true;
    }

    // ---- SHIFT ----
    if (verb === 'SHIFT') {
      const frame = this._currentScriptFrame();
      if (frame) frame.argOffset += 1;
      return false;
    }

    // ---- CMD /C <command> (depth-limited, strictly budget-bounded, routed through emitOut/emitErr) ----
    if (verb === 'CMD') {
      const m = /^\/c\s+([\s\S]+)$/i.exec(argStr.trim());
      if (m) {
        if (this._subDepth >= this._maxSubDepth) {
          emitErr(`CMD /C maximum nesting depth (${this._maxSubDepth}) exceeded.\n`);
          this.errorLevel = 1;
          return false;
        }
        this._flushPendingAppend();
        this._invalidateReaddirCache();
        const sub = new BatchExecutionContext({
          scriptText: m[1],
          scriptKind: 'cmd',
          scriptName: 'cmd.cmd',
          pcb: this.pcb,
          appRecord: this.appRecord,
          services: this.services,
          env: Object.fromEntries(Array.from(this.env.values()).map((e) => [e.name, e.value])),
          subDepth: this._subDepth + 1,
          maxSubDepth: this._maxSubDepth,
          stdoutSink: emitOut,
          stderrSink: emitErr,
          activeForBudget: this._activeForBudget,
          activeLocalBudget: this._activeLocalBudget,
          activeVfsBudget: this._activeVfsBudget,
          activePermBudget: this._activePermBudget,
        });
        sub.echoOn = false;
        sub.cwd = this.cwd;

        const tracker = this._stepTracker;
        const remaining = tracker ? Math.max(0, tracker.maxSteps - tracker.executed) : 1000;

        if (remaining > 0) {
          let res;
          try {
            res = sub.step(remaining);
          } catch (err) {
            this._invalidateReaddirCache();
            sub._clearFrames();
            sub._clearLocalStack();
            throw err;
          }
          this._invalidateReaddirCache();
          if (tracker) tracker.executed += res.instructionsExecuted;
          this.instructionsExecuted += res.instructionsExecuted;
          if (res.status === 'FAULT') {
            sub._clearFrames();
            sub._clearLocalStack();
            this._pendingFault = res.fault;
            return true;
          }
          if (res.status === 'EXITED') {
            const subBudgetHit = Boolean(sub._activeForBudgetHit);
            sub._clearFrames();
            sub._clearLocalStack();
            this.errorLevel = sub.errorLevel;
            if (subBudgetHit) {
              this._activeForBudgetHit = true;
              while (this._frames.length > 1) {
                this._popFrame();
              }
              return true;
            }
            return false;
          }
          if (allowSuspend) {
            this._suspendedSub = { sub };
            return false;
          }
          sub._clearFrames();
          sub._clearLocalStack();
          this.errorLevel = sub.errorLevel;
          return false;
        }

        if (allowSuspend) {
          this._suspendedSub = { sub };
          return false;
        }
        sub._clearFrames();
        sub._clearLocalStack();
        this.errorLevel = sub.errorLevel;
        return false;
      }
      return false;
    }

    // ---- VFS File & Directory Commands ----
    if (verb === 'CD' || verb === 'CHDIR') {
      let target = argStr.trim();
      if (target.toUpperCase().startsWith('/D ')) target = target.slice(3).trim();
      target = unquote(target);
      if (!target) {
        emitOut(`${this._winCwd()}\n`);
        this.errorLevel = 0;
        return false;
      }
      this._flushPendingAppend();
      try {
        const { canonicalPath, vfsCtx } = this._resolveVfsPath(target, 'read');
        const st = this.services.vfs.stat(canonicalPath, vfsCtx);
        if (st.type !== 'dir') {
          emitErr('The directory name is invalid.\n');
          this.errorLevel = 1;
          return false;
        }
        this.cwd = canonicalPath;
        if (this.pcb) this.pcb.cwd = canonicalPath;
        this.errorLevel = 0;
      } catch (err) {
        const msg = this._isAccessDeniedErr(err)
          ? `Access is denied: ${target}\n`
          : `The system cannot find the path specified: ${target}\n`;
        emitErr(msg);
        this.errorLevel = 1;
      }
      return false;
    }

    if (verb === 'DIR') {
      const tokens = tokenizeArgs(argStr.trim());
      const bare = tokens.some((t) => t.toUpperCase() === '/B');
      const targetArg = tokens.find((t) => !t.startsWith('/')) ?? '.';
      const target = unquote(targetArg);
      this._flushPendingAppend();
      try {
        const { canonicalPath, vfsCtx } = this._resolveVfsPath(target, 'read');
        const { entries, nameBytes, fromCache } = this._readdirCached(canonicalPath, vfsCtx);
        if (!emitOut.isNul) {
          if (fromCache && !this._isRootUid()) {
            const emitCost = Math.max(64, entries.length * 64 + nameBytes * 2);
            this._checkVfsReadQuota(emitCost);
            this._recordVfsReadQuota(emitCost);
          }
          if (this._stepTracker && entries.length >= 64) {
            const rem = this._stepTracker.maxSteps - this._stepTracker.executed;
            if (rem > 0) {
              const workUnits = Math.min(rem, Math.floor(entries.length / 64));
              if (workUnits > 0) {
                this._stepTracker.executed += workUnits;
                this.instructionsExecuted += workUnits;
              }
            }
          }
          if (!bare) {
            emitOut(` Directory of ${this.services.vfs.pathTranslator.toPlatform(canonicalPath, 'windows')}\n\n`);
          }
          const BATCH_CHUNK = 256;
          for (let i = 0; i < entries.length; i += BATCH_CHUNK) {
            const end = Math.min(entries.length, i + BATCH_CHUNK);
            const parts = new Array(end - i);
            if (bare) {
              for (let j = i; j < end; j += 1) {
                parts[j - i] = `${entries[j].name}\n`;
              }
            } else {
              for (let j = i; j < end; j += 1) {
                const e = entries[j];
                const tag = e.type === 'dir' ? '<DIR>         ' : String(e.size ?? 0).padStart(14, ' ');
                parts[j - i] = `${tag} ${e.name}\n`;
              }
            }
            emitOut(parts.join(''));
          }
        }
        this.errorLevel = 0;
      } catch (err) {
        if (err?.isBatchLimitError) throw err;
        const msg = this._isAccessDeniedErr(err)
          ? `Access is denied: ${target}\n`
          : `File Not Found: ${target}\n`;
        emitErr(msg);
        this.errorLevel = 1;
      }
      return false;
    }

    if (verb === 'MKDIR' || verb === 'MD') {
      const tokens = tokenizeArgs(argStr.trim()).filter((t) => !t.startsWith('/'));
      if (tokens.length === 0) {
        emitErr('The syntax of the command is incorrect.\n');
        this.errorLevel = 1;
        return false;
      }
      this._flushPendingAppend();
      for (const t of tokens) {
        try {
          const { canonicalPath, vfsCtx } = this._resolveVfsPath(unquote(t), 'write');
          let missingDirs = 0;
          let probePath = canonicalPath;
          while (probePath && probePath !== '/') {
            try {
              this.services.vfs.stat(probePath, vfsCtx);
              break;
            } catch (stErr) {
              if (stErr?.code === ERROR_CODES.ENOENT) {
                missingDirs += 1;
                const slash = probePath.lastIndexOf('/');
                probePath = slash > 0 ? probePath.slice(0, slash) : '/';
              } else {
                break;
              }
            }
          }
          if (missingDirs > 0) {
            this._checkVfsWriteQuota(0, missingDirs);
          }
          this.services.vfs.mkdir(canonicalPath, { ...vfsCtx, recursive: true });
          this._invalidateReaddirCache();
          if (missingDirs > 0) {
            this._recordVfsWriteQuota(0, missingDirs);
          }
          this.errorLevel = 0;
        } catch (err) {
          if (err?.isBatchLimitError) throw err;
          emitErr(`Cannot create directory: ${err.message}\n`);
          this.errorLevel = 1;
        }
      }
      return false;
    }

    if (verb === 'RMDIR' || verb === 'RD') {
      const tokens = tokenizeArgs(argStr.trim());
      const recursive = tokens.some((t) => t.toUpperCase() === '/S');
      const paths = tokens.filter((t) => !t.startsWith('/'));
      this._flushPendingAppend();
      for (const p of paths) {
        try {
          const { canonicalPath, vfsCtx } = this._resolveVfsPath(unquote(p), 'write');
          this.services.vfs.rmdir(canonicalPath, { ...vfsCtx, recursive });
          this._invalidateReaddirCache();
          this.errorLevel = 0;
        } catch (err) {
          emitErr(`Cannot remove directory: ${err.message}\n`);
          this.errorLevel = 1;
        }
      }
      return false;
    }

    if (verb === 'COPY') {
      const tokens = tokenizeArgs(argStr.trim()).filter((t) => !t.startsWith('/'));
      if (tokens.length < 2) {
        emitErr('The syntax of the command is incorrect.\n');
        this.errorLevel = 1;
        return false;
      }
      this._flushPendingAppend();
      try {
        const vfs = this.services.vfs;
        const src = this._resolveVfsPath(unquote(tokens[0]), 'read');
        const dst = this._resolveVfsPath(unquote(tokens[1]), 'write');
        const srcStat = vfs.stat(src.canonicalPath, src.vfsCtx);
        const maxBytes =
          typeof vfs.maxStorageBytes === 'number' && Number.isFinite(vfs.maxStorageBytes) && vfs.maxStorageBytes > 0
            ? Math.min(MAX_BATCH_FILE_BYTES, Math.floor(vfs.maxStorageBytes))
            : MAX_BATCH_FILE_BYTES;
        if (typeof srcStat.size === 'number' && srcStat.size > maxBytes) {
          throw new BatchLimitError(`File size (${srcStat.size}) exceeds maximum allowed (${maxBytes})`);
        }
        let dstExists = false;
        try {
          vfs.lstat(dst.canonicalPath, dst.vfsCtx);
          dstExists = true;
        } catch (stErr) {
          if (stErr?.code !== ERROR_CODES.ENOENT) throw stErr;
        }
        const createOps = dstExists ? 0 : 1;
        const estBytes = typeof srcStat.size === 'number' ? srcStat.size : 0;
        this._checkVfsWriteQuota(estBytes, createOps, estBytes, 0);
        this._checkVfsReadQuota(estBytes);
        const data = vfs.readFile(src.canonicalPath, src.vfsCtx);
        this._recordVfsReadQuota(data.byteLength);
        if (data.byteLength > maxBytes) {
          throw new BatchLimitError(`File size (${data.byteLength}) exceeds maximum allowed (${maxBytes})`);
        }
        this._checkVfsWriteQuota(data.byteLength, createOps, data.byteLength, 0);
        vfs.writeFile(dst.canonicalPath, data, dst.vfsCtx);
        this._invalidateReaddirCache();
        this._recordVfsWriteQuota(data.byteLength, createOps, data.byteLength, 0);
        emitOut('        1 file(s) copied.\n');
        this.errorLevel = 0;
      } catch (err) {
        if (err?.isBatchLimitError) throw err;
        emitErr(`COPY failed: ${err.message}\n`);
        this.errorLevel = 1;
      }
      return false;
    }

    if (verb === 'MOVE') {
      const tokens = tokenizeArgs(argStr.trim()).filter((t) => !t.startsWith('/'));
      if (tokens.length < 2) {
        emitErr('The syntax of the command is incorrect.\n');
        this.errorLevel = 1;
        return false;
      }
      this._flushPendingAppend();
      try {
        const vfs = this.services.vfs;
        const src = this._resolveVfsPath(unquote(tokens[0]), 'readwrite');
        let dst = this._resolveVfsPath(unquote(tokens[1]), 'write');

        const srcStat = vfs.lstat(src.canonicalPath, src.vfsCtx);
        let dstStat = null;
        try {
          dstStat = vfs.lstat(dst.canonicalPath, dst.vfsCtx);
        } catch (stErr) {
          if (stErr?.code !== ERROR_CODES.ENOENT) throw stErr;
        }

        // If destination is an existing directory, move into <dst>/<srcBasename>
        if (dstStat && dstStat.type === 'dir') {
          const srcLeaf = src.canonicalPath.split('/').filter(Boolean).pop();
          if (!srcLeaf) {
            throw new VfsError(`Invalid MOVE source path: ${src.canonicalPath}`, { code: ERROR_CODES.EINVAL });
          }
          const baseDir = dst.canonicalPath === '/' ? '' : dst.canonicalPath;
          const expandedDstPath = `${baseDir}/${srcLeaf}`;
          if ((this.pcb?.uid ?? 1000) !== 0) {
            const symInfo = this._resolveSymlinkTarget(expandedDstPath);
            if (symInfo.touchesSharedUser && !this._checkCapSync('fs.write.user', { path: expandedDstPath, mode: 'write' })) {
              throw new VfsError('Permission denied (fs.write.user)', {
                code: ERROR_CODES.EACCES,
                path: unquote(tokens[1]),
              });
            }
          }
          dst = { ...dst, canonicalPath: expandedDstPath };
          dstStat = null;
          try {
            dstStat = vfs.lstat(dst.canonicalPath, dst.vfsCtx);
          } catch (stErr) {
            if (stErr?.code !== ERROR_CODES.ENOENT) throw stErr;
          }
        }

        const sameRoot =
          src.vfsCtx.sandboxRoot === dst.vfsCtx.sandboxRoot &&
          src.vfsCtx.uid === dst.vfsCtx.uid;

        if (sameRoot) {
          vfs.rename(src.canonicalPath, dst.canonicalPath, dst.vfsCtx);
          this._invalidateReaddirCache();
        } else {
          if (srcStat.type !== 'file') {
            throw new VfsError(`Cross-root MOVE only supports regular files (got ${srcStat.type})`, {
              code: ERROR_CODES.EACCES,
              path: src.canonicalPath,
            });
          }
          if (dstStat && dstStat.type === 'dir') {
            throw new VfsError(`Cannot overwrite directory: ${dst.canonicalPath}`, {
              code: ERROR_CODES.EISDIR,
              path: dst.canonicalPath,
            });
          }
          const maxBytes =
            typeof vfs.maxStorageBytes === 'number' && Number.isFinite(vfs.maxStorageBytes) && vfs.maxStorageBytes > 0
              ? Math.min(MAX_BATCH_FILE_BYTES, Math.floor(vfs.maxStorageBytes))
              : MAX_BATCH_FILE_BYTES;
          if (typeof srcStat.size === 'number' && srcStat.size > maxBytes) {
            throw new VfsError(`File size (${srcStat.size}) exceeds maximum allowed (${maxBytes})`, {
              code: ERROR_CODES.ENOSPC,
              path: src.canonicalPath,
            });
          }
          const createOps = dstStat ? 0 : 1;
          const estBytes = typeof srcStat.size === 'number' ? srcStat.size : 0;
          this._checkVfsWriteQuota(estBytes, createOps, estBytes, 0);
          this._checkVfsReadQuota(estBytes);
          const data = vfs.readFile(src.canonicalPath, src.vfsCtx);
          this._recordVfsReadQuota(data.byteLength);
          if (data.byteLength > maxBytes) {
            throw new VfsError(`File size (${data.byteLength}) exceeds maximum allowed (${maxBytes})`, {
              code: ERROR_CODES.ENOSPC,
              path: src.canonicalPath,
            });
          }
          this._checkVfsWriteQuota(data.byteLength, createOps, data.byteLength, 0);
          if (dstStat?.type === 'symlink') {
            vfs.unlink(dst.canonicalPath, dst.vfsCtx);
            this._invalidateReaddirCache();
          }
          vfs.writeFile(dst.canonicalPath, data, dst.vfsCtx);
          this._invalidateReaddirCache();
          this._recordVfsWriteQuota(data.byteLength, createOps, data.byteLength, 0);
          try {
            vfs.unlink(src.canonicalPath, src.vfsCtx);
            this._invalidateReaddirCache();
          } catch (unlinkErr) {
            if (!dstStat) {
              try {
                vfs.unlink(dst.canonicalPath, dst.vfsCtx);
                this._invalidateReaddirCache();
              } catch (cleanupErr) {
                void cleanupErr;
              }
            }
            throw unlinkErr;
          }
        }
        emitOut('        1 file(s) moved.\n');
        this.errorLevel = 0;
      } catch (err) {
        if (err?.isBatchLimitError) throw err;
        emitErr(`MOVE failed: ${err.message}\n`);
        this.errorLevel = 1;
      }
      return false;
    }

    if (verb === 'DEL' || verb === 'ERASE') {
      const paths = tokenizeArgs(argStr.trim()).filter((t) => !t.startsWith('/'));
      this._flushPendingAppend();
      for (const p of paths) {
        try {
          const { canonicalPath, vfsCtx } = this._resolveVfsPath(unquote(p), 'write');
          this.services.vfs.unlink(canonicalPath, vfsCtx);
          this._invalidateReaddirCache();
          this.errorLevel = 0;
        } catch (err) {
          const msg = this._isAccessDeniedErr(err)
            ? `Access is denied: ${p}\n`
            : `Could Not Find ${p}\n`;
          emitErr(msg);
          this.errorLevel = 1;
        }
      }
      return false;
    }

    if (verb === 'TYPE') {
      const paths = tokenizeArgs(argStr.trim()).filter((t) => !t.startsWith('/'));
      if (paths.length === 0) {
        this.errorLevel = 1;
        return false;
      }
      this._flushPendingAppend();
      let totalBytes = 0;
      for (const p of paths) {
        try {
          const { canonicalPath, vfsCtx } = this._resolveVfsPath(unquote(p), 'read');
          const st = this.services.vfs.stat(canonicalPath, vfsCtx);
          const fileSize = typeof st?.size === 'number' && Number.isFinite(st.size) ? st.size : 0;
          if (totalBytes + fileSize > MAX_BATCH_IO_BUFFER_BYTES) {
            throw new BatchLimitError(
              `Batch I/O buffer limit exceeded in TYPE (${totalBytes + fileSize} > ${MAX_BATCH_IO_BUFFER_BYTES} bytes)`
            );
          }
          this._checkVfsReadQuota(fileSize);
          const content = String(this.services.vfs.readFile(canonicalPath, { ...vfsCtx, encoding: 'utf8' }));
          this._recordVfsReadQuota(fileSize > 0 ? fileSize : utf8ByteLength(content));
          const actualSize = Math.max(fileSize, content.length);
          if (totalBytes + actualSize > MAX_BATCH_IO_BUFFER_BYTES) {
            throw new BatchLimitError(
              `Batch I/O buffer limit exceeded in TYPE (${totalBytes + actualSize} > ${MAX_BATCH_IO_BUFFER_BYTES} bytes)`
            );
          }
          totalBytes += actualSize;
          emitOut(content);
          this.errorLevel = 0;
        } catch (err) {
          if (err?.isBatchLimitError) throw err;
          const msg = this._isAccessDeniedErr(err)
            ? `Access is denied: ${p}\n`
            : `The system cannot find the file specified: ${p}\n`;
          emitErr(msg);
          this.errorLevel = 1;
        }
      }
      return false;
    }

    if (verb === 'FIND' || verb === 'FINDSTR') {
      const tokens = tokenizeArgs(argStr.trim());
      const ignoreCase = tokens.some((t) => t.toUpperCase() === '/I');
      const nonFlags = tokens.filter((t) => !t.startsWith('/'));
      const needle = unquote(nonFlags[0] ?? '');
      let haystack = stdinText ?? '';
      if (nonFlags.length >= 2) {
        this._flushPendingAppend();
        try {
          const { canonicalPath, vfsCtx } = this._resolveVfsPath(unquote(nonFlags[1]), 'read');
          const st = this.services.vfs.stat(canonicalPath, vfsCtx);
          const fileSize = typeof st?.size === 'number' && Number.isFinite(st.size) ? st.size : 0;
          if (fileSize > MAX_BATCH_IO_BUFFER_BYTES) {
            throw new BatchLimitError(
              `Batch I/O buffer limit exceeded in ${verb} (${fileSize} > ${MAX_BATCH_IO_BUFFER_BYTES} bytes)`
            );
          }
          this._checkVfsReadQuota(fileSize);
          haystack = String(this.services.vfs.readFile(canonicalPath, { ...vfsCtx, encoding: 'utf8' }));
          this._recordVfsReadQuota(fileSize > 0 ? fileSize : utf8ByteLength(haystack));
          if (haystack.length > MAX_BATCH_IO_BUFFER_BYTES) {
            throw new BatchLimitError(
              `Batch I/O buffer limit exceeded in ${verb} (${haystack.length} > ${MAX_BATCH_IO_BUFFER_BYTES} bytes)`
            );
          }
        } catch (err) {
          if (err?.isBatchLimitError) throw err;
          if (this._isAccessDeniedErr(err)) {
            emitErr(`Access is denied - ${nonFlags[1]}\n`);
            this.errorLevel = 1;
          } else {
            emitErr(`File not found - ${nonFlags[1]}\n`);
            this.errorLevel = 2;
          }
          return false;
        }
      }
      let foundAny = false;
      const cmpNeedle = ignoreCase ? needle.toLowerCase() : needle;
      const hLen = haystack.length;
      let pos = 0;
      while (pos <= hLen) {
        const nl = haystack.indexOf('\n', pos);
        const isTrailingEmpty = nl === -1 && pos === hLen && hLen > 0;
        if (isTrailingEmpty) break;
        const end = nl === -1 ? hLen : nl;
        let line = haystack.slice(pos, end);
        if (line.endsWith('\r')) line = line.slice(0, -1);
        const cmpLine = ignoreCase ? line.toLowerCase() : line;
        if (cmpLine.includes(cmpNeedle)) {
          emitOut(`${line}\n`);
          foundAny = true;
        }
        if (nl === -1) break;
        pos = nl + 1;
      }
      this.errorLevel = foundAny ? 0 : 1;
      return false;
    }

    if (verb === 'VER') {
      emitOut('OmniOS Windows Subsystem [Version 10.0.22631]\n');
      this.errorLevel = 0;
      return false;
    }
    if (verb === 'CLS' || verb === 'PAUSE' || verb === 'TITLE' || verb === 'VERIFY') {
      if (verb === 'VERIFY' && argStr.trim().toUpperCase() === 'OTHER') {
        this.errorLevel = 1;
      } else {
        this.errorLevel = 0;
      }
      return false;
    }

    emitErr(`'${verb}' is not recognized as an internal or external command.\n`);
    this.errorLevel = 9009;
    return false;
  }

  // ---- IF [NOT] [/I] ... [ELSE ...] ----

  _executeIf(rawIf) {
    let rest = this._expandDelayed(rawIf.slice(2).trimStart());
    let ignoreCase = false;
    let negate = false;

    while (true) {
      if (/^\/i\b/i.test(rest)) {
        ignoreCase = true;
        rest = rest.slice(2).trimStart();
        continue;
      }
      if (/^not\b/i.test(rest)) {
        negate = !negate;
        rest = rest.slice(3).trimStart();
        continue;
      }
      break;
    }

    let cond = false;
    let bodyRest = '';

    if (/^exist\b/i.test(rest)) {
      rest = rest.slice(5).trimStart();
      const { token, tail } = this._consumeNextToken(rest);
      bodyRest = tail;
      this._flushPendingAppend();
      try {
        const { canonicalPath, vfsCtx } = this._resolveVfsPath(unquote(token), 'read');
        this.services.vfs.stat(canonicalPath, vfsCtx);
        cond = true;
      } catch (err) {
        void err;
        cond = false;
      }
    } else if (/^defined\b/i.test(rest)) {
      rest = rest.slice(7).trimStart();
      const { token, tail } = this._consumeNextToken(rest);
      bodyRest = tail;
      cond = this.getEnv(unquote(token)) !== undefined;
    } else if (/^errorlevel\b/i.test(rest)) {
      rest = rest.slice(10).trimStart();
      const { token, tail } = this._consumeNextToken(rest);
      bodyRest = tail;
      const n = parseInt(token, 10);
      cond = Number.isFinite(n) && this.errorLevel >= n;
    } else {
      // Comparison: `lhs==rhs` OR `lhs EQU|NEQ|LSS|LEQ|GTR|GEQ rhs`
      const eqMatch = this._parseIfComparison(rest);
      if (!eqMatch) {
        this._writeStderr(`Invalid IF syntax: ${rawIf}\n`);
        this.errorLevel = 1;
        return;
      }
      const { lhs, op, rhs, tail } = eqMatch;
      bodyRest = tail;

      const cmpNumL = /^-?\d+$/.test(lhs) ? parseInt(lhs, 10) : null;
      const cmpNumR = /^-?\d+$/.test(rhs) ? parseInt(rhs, 10) : null;
      const bothNum = cmpNumL !== null && cmpNumR !== null;

      const sL = ignoreCase ? lhs.toLowerCase() : lhs;
      const sR = ignoreCase ? rhs.toLowerCase() : rhs;

      if (op === '==' || op === 'EQU') {
        cond = bothNum && op === 'EQU' ? cmpNumL === cmpNumR : sL === sR;
      } else if (op === 'NEQ') {
        cond = bothNum ? cmpNumL !== cmpNumR : sL !== sR;
      } else if (op === 'LSS') {
        cond = bothNum ? cmpNumL < cmpNumR : sL < sR;
      } else if (op === 'LEQ') {
        cond = bothNum ? cmpNumL <= cmpNumR : sL <= sR;
      } else if (op === 'GTR') {
        cond = bothNum ? cmpNumL > cmpNumR : sL > sR;
      } else if (op === 'GEQ') {
        cond = bothNum ? cmpNumL >= cmpNumR : sL >= sR;
      }
    }

    if (negate) cond = !cond;
    const { thenPart, elsePart } = splitIfElse(bodyRest);
    const chosen = cond ? thenPart : elsePart;
    if (chosen) {
      this._pushInlineCommands(chosen, false);
    }
  }

  _consumeNextToken(str) {
    let i = 0;
    const len = str.length;
    while (i < len && isBatchWhitespace(str[i])) i += 1;
    const start = i;
    let inQ = false;
    while (i < len) {
      const c = str[i];
      if (c === '"') { inQ = !inQ; i += 1; continue; }
      if (!inQ && isBatchWhitespace(c)) break;
      i += 1;
    }
    return { token: str.slice(start, i), tail: str.slice(i).trimStart() };
  }

  _parseIfComparison(str) {
    // Scan lhs until `==` or whitespace
    let i = 0;
    let inQ = false;
    while (i < str.length) {
      const c = str[i];
      if (c === '"') { inQ = !inQ; i += 1; continue; }
      if (!inQ && str[i] === '=' && str[i + 1] === '=') {
        const lhs = str.slice(0, i).trim();
        const afterEq = str.slice(i + 2).trimStart();
        const { token: rhs, tail } = this._consumeNextToken(afterEq);
        return { lhs, op: '==', rhs, tail };
      }
      if (!inQ && /\s/.test(c)) break;
      i += 1;
    }
    const lhs = str.slice(0, i).trim();
    const afterLhs = str.slice(i).trimStart();
    if (afterLhs.startsWith('==')) {
      const { token: rhs, tail } = this._consumeNextToken(afterLhs.slice(2).trimStart());
      return { lhs, op: '==', rhs, tail };
    }
    const { token: opTok, tail: afterOp } = this._consumeNextToken(afterLhs);
    const opUpper = opTok.toUpperCase();
    if (['EQU', 'NEQ', 'LSS', 'LEQ', 'GTR', 'GEQ'].includes(opUpper)) {
      const { token: rhs, tail } = this._consumeNextToken(afterOp);
      return { lhs, op: opUpper, rhs, tail };
    }
    return null;
  }

  // ---- FOR [/L | /D | /F ["opts"]] %%v IN (...) DO <cmd> ----

  _executeFor(rawFor) {
    let rest = rawFor.slice(3).trimStart();
    let mode = 'list'; // 'list' | 'L' | 'D' | 'F'
    let fOptions = '';

    if (/^\/l\b/i.test(rest)) {
      mode = 'L';
      rest = rest.slice(2).trimStart();
    } else if (/^\/d\b/i.test(rest)) {
      mode = 'D';
      rest = rest.slice(2).trimStart();
    } else if (/^\/f\b/i.test(rest)) {
      mode = 'F';
      rest = rest.slice(2).trimStart();
      if (rest.startsWith('"')) {
        const endQ = rest.indexOf('"', 1);
        if (endQ !== -1) {
          fOptions = rest.slice(1, endQ);
          rest = rest.slice(endQ + 1).trimStart();
        }
      }
    }

    const varMatch = /^%%?([A-Za-z])\s+IN\s*\(/i.exec(rest);
    if (!varMatch) {
      this._writeStderr(`Invalid FOR syntax: ${rawFor}\n`);
      this.errorLevel = 1;
      return;
    }
    const varName = varMatch[1];
    const parenPos = rest.indexOf('(');
    const inBlk = extractParenBlock(rest, parenPos);
    if (!inBlk) {
      this._writeStderr(`Missing closing parenthesis in FOR: ${rawFor}\n`);
      this.errorLevel = 1;
      return;
    }
    const afterIn = rest.slice(inBlk.afterIdx).trimStart();
    const doMatch = /^do\b/i.exec(afterIn);
    if (!doMatch) {
      this._writeStderr(`Missing DO in FOR: ${rawFor}\n`);
      this.errorLevel = 1;
      return;
    }
    const bodyTemplate = afterIn.slice(doMatch[0].length).trimStart();
    const setText = this._expandDelayed(inBlk.inner).trim();

    if (mode === 'L') {
      const nums = setText.split(/[\s,]+/).filter(Boolean).map((n) => parseInt(n, 10) | 0);
      const start = nums[0] ?? 0;
      const step = nums[1] ?? 1;
      const end = nums[2] ?? 0;
      if (step === 0) return;
      this._frames.push({ kind: 'forL', varName, cur: start, step, end, bodyTemplate });
      return;
    }

    if (mode === 'D') {
      const patterns = tokenizeArgs(setText);
      this._flushPendingAppend();
      if (patterns.length === 0) {
        return;
      }
      if (patterns.length > 1) {
        this._frames.push({
          kind: 'forD',
          varName,
          patterns,
          patIndex: 0,
          items: [],
          forCells: 0,
          forBytes: 0,
          bodyTemplate,
        });
        return;
      }
      const items = [];
      let frameCells = 0;
      let frameBytes = 0;
      this._expandForDPattern(patterns[0], false, (item) => {
        const itemCells = 1;
        const itemBytes = 16 + utf8ByteLength(item);
        if (
          this._activeForBudget.cells + frameCells + itemCells > MAX_ACTIVE_FOR_F_CELLS ||
          this._activeForBudget.bytes + frameBytes + itemBytes > MAX_ACTIVE_FOR_F_BYTES
        ) {
          throw new BatchLimitError(
            `Batch active FOR budget exceeded (cells=${this._activeForBudget.cells + frameCells + itemCells}/${MAX_ACTIVE_FOR_F_CELLS}, bytes=${this._activeForBudget.bytes + frameBytes + itemBytes}/${MAX_ACTIVE_FOR_F_BYTES})`,
            { unwindToRoot: true }
          );
        }
        frameCells += itemCells;
        frameBytes += itemBytes;
        items.push(item);
      });
      this._pushForFrame({ kind: 'for', varName, items, index: 0, bodyTemplate, tokenVars: null }, frameCells, frameBytes);
      return;
    }

    if (mode === 'F') {
      let skipLines = 0;
      let eolChar = ';';
      let delims = ' \t';
      let tokensSpec = '1';

      // Parse FOR /F options string (skip=, eol=, delims=, tokens=)
      const skipM = /\bskip=(\d+)/i.exec(fOptions);
      if (skipM) skipLines = parseInt(skipM[1], 10);
      const eolM = /\beol=(.)/i.exec(fOptions);
      if (eolM) eolChar = eolM[1];
      const tokM = /\btokens=([^\s]+)/i.exec(fOptions);
      if (tokM) tokensSpec = tokM[1];
      const delM = /\bdelims=(.+?)(?:\s+(?:tokens|skip|eol|usebackq)=|$)/i.exec(fOptions);
      if (delM) delims = delM[1];

      // Determine source text: "literal string" vs 'command' vs file path(s)
      let sourceText = '';
      if (setText.startsWith('"') && setText.endsWith('"')) {
        sourceText = setText.slice(1, -1);
      } else if (setText.startsWith("'") && setText.endsWith("'")) {
        this._flushPendingAppend();
        const cmdText = setText.slice(1, -1);
        const res = this._executeSingleCommand(cmdText, {
          stdinText: null,
          captureStdout: true,
          allowSuspend: false,
        });
        if (res.limitExceeded) {
          return;
        }
        sourceText = res.capturedStdout ?? '';
      } else {
        this._flushPendingAppend();
        const files = tokenizeArgs(setText);
        const chunks = [];
        let totalBytes = 0;
        for (const f of files) {
          try {
            const { canonicalPath, vfsCtx } = this._resolveVfsPath(unquote(f), 'read');
            const st = this.services.vfs.stat(canonicalPath, vfsCtx);
            const fileSize = typeof st?.size === 'number' && Number.isFinite(st.size) ? st.size : 0;
            const sepBytes = chunks.length > 0 ? 1 : 0;
            if (totalBytes + sepBytes + fileSize > MAX_BATCH_IO_BUFFER_BYTES) {
              throw new BatchLimitError(
                `Batch I/O buffer limit exceeded in FOR /F (${totalBytes + sepBytes + fileSize} > ${MAX_BATCH_IO_BUFFER_BYTES} bytes)`
              );
            }
            this._checkVfsReadQuota(fileSize);
            const text = String(this.services.vfs.readFile(canonicalPath, { ...vfsCtx, encoding: 'utf8' }));
            this._recordVfsReadQuota(fileSize > 0 ? fileSize : utf8ByteLength(text));
            const actualSize = Math.max(fileSize, text.length);
            if (totalBytes + sepBytes + actualSize > MAX_BATCH_IO_BUFFER_BYTES) {
              throw new BatchLimitError(
                `Batch I/O buffer limit exceeded in FOR /F (${totalBytes + sepBytes + actualSize} > ${MAX_BATCH_IO_BUFFER_BYTES} bytes)`
              );
            }
            totalBytes += sepBytes + actualSize;
            chunks.push(text);
          } catch (err) {
            if (err?.isBatchLimitError) throw err;
            void err;
          }
        }
        sourceText = chunks.join('\n');
      }

      const parsedTokens = this._parseForTokens(tokensSpec);
      if (parsedTokens.error) {
        this._writeStderr(`${parsedTokens.error}\n`);
        this.errorLevel = 1;
        return;
      }
      const tokenSpecs = parsedTokens.specs;
      const tokenVars = [];
      const baseCode = varName.charCodeAt(0);
      for (let t = 0; t < tokenSpecs.length; t++) {
        tokenVars.push(String.fromCharCode(baseCode + t));
      }

      const items = [];
      let frameCells = 0;
      let frameBytes = 0;
      const delimSet = new Set(delims.split(''));
      const srcLen = sourceText.length;
      let pos = 0;
      let lineIdx = 0;
      while (pos <= srcLen) {
        const nl = sourceText.indexOf('\n', pos);
        const end = nl === -1 ? srcLen : nl;
        let line = sourceText.slice(pos, end);
        if (line.endsWith('\r')) line = line.slice(0, -1);
        if (lineIdx >= skipLines && line && !(eolChar && line.startsWith(eolChar))) {
          const fields = this._splitForFields(line, delimSet, tokenSpecs);
          if (!fields.every((f) => f === '')) {
            if (items.length >= MAX_FOR_F_LINES) {
              throw new BatchLimitError(
                `Batch FOR /F line limit exceeded (> ${MAX_FOR_F_LINES} lines)`
              );
            }
            const rowCells = Math.max(1, fields.length);
            let rowBytes = 32;
            for (let fi = 0; fi < fields.length; fi++) {
              rowBytes += utf8ByteLength(fields[fi]) + 8;
            }
            if (
              this._activeForBudget.cells + frameCells + rowCells > MAX_ACTIVE_FOR_F_CELLS ||
              this._activeForBudget.bytes + frameBytes + rowBytes > MAX_ACTIVE_FOR_F_BYTES
            ) {
              throw new BatchLimitError(
                `Batch active FOR /F budget exceeded (cells=${this._activeForBudget.cells + frameCells + rowCells}/${MAX_ACTIVE_FOR_F_CELLS}, bytes=${this._activeForBudget.bytes + frameBytes + rowBytes}/${MAX_ACTIVE_FOR_F_BYTES})`,
                { unwindToRoot: true }
              );
            }
            frameCells += rowCells;
            frameBytes += rowBytes;
            items.push(fields);
          }
        }
        lineIdx += 1;
        if (nl === -1) break;
        pos = nl + 1;
      }

      this._pushForFrame({ kind: 'for', varName, items, index: 0, bodyTemplate, tokenVars }, frameCells, frameBytes);
      return;
    }

    // Standard list FOR %%v IN (a b c)
    const rawItems = tokenizeArgs(setText);
    const items = [];
    let frameCells = 0;
    let frameBytes = 0;
    for (let idx = 0; idx < rawItems.length; idx++) {
      const item = rawItems[idx];
      const itemCells = 1;
      const itemBytes = 16 + utf8ByteLength(item);
      if (
        this._activeForBudget.cells + frameCells + itemCells > MAX_ACTIVE_FOR_F_CELLS ||
        this._activeForBudget.bytes + frameBytes + itemBytes > MAX_ACTIVE_FOR_F_BYTES
      ) {
        throw new BatchLimitError(
          `Batch active FOR budget exceeded (cells=${this._activeForBudget.cells + frameCells + itemCells}/${MAX_ACTIVE_FOR_F_CELLS}, bytes=${this._activeForBudget.bytes + frameBytes + itemBytes}/${MAX_ACTIVE_FOR_F_BYTES})`,
          { unwindToRoot: true }
        );
      }
      frameCells += itemCells;
      frameBytes += itemBytes;
      items.push(item);
    }
    this._pushForFrame({ kind: 'for', varName, items, index: 0, bodyTemplate, tokenVars: null }, frameCells, frameBytes);
  }

  _parseForTokens(spec) {
    const out = [];
    const parts = String(spec || '').split(',');
    if (parts.length > MAX_FOR_TOKENS) {
      return { error: `FOR /F tokens= specification exceeds maximum (${MAX_FOR_TOKENS}).` };
    }
    const parseTokenIndex = (raw) => {
      if (!/^\d+$/.test(raw)) return null;
      const n = Number(raw);
      if (!Number.isSafeInteger(n) || n < 1 || n > MAX_FOR_TOKENS) return null;
      return n;
    };
    const pushSpec = (entry) => {
      if (out.length >= MAX_FOR_TOKENS) return false;
      out.push(entry);
      return true;
    };

    for (const p of parts) {
      const clean = p.trim();
      if (!clean) continue;
      if (clean === '*') {
        if (!pushSpec({ rest: true })) {
          return { error: `FOR /F tokens= specification exceeds maximum (${MAX_FOR_TOKENS}).` };
        }
      } else if (clean.endsWith('*')) {
        const base = clean.slice(0, -1);
        if (base.includes('-')) {
          const segs = base.split('-');
          if (segs.length !== 2) {
            return { error: `Invalid FOR /F tokens= range: ${clean}` };
          }
          const a = parseTokenIndex(segs[0]);
          const b = parseTokenIndex(segs[1]);
          if (a === null || b === null || b < a) {
            return { error: `Invalid FOR /F tokens= range (allowed 1..${MAX_FOR_TOKENS}): ${clean}` };
          }
          for (let i = a; i <= b; i++) {
            if (!pushSpec({ index: i })) {
              return { error: `FOR /F tokens= specification exceeds maximum (${MAX_FOR_TOKENS}).` };
            }
          }
        } else if (base) {
          const n = parseTokenIndex(base);
          if (n === null) {
            return { error: `Invalid FOR /F tokens= index (allowed 1..${MAX_FOR_TOKENS}): ${clean}` };
          }
          if (!pushSpec({ index: n })) {
            return { error: `FOR /F tokens= specification exceeds maximum (${MAX_FOR_TOKENS}).` };
          }
        }
        if (!pushSpec({ rest: true })) {
          return { error: `FOR /F tokens= specification exceeds maximum (${MAX_FOR_TOKENS}).` };
        }
      } else if (clean.includes('-')) {
        const segs = clean.split('-');
        if (segs.length !== 2) {
          return { error: `Invalid FOR /F tokens= range: ${clean}` };
        }
        const a = parseTokenIndex(segs[0]);
        const b = parseTokenIndex(segs[1]);
        if (a === null || b === null || b < a) {
          return { error: `Invalid FOR /F tokens= range (allowed 1..${MAX_FOR_TOKENS}): ${clean}` };
        }
        for (let i = a; i <= b; i++) {
          if (!pushSpec({ index: i })) {
            return { error: `FOR /F tokens= specification exceeds maximum (${MAX_FOR_TOKENS}).` };
          }
        }
      } else {
        const n = parseTokenIndex(clean);
        if (n === null) {
          return { error: `Invalid FOR /F tokens= index (allowed 1..${MAX_FOR_TOKENS}): ${clean}` };
        }
        if (!pushSpec({ index: n })) {
          return { error: `FOR /F tokens= specification exceeds maximum (${MAX_FOR_TOKENS}).` };
        }
      }
    }
    return { specs: out.length > 0 ? out : [{ index: 1 }] };
  }

  _splitForFields(line, delimSet, tokenSpecs) {
    if (delimSet.size === 0) {
      return [line];
    }
    let maxNeeded = 0;
    for (let k = 0; k < tokenSpecs.length; k++) {
      const ts = tokenSpecs[k];
      if (!ts.rest && ts.index > maxNeeded) {
        maxNeeded = ts.index;
      }
    }
    const tokens = [];
    const tokenEnds = [];
    let i = 0;
    while (i < line.length && tokens.length < maxNeeded) {
      while (i < line.length && delimSet.has(line[i])) i += 1;
      if (i >= line.length) break;
      const start = i;
      while (i < line.length && !delimSet.has(line[i])) i += 1;
      tokens.push(line.slice(start, i));
      tokenEnds.push(i);
    }

    const out = [];
    let highestUsed = 0;
    for (const ts of tokenSpecs) {
      if (ts.rest) {
        if (highestUsed === 0) {
          out.push(line.trimStart());
        } else if (highestUsed <= tokenEnds.length) {
          let restStart = tokenEnds[highestUsed - 1];
          while (restStart < line.length && delimSet.has(line[restStart])) restStart += 1;
          out.push(line.slice(restStart));
        } else {
          out.push('');
        }
      } else {
        const idx = ts.index;
        highestUsed = Math.max(highestUsed, idx);
        out.push(tokens[idx - 1] ?? '');
      }
    }
    return out;
  }

  deliverEvent(event) {
    void event;
  }

  getDebugState() {
    const top = this._frames[this._frames.length - 1] ?? null;
    return {
      arch: 'batch',
      scriptKind: this.scriptKind,
      pc: top && top.kind === 'script' ? `line:${top.ip}` : `frame:${this._frames.length}`,
      sp: `depth:${this._frames.length}`,
      registers: {
        ERRORLEVEL: this.errorLevel,
        ECHO: this.echoOn ? 'ON' : 'OFF',
        DELAYED_EXPANSION: this.delayedExpansion ? 'ON' : 'OFF',
      },
      instructionsExecuted: this.instructionsExecuted,
      lastSyscall: this.lastCommand,
      stackTop: this._frames.map((f) => `${f.kind}@${f.ip ?? f.index ?? f.patIndex ?? 0}`),
    };
  }

  dispose() {
    this._disposed = true;
    this._pendingAppend = null;
    this._invalidateReaddirCache();
    if (this._suspendedSub?.sub) {
      if (typeof this._suspendedSub.sub._clearFrames === 'function') {
        this._suspendedSub.sub._clearFrames();
      }
      if (typeof this._suspendedSub.sub._clearLocalStack === 'function') {
        this._suspendedSub.sub._clearLocalStack();
      }
    }
    this._suspendedSub = null;
    this._clearFrames();
    this._clearLocalStack();
  }
}

export function createBatchExecutionContext(opts = {}) {
  return new BatchExecutionContext(opts);
}
