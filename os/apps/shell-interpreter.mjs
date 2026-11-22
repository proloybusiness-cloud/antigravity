/**
 * OmniOS Multi-Syntax Shell Interpreter (`F-066`)
 * Zero external dependencies, zero host filesystem access — all filesystem I/O goes strictly through `os.vfs`.
 * Supports:
 *  - Tokenizer with single/double quotes, backslash escapes, env var expansion ($VAR, ${VAR}, %VAR%, $?)
 *  - Command chaining (; && ||), pipelines (|), stdout overwrite (>) and append (>>) redirection
 *  - Bounded safety caps (command length, pipeline depth, command count, output byte cap)
 *  - POSIX commands: ls, cat, echo, pwd, cd, mkdir, rm, rmdir, cp, mv, touch, stat, ln, ps, kill,
 *    dmesg, uname, whoami, env, export, set, unset, help, clear, grep, head, tail, wc, readlink,
 *    chmod, chown, basename, dirname, true, false
 *  - Windows commands: dir, type, md, rd, del, copy, move, tasklist, taskkill, reg
 *  - macOS commands: defaults, open
 *  - Android commands: am, pm, prefs
 *  - OmniOS native commands: ospm, intent, clip, notify, search
 */

import { mapNativePermission } from '../security/permissions.mjs';

export const DEFAULT_SHELL_LIMITS = Object.freeze({
  maxCommandLength: 8192,
  maxPipelineDepth: 16,
  maxCommands: 32,
  maxOutputBytes: 256 * 1024,
  maxHistoryEntries: 500,
  maxRecursionDepth: 32,
});

const EXT_MIME_MAP = Object.freeze({
  '.txt': 'text/plain',
  '.md': 'text/markdown',
  '.markdown': 'text/markdown',
  '.log': 'text/plain',
  '.json': 'application/json',
  '.html': 'text/html',
  '.htm': 'text/html',
  '.xml': 'application/xml',
  '.csv': 'text/csv',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.pdf': 'application/pdf',
  '.apk': 'application/vnd.android.package-archive',
  '.exe': 'application/vnd.microsoft.portable-executable',
  '.ipa': 'application/octet-stream',
  '.uapp': 'application/zip',
  '.wasm': 'application/wasm',
});

const WINDOWS_DRIVE_RE = /^[A-Za-z]:[\\/]|^\\\\\?\\/;
const WIN_DIR_SWITCH_RE = /^\/[A-Za-z](?:[:\-][A-Za-z0-9]+)?$/;

function parseStrictPid(raw) {
  if (typeof raw === 'number') {
    return Number.isSafeInteger(raw) && raw >= 0 ? raw : null;
  }
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (!/^\d+$/.test(trimmed)) return null;
  const n = Number(trimmed);
  return Number.isSafeInteger(n) && n >= 0 ? n : null;
}

function jsonStringifySafe(value) {
  return JSON.stringify(value, (_key, val) => {
    if (typeof val === 'bigint') return val.toString(10);
    if (val instanceof Uint8Array) {
      return Buffer.from(val.buffer, val.byteOffset, val.byteLength).toString('hex');
    }
    if (ArrayBuffer.isView(val)) {
      return Buffer.from(val.buffer, val.byteOffset, val.byteLength).toString('hex');
    }
    return val;
  });
}

function formatRegValueData(data, { quoteStrings = false } = {}) {
  if (typeof data === 'bigint') {
    return data.toString(10);
  }
  if (data instanceof Uint8Array) {
    return Buffer.from(data.buffer, data.byteOffset, data.byteLength).toString('hex');
  }
  if (ArrayBuffer.isView(data)) {
    return Buffer.from(data.buffer, data.byteOffset, data.byteLength).toString('hex');
  }
  if (typeof data === 'string') {
    return quoteStrings ? JSON.stringify(data) : data;
  }
  if (typeof data === 'number' || typeof data === 'boolean') {
    return String(data);
  }
  return jsonStringifySafe(data);
}

function formatError(err) {
  if (!err) return 'Unknown error';
  const code = typeof err.code === 'string' && err.code.length > 0 ? `[${err.code}] ` : '';
  const msg = typeof err.message === 'string' && err.message.length > 0 ? err.message : String(err);
  return `${code}${msg}`;
}

function capOutput(str, maxBytes) {
  const s = typeof str === 'string' ? str : String(str ?? '');
  if (Buffer.byteLength(s, 'utf8') <= maxBytes) return s;
  const buf = Buffer.from(s, 'utf8').subarray(0, Math.max(0, maxBytes - 24));
  return `${buf.toString('utf8')}\n[output truncated]\n`;
}

function inferPlatformForPath(rawPath, fallbackPlatform = 'posix', isWindowsCmd = false) {
  if (typeof rawPath !== 'string' || rawPath.length === 0) return fallbackPlatform;
  if (WINDOWS_DRIVE_RE.test(rawPath) || (isWindowsCmd && rawPath.includes('\\'))) {
    return 'windows';
  }
  if (/^\/(?:sdcard|storage\/emulated\/0|data\/data)(?:\/|$)/i.test(rawPath)) {
    return 'android';
  }
  if (/^\/var\/mobile(?:\/|$)/i.test(rawPath)) {
    return 'ios';
  }
  if (/^\/(?:Users|Applications)(?:\/|$)/.test(rawPath)) {
    return 'macos';
  }
  return fallbackPlatform;
}

function formatModeOctal(mode, type) {
  const perms = Number(mode ?? 0o644) & 0o777;
  const prefix = type === 'dir' ? 'd' : type === 'symlink' ? 'l' : '-';
  const tri = (bits) =>
    `${bits & 4 ? 'r' : '-'}${bits & 2 ? 'w' : '-'}${bits & 1 ? 'x' : '-'}`;
  return `${prefix}${tri((perms >> 6) & 7)}${tri((perms >> 3) & 7)}${tri(perms & 7)}`;
}

function parseScalarValue(raw, explicitType = null) {
  const t = explicitType ? String(explicitType).toLowerCase() : null;
  if (t === 'string' || t === '-string' || t === 'reg_sz' || t === 'reg_expand_sz') {
    return String(raw);
  }
  if (t === 'bool' || t === '-bool' || t === 'boolean') {
    const low = String(raw).toLowerCase();
    return low === 'true' || low === '1' || low === 'yes' || low === 'on';
  }
  if (t === 'int' || t === '-int' || t === 'integer' || t === 'reg_dword') {
    const parsed = Number.parseInt(String(raw), 0);
    if (!Number.isFinite(parsed)) throw new Error(`Invalid integer value: ${raw}`);
    return parsed;
  }
  if (t === 'reg_qword') {
    const trimmed = String(raw).trim();
    if (!/^(?:0[xX][0-9a-fA-F]+|\d+)$/.test(trimmed)) {
      throw new Error(`Invalid REG_QWORD value: ${raw}`);
    }
    const big = BigInt(trimmed);
    if (big < 0n || big > 0xffffffffffffffffn) {
      throw new Error(`REG_QWORD out of unsigned 64-bit range: ${raw}`);
    }
    return big;
  }
  if (t === 'reg_binary') {
    const cleaned = String(raw).replace(/\s+/g, '').replace(/^0[xX]/, '');
    if (cleaned.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(cleaned)) {
      throw new Error(`Invalid REG_BINARY hex value: ${raw}`);
    }
    if (cleaned.length === 0) return new Uint8Array(0);
    const buf = Buffer.from(cleaned, 'hex');
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  if (t === 'float' || t === '-float' || t === 'double' || t === 'number') {
    const parsed = Number(raw);
    if (!Number.isFinite(parsed)) throw new Error(`Invalid numeric value: ${raw}`);
    return parsed;
  }
  if (t === 'json' || t === '-json') {
    return JSON.parse(String(raw));
  }
  if (t === 'reg_multi_sz') {
    return String(raw).split(',');
  }
  const s = String(raw);
  if (s === 'true') return true;
  if (s === 'false') return false;
  if (/^-?\d+$/.test(s)) {
    const n = Number(s);
    if (Number.isSafeInteger(n)) return n;
  }
  if (/^-?\d+\.\d+$/.test(s)) {
    const n = Number(s);
    if (Number.isFinite(n)) return n;
  }
  return s;
}

function parseRegistryPath(fullPath) {
  if (typeof fullPath !== 'string' || fullPath.trim().length === 0) {
    throw new Error('Registry path is required (e.g. HKCU\\Software\\OmniOS)');
  }
  const normalized = fullPath.trim().replace(/\//g, '\\');
  const idx = normalized.indexOf('\\');
  if (idx === -1) {
    return { hive: normalized.toUpperCase(), keyPath: '' };
  }
  const hive = normalized.slice(0, idx).toUpperCase();
  const keyPath = normalized.slice(idx + 1).replace(/^\\+|\\+$/g, '');
  return { hive, keyPath };
}

function splitBaseDir(canonicalPath) {
  if (canonicalPath === '/') return { dir: '/', base: '/' };
  const trimmed = canonicalPath.endsWith('/') ? canonicalPath.slice(0, -1) : canonicalPath;
  const idx = trimmed.lastIndexOf('/');
  if (idx <= 0) return { dir: '/', base: trimmed.slice(1) };
  return { dir: trimmed.slice(0, idx), base: trimmed.slice(idx + 1) };
}

function extnameOf(p) {
  const { base } = splitBaseDir(p);
  const dot = base.lastIndexOf('.');
  if (dot <= 0) return '';
  return base.slice(dot).toLowerCase();
}

function expandVariables(str, env, lastExitCode) {
  let out = '';
  let i = 0;
  while (i < str.length) {
    const ch = str[i];
    if (ch === '$') {
      if (str[i + 1] === '?') {
        out += String(lastExitCode);
        i += 2;
        continue;
      }
      if (str[i + 1] === '{') {
        const close = str.indexOf('}', i + 2);
        if (close !== -1) {
          const name = str.slice(i + 2, close);
          if (name === '?') {
            out += String(lastExitCode);
          } else {
            out += Object.prototype.hasOwnProperty.call(env, name) ? String(env[name]) : '';
          }
          i = close + 1;
          continue;
        }
      }
      const match = /^\$([A-Za-z_][A-Za-z0-9_]*)/.exec(str.slice(i));
      if (match) {
        const name = match[1];
        out += Object.prototype.hasOwnProperty.call(env, name) ? String(env[name]) : '';
        i += match[0].length;
        continue;
      }
      out += '$';
      i += 1;
      continue;
    }
    if (ch === '%') {
      const match = /^%([A-Za-z_][A-Za-z0-9_]*)%/.exec(str.slice(i));
      if (match) {
        const name = match[1];
        if (Object.prototype.hasOwnProperty.call(env, name)) {
          out += String(env[name]);
        } else {
          const upper = name.toUpperCase();
          out += Object.prototype.hasOwnProperty.call(env, upper) ? String(env[upper]) : '';
        }
        i += match[0].length;
        continue;
      }
      out += '%';
      i += 1;
      continue;
    }
    out += ch;
    i += 1;
  }
  return out;
}

function expandWordParts(parts, env, lastExitCode) {
  let out = '';
  for (const part of parts) {
    out += part.kind === 'expand' ? expandVariables(part.text, env, lastExitCode) : part.text;
  }
  return out;
}

/**
 * Tokenize a shell command line into word & operator tokens.
 * Supports single quotes, double quotes, backslash escapes, env var expansion,
 * and operators: `;`, `&&`, `||`, `|`, `>>`, `>`.
 */
export function tokenizeCommand(input, env = null, lastExitCode = 0) {
  const tokens = [];
  let i = 0;
  const len = input.length;

  while (i < len) {
    const ch = input[i];
    if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      // Comment until end of line
      while (i < len && input[i] !== '\n') i += 1;
      continue;
    }

    // Two-character operators
    const two = input.slice(i, i + 2);
    if (two === '&&' || two === '||' || two === '>>') {
      tokens.push({ type: 'op', value: two });
      i += 2;
      continue;
    }

    // Single-character operators
    if (ch === ';' || ch === '|' || ch === '>') {
      tokens.push({ type: 'op', value: ch });
      i += 1;
      continue;
    }

    // Word token (may contain mixed unquoted, single-quoted, double-quoted segments)
    const parts = [];
    while (i < len) {
      const c = input[i];
      if (c === ' ' || c === '\t' || c === '\r' || c === '\n' || c === ';' || c === '|' || c === '>' || c === '&') {
        if (c === '&' && input[i + 1] !== '&') {
          parts.push({ kind: 'literal', text: '&' });
          i += 1;
          continue;
        }
        break;
      }
      if (c === "'") {
        i += 1;
        let closed = false;
        let lit = '';
        while (i < len) {
          if (input[i] === "'") {
            closed = true;
            i += 1;
            break;
          }
          lit += input[i];
          i += 1;
        }
        if (!closed) {
          throw new SyntaxError('Unterminated single-quoted string');
        }
        parts.push({ kind: 'literal', text: lit });
        continue;
      }
      if (c === '"') {
        i += 1;
        let closed = false;
        let segment = '';
        while (i < len) {
          if (input[i] === '"') {
            closed = true;
            i += 1;
            break;
          }
          if (input[i] === '\\') {
            if (i + 1 < len) {
              const next = input[i + 1];
              // POSIX sh & Windows CMD double-quote rule: only escape ", \, $, and `
              // so Windows paths like "C:\Users\user\Documents\notes.txt" stay intact.
              if (next === '"' || next === '\\' || next === '$' || next === '`') {
                if (next === '$') {
                  if (segment.length > 0) {
                    parts.push({ kind: 'expand', text: segment });
                    segment = '';
                  }
                  parts.push({ kind: 'literal', text: '$' });
                } else {
                  segment += next;
                }
                i += 2;
                continue;
              }
              segment += `\\${next}`;
              i += 2;
              continue;
            }
            // Trailing backslash inside unclosed double quote -> advance so loop terminates cleanly.
            segment += '\\';
            i += 1;
            continue;
          }
          segment += input[i];
          i += 1;
        }
        if (!closed) {
          throw new SyntaxError('Unterminated double-quoted string');
        }
        if (segment.length > 0) {
          parts.push({ kind: 'expand', text: segment });
        }
        continue;
      }
      if (c === '\\') {
        if (i + 1 >= len) {
          throw new SyntaxError('Trailing backslash at end of command');
        }
        const next = input[i + 1];
        // Preserve Windows drive/path backslashes like C:\Users\user when followed by non-shell-meta chars
        if (next === ' ' || next === '"' || next === "'" || next === '\\' || next === '$' || next === ';' || next === '|' || next === '>' || next === '&') {
          parts.push({ kind: 'literal', text: next });
          i += 2;
          continue;
        }
        parts.push({ kind: 'literal', text: c });
        i += 1;
        continue;
      }
      // Unquoted chunk up to next special char
      let seg = '';
      while (i < len) {
        const uc = input[i];
        if (
          uc === ' ' || uc === '\t' || uc === '\r' || uc === '\n' ||
          uc === ';' || uc === '|' || uc === '>' || uc === "'" || uc === '"' || uc === '\\' ||
          (uc === '&' && input[i + 1] === '&')
        ) {
          break;
        }
        seg += uc;
        i += 1;
      }
      if (seg.length > 0) {
        parts.push({ kind: 'expand', text: seg });
      }
    }
    const value = env !== null ? expandWordParts(parts, env, lastExitCode) : parts.map((p) => p.text).join('');
    tokens.push({ type: 'word', value, parts });
  }

  return tokens;
}

/**
 * Parse token stream into chained pipelines with safety limits.
 */
function parseChains(tokens, { maxPipelineDepth, maxCommands }) {
  const chains = [];
  let currentOp = null;
  let currentPipeline = [];
  let currentCmd = { argvParts: [], redirectOut: null };
  let totalCommands = 0;

  const finalizeCmd = () => {
    if (currentCmd.argvParts.length === 0) {
      if (currentCmd.redirectOut) {
        throw new SyntaxError('Syntax error: redirection without command');
      }
      return false;
    }
    totalCommands += 1;
    if (totalCommands > maxCommands) {
      throw new RangeError(`Command chain exceeds maximum of ${maxCommands} commands`);
    }
    currentPipeline.push(currentCmd);
    if (currentPipeline.length > maxPipelineDepth) {
      throw new RangeError(`Pipeline exceeds maximum depth of ${maxPipelineDepth}`);
    }
    currentCmd = { argvParts: [], redirectOut: null };
    return true;
  };

  for (let i = 0; i < tokens.length; i += 1) {
    const tok = tokens[i];
    if (tok.type === 'word') {
      currentCmd.argvParts.push(tok.parts ?? [{ kind: 'literal', text: tok.value }]);
      continue;
    }
    if (tok.value === '>' || tok.value === '>>') {
      const target = tokens[i + 1];
      if (!target || target.type !== 'word') {
        throw new SyntaxError(`Syntax error: expected file path after '${tok.value}'`);
      }
      currentCmd.redirectOut = {
        pathParts: target.parts ?? [{ kind: 'literal', text: target.value }],
        append: tok.value === '>>',
      };
      i += 1;
      continue;
    }
    if (tok.value === '|') {
      if (!finalizeCmd()) {
        throw new SyntaxError("Syntax error: unexpected '|'");
      }
      continue;
    }
    if (tok.value === ';' || tok.value === '&&' || tok.value === '||') {
      const hadCmd = finalizeCmd();
      if (hadCmd && currentPipeline.length > 0) {
        chains.push({ operator: currentOp, pipeline: currentPipeline });
        currentPipeline = [];
        currentOp = tok.value;
      } else if (
        currentPipeline.length > 0 ||
        tok.value !== ';' ||
        currentOp === '&&' ||
        currentOp === '||'
      ) {
        throw new SyntaxError(`Syntax error: unexpected '${tok.value}'`);
      }
    }
  }

  if (finalizeCmd() && currentPipeline.length > 0) {
    chains.push({ operator: currentOp, pipeline: currentPipeline });
  } else if (currentPipeline.length > 0) {
    throw new SyntaxError("Syntax error: trailing '|'");
  } else if (currentOp === '&&' || currentOp === '||') {
    throw new SyntaxError(`Syntax error: trailing '${currentOp}'`);
  }

  return chains;
}

const HELP_TEXT = [
  'OmniOS Multi-Syntax Shell — Available Commands:',
  '  POSIX:   ls [-l|-a], cat, echo [-n], pwd, cd, mkdir [-p], rm [-r|-f], rmdir, cp [-r], mv,',
  '           touch, stat, ln -s, readlink, chmod, chown, ps [--tree|-a], kill [-9|-15|-s SIG],',
  '           dmesg [-n N], uname [-a], whoami, env, export, set, unset, grep [-i|-v|-n|-c],',
  '           head [-n N], tail [-n N], wc [-l|-w|-c], basename, dirname, help, clear',
  '  Windows: dir, type, md, rd [/s], del, copy, move, tasklist, taskkill [/PID n] [/F],',
  '           reg <query|get|add|set|delete|list>',
  '  macOS:   defaults <domains|read|write|delete|export>, open [-a app] <target>',
  '  Android: am <start|broadcast>, pm <list packages|install|uninstall|grant|revoke>,',
  '           prefs <get|set|edit|delete>',
  '  OmniOS:  ospm <list|catalog|inspect|install|launch|stop|uninstall>,',
  '           intent <resolve|dispatch>, clip <get|set|history|clear>,',
  '           notify <send|list|dismiss>, search <query>',
  '  Syntax:  quotes (\'...\', "..."), $VAR/${VAR}/%VAR%, chains (; && ||), pipes (|), > / >>',
].join('\n');

export class ShellInterpreter {
  constructor(os, options = {}) {
    if (!os || typeof os !== 'object') {
      throw new TypeError('ShellInterpreter requires an OmniOS instance');
    }
    this.os = os;
    this.cwd = typeof options.cwd === 'string' && options.cwd.length > 0 ? options.cwd : '/home/user';
    this.env = {
      HOME: '/home/user',
      USER: 'user',
      PATH: '/usr/bin:/bin',
      SHELL: '/bin/omnish',
      OSTYPE: 'OmniOS',
      PWD: this.cwd,
      ...(options.env && typeof options.env === 'object' ? options.env : {}),
    };
    this.lastExitCode = 0;
    this.history = [];
    this.limits = {
      ...DEFAULT_SHELL_LIMITS,
      ...(options.limits && typeof options.limits === 'object' ? options.limits : {}),
    };
  }

  getHistory(limit = 100) {
    const n = Number.isInteger(limit) && limit >= 0 ? limit : 100;
    if (n === 0) return [];
    return this.history.slice(-n);
  }

  _recordHistory(line) {
    const trimmed = line.trim();
    if (!trimmed) return;
    this.history.push(trimmed);
    if (this.history.length > this.limits.maxHistoryEntries) {
      this.history.splice(0, this.history.length - this.limits.maxHistoryEntries);
    }
  }

  _requireVfs() {
    if (!this.os.vfs || !this.os.vfs.isReady) {
      throw new Error('VFS is not mounted or kernel is not booted');
    }
    return this.os.vfs;
  }

  _requireConfig() {
    if (!this.os.configStore || !this.os.configStore.isReady()) {
      throw new Error('UnifiedConfigStore is not ready');
    }
    return this.os.configStore;
  }

  _resolvePath(rawPath, state, isWindowsCmd = false) {
    let target = String(rawPath ?? '');
    if (target === '~') {
      target = state.env.HOME || '/home/user';
    } else if (target.startsWith('~/')) {
      target = `${state.env.HOME || '/home/user'}/${target.slice(2)}`;
    }
    const platform = inferPlatformForPath(target, state.platform, isWindowsCmd);
    if (this.os.pathTranslator) {
      const res = this.os.pathTranslator.toCanonical(target, {
        platform,
        cwd: state.cwd,
      });
      return { canonicalPath: res.canonicalPath, platform };
    }
    const canonicalPath = target.startsWith('/') ? target : `${state.cwd.replace(/\/$/, '')}/${target}`;
    return { canonicalPath, platform };
  }

  _vfsCtx(state, platform = 'posix', extra = {}) {
    return {
      uid: state.uid,
      gid: state.gid,
      cwd: state.cwd,
      platform,
      ...extra,
    };
  }

  _rmRecursive(vfs, canonicalPath, ctx, depth = 0) {
    if (depth > this.limits.maxRecursionDepth) {
      throw new Error(`Maximum recursion depth (${this.limits.maxRecursionDepth}) exceeded`);
    }
    const st = vfs.lstat(canonicalPath, ctx);
    if (st.type !== 'dir') {
      vfs.unlink(canonicalPath, ctx);
      return;
    }
    const entries = vfs.readdir(canonicalPath, ctx);
    for (const entry of entries) {
      const childPath = canonicalPath === '/' ? `/${entry.name}` : `${canonicalPath}/${entry.name}`;
      if (entry.type === 'dir') {
        this._rmRecursive(vfs, childPath, ctx, depth + 1);
      } else {
        vfs.unlink(childPath, ctx);
      }
    }
    vfs.rmdir(canonicalPath, ctx);
  }

  _cpRecursive(vfs, srcPath, dstPath, ctx, recursive, depth = 0) {
    if (depth > this.limits.maxRecursionDepth) {
      throw new Error(`Maximum copy depth (${this.limits.maxRecursionDepth}) exceeded`);
    }
    const st = vfs.stat(srcPath, ctx);
    if (st.type === 'dir') {
      if (!recursive) {
        throw new Error(`cp: omitting directory '${srcPath}' (use -r)`);
      }
      try {
        vfs.mkdir(dstPath, { ...ctx, recursive: true, mode: st.mode & 0o777 });
      } catch (err) {
        if (err?.code !== 'EEXIST') throw err;
      }
      const entries = vfs.readdir(srcPath, ctx);
      for (const entry of entries) {
        const sChild = srcPath === '/' ? `/${entry.name}` : `${srcPath}/${entry.name}`;
        const dChild = dstPath === '/' ? `/${entry.name}` : `${dstPath}/${entry.name}`;
        this._cpRecursive(vfs, sChild, dChild, ctx, true, depth + 1);
      }
      return;
    }
    const bytes = vfs.readFile(srcPath, ctx);
    vfs.writeFile(dstPath, bytes, { ...ctx, mode: st.mode & 0o777 });
  }

  async exec(commandLine, opts = {}) {
    const maxCommandLength =
      Number.isInteger(opts.maxCommandLength) && opts.maxCommandLength > 0
        ? opts.maxCommandLength
        : this.limits.maxCommandLength;
    const maxPipelineDepth =
      Number.isInteger(opts.maxPipelineDepth) && opts.maxPipelineDepth > 0
        ? opts.maxPipelineDepth
        : this.limits.maxPipelineDepth;
    const maxCommands =
      Number.isInteger(opts.maxCommands) && opts.maxCommands > 0
        ? opts.maxCommands
        : this.limits.maxCommands;
    const maxOutputBytes =
      Number.isInteger(opts.maxOutputBytes) && opts.maxOutputBytes > 0
        ? opts.maxOutputBytes
        : this.limits.maxOutputBytes;

    const isolatedCwd = typeof opts.cwd === 'string' && opts.cwd.length > 0;
    const isolatedEnv = opts.env !== undefined && opts.env !== null && typeof opts.env === 'object';

    const state = {
      cwd: isolatedCwd ? opts.cwd : this.cwd,
      env: isolatedEnv ? { ...this.env, ...opts.env } : { ...this.env },
      platform: typeof opts.platform === 'string' ? opts.platform : 'posix',
      uid: Number.isInteger(opts.uid) ? opts.uid : 1000,
      gid: Number.isInteger(opts.gid) ? opts.gid : 1000,
      lastExitCode: this.lastExitCode,
      cleared: false,
      maxOutputBytes,
    };
    state.env.PWD = state.cwd;

    if (typeof commandLine !== 'string') {
      return {
        ok: false,
        exitCode: 2,
        stdout: '',
        stderr: 'Shell command must be a string\n',
        cwd: state.cwd,
        env: { ...state.env },
      };
    }

    if (commandLine.length > maxCommandLength) {
      return {
        ok: false,
        exitCode: 1,
        stdout: '',
        stderr: `Command exceeds maximum length of ${maxCommandLength} characters\n`,
        cwd: state.cwd,
        env: { ...state.env },
      };
    }

    const trimmed = commandLine.trim();
    if (trimmed.length === 0) {
      return {
        ok: true,
        exitCode: 0,
        stdout: '',
        stderr: '',
        cwd: state.cwd,
        env: { ...state.env },
      };
    }

    this._recordHistory(trimmed);

    let chains;
    try {
      const tokens = tokenizeCommand(commandLine, null, state.lastExitCode);
      chains = parseChains(tokens, { maxPipelineDepth, maxCommands });
    } catch (err) {
      return {
        ok: false,
        exitCode: 2,
        stdout: '',
        stderr: `${formatError(err)}\n`,
        cwd: state.cwd,
        env: { ...state.env },
      };
    }

    let totalStdout = '';
    let totalStderr = '';
    let lastCode = 0;

    for (const chain of chains) {
      if (chain.operator === '&&' && lastCode !== 0) {
        continue;
      }
      if (chain.operator === '||' && lastCode === 0) {
        continue;
      }

      let pipeInput = '';
      let stageResult = { exitCode: 0, stdout: '', stderr: '' };

      for (let s = 0; s < chain.pipeline.length; s += 1) {
        const cmd = chain.pipeline[s];
        const isLastStage = s === chain.pipeline.length - 1;
        const expandedArgv = cmd.argvParts.map((parts) => expandWordParts(parts, state.env, state.lastExitCode));
        stageResult = await this._runSingleCommand(expandedArgv, pipeInput, state);

        if (stageResult.stderr) {
          totalStderr = capOutput(totalStderr + stageResult.stderr, maxOutputBytes);
        }

        const cappedStageOut = capOutput(stageResult.stdout ?? '', maxOutputBytes);

        if (cmd.redirectOut) {
          const redirPath = expandWordParts(cmd.redirectOut.pathParts, state.env, state.lastExitCode);
          try {
            const vfs = this._requireVfs();
            const { canonicalPath, platform } = this._resolvePath(redirPath, state);
            vfs.writeFile(canonicalPath, cappedStageOut, {
              ...this._vfsCtx(state, platform),
              append: cmd.redirectOut.append,
            });
            pipeInput = '';
          } catch (redirErr) {
            stageResult.exitCode = 1;
            totalStderr = capOutput(
              `${totalStderr}redirection error (${redirPath}): ${formatError(redirErr)}\n`,
              maxOutputBytes
            );
            pipeInput = '';
          }
        } else if (!isLastStage) {
          pipeInput = cappedStageOut;
        } else {
          totalStdout = capOutput(totalStdout + cappedStageOut, maxOutputBytes);
        }

        lastCode = stageResult.exitCode;
        state.lastExitCode = lastCode;
      }
    }

    if (!isolatedCwd) {
      this.cwd = state.cwd;
    }
    if (!isolatedEnv) {
      this.env = { ...state.env };
    }
    this.lastExitCode = lastCode;

    const result = {
      ok: lastCode === 0,
      exitCode: lastCode,
      stdout: totalStdout,
      stderr: totalStderr,
      cwd: state.cwd,
      env: { ...state.env },
    };
    if (state.cleared) {
      result.cleared = true;
    }
    return result;
  }

  async _runSingleCommand(argv, stdin, state) {
    const rawCmd = argv[0] ?? '';
    const cmd = rawCmd.toLowerCase();
    const args = argv.slice(1);

    try {
      switch (cmd) {
        case 'help':
          return { exitCode: 0, stdout: `${HELP_TEXT}\n`, stderr: '' };
        case 'clear':
          state.cleared = true;
          return { exitCode: 0, stdout: '', stderr: '' };
        case 'true':
          return { exitCode: 0, stdout: '', stderr: '' };
        case 'false':
          return { exitCode: 1, stdout: '', stderr: '' };
        case 'pwd':
          return { exitCode: 0, stdout: `${state.cwd}\n`, stderr: '' };
        case 'echo':
          return this._cmdEcho(args);
        case 'whoami':
          return this._cmdWhoami(state);
        case 'uname':
          return this._cmdUname(args);
        case 'env':
          return this._cmdEnv(state);
        case 'export':
          return this._cmdExport(args, state);
        case 'set':
          return this._cmdSet(args, state);
        case 'unset':
          return this._cmdUnset(args, state);
        case 'cd':
          return this._cmdCd(args, state);
        case 'ls':
          return this._cmdLs(args, state);
        case 'dir':
          return this._cmdDir(args, state);
        case 'cat':
          return this._cmdCat(args, stdin, state, false);
        case 'type':
          return this._cmdCat(args, stdin, state, true);
        case 'mkdir':
          return this._cmdMkdir(args, state, false);
        case 'md':
          return this._cmdMkdir(args, state, true);
        case 'rm':
          return this._cmdRm(args, state);
        case 'del':
          return this._cmdDel(args, state);
        case 'rmdir':
          return this._cmdRmdir(args, state, false);
        case 'rd':
          return this._cmdRmdir(args, state, true);
        case 'cp':
          return this._cmdCp(args, state, false);
        case 'copy':
          return this._cmdCp(args, state, true);
        case 'mv':
          return this._cmdMv(args, state, false);
        case 'move':
          return this._cmdMv(args, state, true);
        case 'touch':
          return this._cmdTouch(args, state);
        case 'stat':
          return this._cmdStat(args, state);
        case 'ln':
          return this._cmdLn(args, state);
        case 'readlink':
          return this._cmdReadlink(args, state);
        case 'chmod':
          return this._cmdChmod(args, state);
        case 'chown':
          return this._cmdChown(args, state);
        case 'basename':
          return this._cmdBasename(args);
        case 'dirname':
          return this._cmdDirname(args);
        case 'grep':
          return this._cmdGrep(args, stdin, state);
        case 'head':
          return this._cmdHead(args, stdin, state);
        case 'tail':
          return this._cmdTail(args, stdin, state);
        case 'wc':
          return this._cmdWc(args, stdin, state);
        case 'ps':
          return this._cmdPs(args);
        case 'tasklist':
          return this._cmdTasklist();
        case 'kill':
          return this._cmdKill(args);
        case 'taskkill':
          return this._cmdTaskkill(args);
        case 'dmesg':
          return this._cmdDmesg(args);
        case 'reg':
          return this._cmdReg(args, state);
        case 'defaults':
          return this._cmdDefaults(args);
        case 'open':
          return await this._cmdOpen(args, state);
        case 'am':
          return await this._cmdAm(args);
        case 'pm':
          return await this._cmdPm(args, state);
        case 'prefs':
          return this._cmdPrefs(args);
        case 'ospm':
          return await this._cmdOspm(args, state);
        case 'intent':
          return await this._cmdIntent(args);
        case 'clip':
          return this._cmdClip(args, stdin);
        case 'notify':
          return this._cmdNotify(args);
        case 'search':
          return this._cmdSearch(args);
        default:
          return {
            exitCode: 127,
            stdout: '',
            stderr: `omnish: command not found: ${rawCmd}\n`,
          };
      }
    } catch (err) {
      return {
        exitCode: 1,
        stdout: '',
        stderr: `${rawCmd}: ${formatError(err)}\n`,
      };
    }
  }

  // ---- Basic POSIX / Env ----

  _cmdEcho(args) {
    let noNewline = false;
    let idx = 0;
    if (args[0] === '-n') {
      noNewline = true;
      idx = 1;
    }
    const text = args.slice(idx).join(' ');
    return { exitCode: 0, stdout: noNewline ? text : `${text}\n`, stderr: '' };
  }

  _cmdWhoami(state) {
    let name = state.uid === 0 ? 'root' : 'user';
    if (this.os.users?.isReady) {
      const user = this.os.users.getUserByUid(state.uid);
      if (user?.username) name = user.username;
    }
    return { exitCode: 0, stdout: `${name}\n`, stderr: '' };
  }

  _cmdUname(args) {
    const flags = new Set(args);
    if (flags.size === 0 || flags.has('-s')) {
      return { exitCode: 0, stdout: 'OmniOS\n', stderr: '' };
    }
    if (flags.has('-r')) {
      return { exitCode: 0, stdout: `${this.os.version ?? '1.0.0'}\n`, stderr: '' };
    }
    if (flags.has('-m')) {
      return { exitCode: 0, stdout: 'multi-arch (dalvik/x86_64/arm64/wasm)\n', stderr: '' };
    }
    if (flags.has('-n')) {
      return { exitCode: 0, stdout: 'omnios\n', stderr: '' };
    }
    return {
      exitCode: 0,
      stdout: `OmniOS omnios ${this.os.version ?? '1.0.0'} Unified-4Platform multi-arch (dalvik/x86_64/arm64/wasm)\n`,
      stderr: '',
    };
  }

  _cmdEnv(state) {
    const lines = Object.keys(state.env)
      .sort()
      .map((k) => `${k}=${state.env[k]}`);
    return { exitCode: 0, stdout: lines.length > 0 ? `${lines.join('\n')}\n` : '', stderr: '' };
  }

  _cmdExport(args, state) {
    if (args.length === 0) return this._cmdEnv(state);
    for (const arg of args) {
      const eq = arg.indexOf('=');
      if (eq > 0) {
        const key = arg.slice(0, eq);
        const val = arg.slice(eq + 1);
        state.env[key] = val;
      }
    }
    return { exitCode: 0, stdout: '', stderr: '' };
  }

  _cmdSet(args, state) {
    if (args.length === 0) return this._cmdEnv(state);
    const joined = args.join(' ');
    const eq = joined.indexOf('=');
    if (eq > 0) {
      const key = joined.slice(0, eq).trim();
      const val = joined.slice(eq + 1);
      state.env[key] = val;
      return { exitCode: 0, stdout: '', stderr: '' };
    }
    const prefix = args[0].toLowerCase();
    const lines = Object.keys(state.env)
      .filter((k) => k.toLowerCase().startsWith(prefix))
      .sort()
      .map((k) => `${k}=${state.env[k]}`);
    return { exitCode: 0, stdout: lines.length > 0 ? `${lines.join('\n')}\n` : '', stderr: '' };
  }

  _cmdUnset(args, state) {
    for (const key of args) {
      delete state.env[key];
    }
    return { exitCode: 0, stdout: '', stderr: '' };
  }

  _cmdCd(args, state) {
    const vfs = this._requireVfs();
    let target = args[0] ?? state.env.HOME ?? '/home/user';
    if (target === '-') {
      target = state.env.OLDPWD ?? state.cwd;
    }
    const { canonicalPath, platform } = this._resolvePath(target, state);
    const st = vfs.stat(canonicalPath, this._vfsCtx(state, platform));
    if (st.type !== 'dir') {
      return { exitCode: 1, stdout: '', stderr: `cd: not a directory: ${target}\n` };
    }
    state.env.OLDPWD = state.cwd;
    state.cwd = canonicalPath;
    state.env.PWD = canonicalPath;
    return { exitCode: 0, stdout: '', stderr: '' };
  }

  // ---- Filesystem Commands (POSIX & Windows) ----

  _cmdLs(args, state) {
    const vfs = this._requireVfs();
    let longFmt = false;
    let showAll = false;
    const targets = [];

    for (const arg of args) {
      if (arg.startsWith('-') && arg.length > 1) {
        for (const ch of arg.slice(1)) {
          if (ch === 'l') longFmt = true;
          else if (ch === 'a') showAll = true;
        }
      } else {
        targets.push(arg);
      }
    }

    if (targets.length === 0) targets.push('.');
    const outChunks = [];

    for (const rawTarget of targets) {
      const { canonicalPath, platform } = this._resolvePath(rawTarget, state);
      const ctx = this._vfsCtx(state, platform);
      const st = vfs.stat(canonicalPath, ctx);

      if (st.type !== 'dir') {
        if (longFmt) {
          outChunks.push(
            `${formatModeOctal(st.mode, st.type)} ${String(st.uid).padStart(4)} ${String(st.size).padStart(8)} ${rawTarget}`
          );
        } else {
          outChunks.push(rawTarget);
        }
        continue;
      }

      if (targets.length > 1) {
        outChunks.push(`${rawTarget}:`);
      }
      const entries = vfs.readdir(canonicalPath, ctx);
      const visible = showAll ? entries : entries.filter((e) => !e.name.startsWith('.'));
      for (const entry of visible) {
        if (longFmt) {
          const suffix = entry.type === 'symlink' && entry.target ? ` -> ${entry.target}` : '';
          outChunks.push(
            `${formatModeOctal(entry.mode, entry.type)} ${String(entry.uid ?? 0).padStart(4)} ${String(entry.size ?? 0).padStart(8)} ${entry.name}${suffix}`
          );
        } else {
          outChunks.push(entry.type === 'dir' ? `${entry.name}/` : entry.name);
        }
      }
    }

    return { exitCode: 0, stdout: outChunks.length > 0 ? `${outChunks.join('\n')}\n` : '', stderr: '' };
  }

  _cmdDir(args, state) {
    const vfs = this._requireVfs();
    const rawTarget = args.find((a) => !WIN_DIR_SWITCH_RE.test(a)) ?? '.';
    const { canonicalPath, platform } = this._resolvePath(rawTarget, state, true);
    const ctx = this._vfsCtx(state, platform);
    const winHeader = this.os.pathTranslator
      ? this.os.pathTranslator.toPlatform(canonicalPath, 'windows')
      : canonicalPath;

    const st = vfs.stat(canonicalPath, ctx);
    const lines = [` Directory of ${winHeader}`, ''];

    if (st.type !== 'dir') {
      const { base } = splitBaseDir(canonicalPath);
      lines.push(`${String(st.size).padStart(14)} ${base}`);
      return { exitCode: 0, stdout: `${lines.join('\n')}\n`, stderr: '' };
    }

    const entries = vfs.readdir(canonicalPath, ctx);
    let fileCount = 0;
    let dirCount = 0;
    let totalBytes = 0;
    for (const entry of entries) {
      if (entry.type === 'dir') {
        dirCount += 1;
        lines.push(`         <DIR> ${entry.name}`);
      } else {
        fileCount += 1;
        totalBytes += Number(entry.size ?? 0);
        lines.push(`${String(entry.size ?? 0).padStart(14)} ${entry.name}`);
      }
    }
    lines.push(`               ${fileCount} File(s) ${totalBytes} bytes`);
    lines.push(`               ${dirCount} Dir(s)`);
    return { exitCode: 0, stdout: `${lines.join('\n')}\n`, stderr: '' };
  }

  _cmdCat(args, stdin, state, isWindowsCmd) {
    const vfs = this._requireVfs();
    const files = args.filter((a) => a !== '-n');
    if (files.length === 0) {
      return { exitCode: 0, stdout: stdin, stderr: '' };
    }
    let out = '';
    for (const rawTarget of files) {
      const { canonicalPath, platform } = this._resolvePath(rawTarget, state, isWindowsCmd);
      const content = vfs.readFile(canonicalPath, {
        ...this._vfsCtx(state, platform),
        encoding: 'utf8',
      });
      out += content;
    }
    return { exitCode: 0, stdout: out, stderr: '' };
  }

  _cmdMkdir(args, state, forceRecursive) {
    const vfs = this._requireVfs();
    let recursive = forceRecursive;
    const dirs = [];
    for (const arg of args) {
      if (arg === '-p' || arg === '--parents') {
        recursive = true;
      } else {
        dirs.push(arg);
      }
    }
    if (dirs.length === 0) {
      return { exitCode: 1, stdout: '', stderr: 'mkdir: missing directory operand\n' };
    }
    for (const dir of dirs) {
      const { canonicalPath, platform } = this._resolvePath(dir, state, forceRecursive);
      vfs.mkdir(canonicalPath, { ...this._vfsCtx(state, platform), recursive });
    }
    return { exitCode: 0, stdout: '', stderr: '' };
  }

  _cmdRm(args, state) {
    const vfs = this._requireVfs();
    let recursive = false;
    let force = false;
    const targets = [];

    for (const arg of args) {
      if (arg.startsWith('-') && arg.length > 1) {
        for (const ch of arg.slice(1)) {
          if (ch === 'r' || ch === 'R') recursive = true;
          else if (ch === 'f') force = true;
        }
      } else {
        targets.push(arg);
      }
    }
    if (targets.length === 0) {
      return { exitCode: 1, stdout: '', stderr: 'rm: missing operand\n' };
    }

    for (const rawTarget of targets) {
      const { canonicalPath, platform } = this._resolvePath(rawTarget, state);
      const ctx = this._vfsCtx(state, platform);
      let st;
      try {
        st = vfs.lstat(canonicalPath, ctx);
      } catch (err) {
        if (force && err?.code === 'ENOENT') continue;
        throw err;
      }
      if (st.type === 'dir') {
        if (!recursive) {
          throw new Error(`cannot remove '${rawTarget}': Is a directory (use -r)`);
        }
        this._rmRecursive(vfs, canonicalPath, ctx);
      } else {
        vfs.unlink(canonicalPath, ctx);
      }
    }
    return { exitCode: 0, stdout: '', stderr: '' };
  }

  _cmdDel(args, state) {
    const vfs = this._requireVfs();
    let quiet = false;
    const targets = [];
    for (const arg of args) {
      const up = arg.toUpperCase();
      if (up === '/F' || up === '/Q') {
        quiet = true;
      } else {
        targets.push(arg);
      }
    }
    if (targets.length === 0) {
      return { exitCode: 1, stdout: '', stderr: 'del: missing file path\n' };
    }
    for (const rawTarget of targets) {
      const { canonicalPath, platform } = this._resolvePath(rawTarget, state, true);
      const ctx = this._vfsCtx(state, platform);
      try {
        vfs.unlink(canonicalPath, ctx);
      } catch (err) {
        if (quiet && err?.code === 'ENOENT') continue;
        throw err;
      }
    }
    return { exitCode: 0, stdout: '', stderr: '' };
  }

  _cmdRmdir(args, state, isWindowsCmd) {
    const vfs = this._requireVfs();
    let recursive = false;
    let quiet = false;
    const targets = [];

    for (const arg of args) {
      const low = arg.toLowerCase();
      if (low === '/s' || low === '-r' || low === '-rf') recursive = true;
      else if (low === '/q' || low === '-f') quiet = true;
      else if (low === '-p') {
        // single dir rmdir
      } else {
        targets.push(arg);
      }
    }
    if (targets.length === 0) {
      return { exitCode: 1, stdout: '', stderr: `${isWindowsCmd ? 'rd' : 'rmdir'}: missing directory operand\n` };
    }
    for (const rawTarget of targets) {
      const { canonicalPath, platform } = this._resolvePath(rawTarget, state, isWindowsCmd);
      const ctx = this._vfsCtx(state, platform);
      try {
        if (recursive) {
          this._rmRecursive(vfs, canonicalPath, ctx);
        } else {
          vfs.rmdir(canonicalPath, ctx);
        }
      } catch (err) {
        if (quiet && err?.code === 'ENOENT') continue;
        throw err;
      }
    }
    return { exitCode: 0, stdout: '', stderr: '' };
  }

  _cmdCp(args, state, isWindowsCmd) {
    const vfs = this._requireVfs();
    let recursive = false;
    const paths = [];
    for (const arg of args) {
      if (!isWindowsCmd && (arg === '-r' || arg === '-R' || arg === '-a')) {
        recursive = true;
      } else if (isWindowsCmd && arg.toUpperCase() === '/Y') {
        // overwrite flag
      } else {
        paths.push(arg);
      }
    }
    if (paths.length < 2) {
      return { exitCode: 1, stdout: '', stderr: `${isWindowsCmd ? 'copy' : 'cp'}: missing source or destination\n` };
    }
    const rawDst = paths[paths.length - 1];
    const srcs = paths.slice(0, -1);
    const dstResolved = this._resolvePath(rawDst, state, isWindowsCmd);
    const dstCtx = this._vfsCtx(state, dstResolved.platform);

    let dstIsDir = false;
    try {
      const dstStat = vfs.stat(dstResolved.canonicalPath, dstCtx);
      dstIsDir = dstStat.type === 'dir';
    } catch (err) {
      if (err?.code !== 'ENOENT') throw err;
    }

    for (const rawSrc of srcs) {
      const srcResolved = this._resolvePath(rawSrc, state, isWindowsCmd);
      const ctx = this._vfsCtx(state, srcResolved.platform);
      const { base } = splitBaseDir(srcResolved.canonicalPath);
      const finalDst = dstIsDir
        ? (dstResolved.canonicalPath === '/' ? `/${base}` : `${dstResolved.canonicalPath}/${base}`)
        : dstResolved.canonicalPath;
      this._cpRecursive(vfs, srcResolved.canonicalPath, finalDst, ctx, recursive);
    }
    return { exitCode: 0, stdout: '', stderr: '' };
  }

  _cmdMv(args, state, isWindowsCmd) {
    const vfs = this._requireVfs();
    const paths = args.filter((a) => !(isWindowsCmd && a.toUpperCase() === '/Y') && a !== '-f');
    if (paths.length < 2) {
      return { exitCode: 1, stdout: '', stderr: `${isWindowsCmd ? 'move' : 'mv'}: missing source or destination\n` };
    }
    const rawSrc = paths[0];
    const rawDst = paths[1];
    const srcRes = this._resolvePath(rawSrc, state, isWindowsCmd);
    const dstRes = this._resolvePath(rawDst, state, isWindowsCmd);
    const ctx = this._vfsCtx(state, srcRes.platform);

    let finalDst = dstRes.canonicalPath;
    try {
      const dstStat = vfs.stat(dstRes.canonicalPath, ctx);
      if (dstStat.type === 'dir') {
        const { base } = splitBaseDir(srcRes.canonicalPath);
        finalDst = dstRes.canonicalPath === '/' ? `/${base}` : `${dstRes.canonicalPath}/${base}`;
      }
    } catch (err) {
      if (err?.code !== 'ENOENT') throw err;
    }

    vfs.rename(srcRes.canonicalPath, finalDst, ctx);
    return { exitCode: 0, stdout: '', stderr: '' };
  }

  _cmdTouch(args, state) {
    const vfs = this._requireVfs();
    if (args.length === 0) {
      return { exitCode: 1, stdout: '', stderr: 'touch: missing file operand\n' };
    }
    for (const rawTarget of args) {
      const { canonicalPath, platform } = this._resolvePath(rawTarget, state);
      const ctx = this._vfsCtx(state, platform);
      let exists = false;
      try {
        vfs.stat(canonicalPath, ctx);
        exists = true;
      } catch (err) {
        if (err?.code !== 'ENOENT') throw err;
      }
      if (!exists) {
        vfs.writeFile(canonicalPath, new Uint8Array(0), ctx);
      } else {
        const existing = vfs.readFile(canonicalPath, ctx);
        vfs.writeFile(canonicalPath, existing, ctx);
      }
    }
    return { exitCode: 0, stdout: '', stderr: '' };
  }

  _cmdStat(args, state) {
    const vfs = this._requireVfs();
    if (args.length === 0) {
      return { exitCode: 1, stdout: '', stderr: 'stat: missing file operand\n' };
    }
    const lines = [];
    for (const rawTarget of args) {
      const { canonicalPath, platform } = this._resolvePath(rawTarget, state);
      const st = vfs.lstat(canonicalPath, this._vfsCtx(state, platform));
      lines.push(`  File: ${canonicalPath}${st.type === 'symlink' && st.target ? ` -> ${st.target}` : ''}`);
      lines.push(`  Size: ${st.size}\tType: ${st.type}\tInode: ${st.ino}\tLinks: ${st.nlink}`);
      lines.push(
        `Access: (0${(st.mode & 0o7777).toString(8)}/${formatModeOctal(st.mode, st.type)})\tUid: ${st.uid}\tGid: ${st.gid}`
      );
    }
    return { exitCode: 0, stdout: `${lines.join('\n')}\n`, stderr: '' };
  }

  _cmdLn(args, state) {
    const vfs = this._requireVfs();
    let symbolic = false;
    const operands = [];
    for (const arg of args) {
      if (arg === '-s' || arg === '-sf') symbolic = true;
      else operands.push(arg);
    }
    if (!symbolic) {
      return { exitCode: 1, stdout: '', stderr: 'ln: only symbolic links (-s) are supported\n' };
    }
    if (operands.length < 2) {
      return { exitCode: 1, stdout: '', stderr: 'ln: usage: ln -s <target> <linkPath>\n' };
    }
    const target = operands[0];
    const { canonicalPath: linkPath, platform } = this._resolvePath(operands[1], state);
    vfs.symlink(target, linkPath, this._vfsCtx(state, platform));
    return { exitCode: 0, stdout: '', stderr: '' };
  }

  _cmdReadlink(args, state) {
    const vfs = this._requireVfs();
    if (args.length === 0) {
      return { exitCode: 1, stdout: '', stderr: 'readlink: missing operand\n' };
    }
    const { canonicalPath, platform } = this._resolvePath(args[0], state);
    const target = vfs.readlink(canonicalPath, this._vfsCtx(state, platform));
    return { exitCode: 0, stdout: `${target}\n`, stderr: '' };
  }

  _cmdChmod(args, state) {
    const vfs = this._requireVfs();
    if (args.length < 2) {
      return { exitCode: 1, stdout: '', stderr: 'chmod: usage: chmod <octalMode> <path>\n' };
    }
    const mode = Number.parseInt(args[0], 8);
    if (!Number.isInteger(mode) || mode < 0 || mode > 0o7777) {
      return { exitCode: 1, stdout: '', stderr: `chmod: invalid mode: ${args[0]}\n` };
    }
    for (const rawTarget of args.slice(1)) {
      const { canonicalPath, platform } = this._resolvePath(rawTarget, state);
      vfs.chmod(canonicalPath, mode, this._vfsCtx(state, platform));
    }
    return { exitCode: 0, stdout: '', stderr: '' };
  }

  _cmdChown(args, state) {
    const vfs = this._requireVfs();
    if (args.length < 2) {
      return { exitCode: 1, stdout: '', stderr: 'chown: usage: chown <uid[:gid]> <path>\n' };
    }
    const [uidStr, gidStr] = args[0].split(':');
    const uid = Number.parseInt(uidStr, 10);
    const gid = gidStr !== undefined ? Number.parseInt(gidStr, 10) : uid;
    if (!Number.isInteger(uid) || !Number.isInteger(gid)) {
      return { exitCode: 1, stdout: '', stderr: `chown: invalid uid:gid: ${args[0]}\n` };
    }
    for (const rawTarget of args.slice(1)) {
      const { canonicalPath, platform } = this._resolvePath(rawTarget, state);
      vfs.chown(canonicalPath, uid, gid, this._vfsCtx(state, platform));
    }
    return { exitCode: 0, stdout: '', stderr: '' };
  }

  _cmdBasename(args) {
    if (args.length === 0) return { exitCode: 1, stdout: '', stderr: 'basename: missing operand\n' };
    const { base } = splitBaseDir(args[0]);
    const suffix = args[1];
    const result = suffix && base.endsWith(suffix) ? base.slice(0, -suffix.length) : base;
    return { exitCode: 0, stdout: `${result}\n`, stderr: '' };
  }

  _cmdDirname(args) {
    if (args.length === 0) return { exitCode: 1, stdout: '', stderr: 'dirname: missing operand\n' };
    const { dir } = splitBaseDir(args[0]);
    return { exitCode: 0, stdout: `${dir}\n`, stderr: '' };
  }

  // ---- Text Filters (grep, head, tail, wc) ----

  _readInputsOrStdin(files, stdin, state) {
    if (files.length === 0) return stdin;
    const vfs = this._requireVfs();
    let combined = '';
    for (const rawTarget of files) {
      const { canonicalPath, platform } = this._resolvePath(rawTarget, state);
      combined += vfs.readFile(canonicalPath, { ...this._vfsCtx(state, platform), encoding: 'utf8' });
    }
    return combined;
  }

  _cmdGrep(args, stdin, state) {
    let ignoreCase = false;
    let invert = false;
    let lineNums = false;
    let countOnly = false;
    const rest = [];

    for (const arg of args) {
      if (arg.startsWith('-') && arg.length > 1) {
        for (const ch of arg.slice(1)) {
          if (ch === 'i') ignoreCase = true;
          else if (ch === 'v') invert = true;
          else if (ch === 'n') lineNums = true;
          else if (ch === 'c') countOnly = true;
        }
      } else {
        rest.push(arg);
      }
    }
    if (rest.length === 0) {
      return { exitCode: 2, stdout: '', stderr: 'grep: missing pattern\n' };
    }
    const pattern = rest[0];
    const files = rest.slice(1);
    const content = this._readInputsOrStdin(files, stdin, state);
    const lines = content.length === 0 ? [] : content.replace(/\n$/, '').split('\n');
    const needle = ignoreCase ? pattern.toLowerCase() : pattern;

    let rx = null;
    try {
      rx = new RegExp(pattern, ignoreCase ? 'i' : '');
    } catch (_rxErr) {
      // Fall back to literal substring search if regex syntax is invalid
      rx = null;
    }

    const matched = [];
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i];
      const hit = rx ? rx.test(line) : (ignoreCase ? line.toLowerCase().includes(needle) : line.includes(needle));
      const keep = invert ? !hit : hit;
      if (keep) {
        matched.push(lineNums ? `${i + 1}:${line}` : line);
      }
    }

    if (countOnly) {
      return { exitCode: matched.length > 0 ? 0 : 1, stdout: `${matched.length}\n`, stderr: '' };
    }
    return {
      exitCode: matched.length > 0 ? 0 : 1,
      stdout: matched.length > 0 ? `${matched.join('\n')}\n` : '',
      stderr: '',
    };
  }

  _cmdHead(args, stdin, state) {
    let count = 10;
    const files = [];
    for (let i = 0; i < args.length; i += 1) {
      if (args[i] === '-n' && i + 1 < args.length) {
        count = Math.max(0, Number.parseInt(args[i + 1], 10) || 0);
        i += 1;
      } else if (/^-\d+$/.test(args[i])) {
        count = Math.max(0, Number.parseInt(args[i].slice(1), 10) || 0);
      } else {
        files.push(args[i]);
      }
    }
    const content = this._readInputsOrStdin(files, stdin, state);
    if (!content) return { exitCode: 0, stdout: '', stderr: '' };
    const lines = content.replace(/\n$/, '').split('\n').slice(0, count);
    return { exitCode: 0, stdout: lines.length > 0 ? `${lines.join('\n')}\n` : '', stderr: '' };
  }

  _cmdTail(args, stdin, state) {
    let count = 10;
    const files = [];
    for (let i = 0; i < args.length; i += 1) {
      if (args[i] === '-n' && i + 1 < args.length) {
        count = Math.max(0, Number.parseInt(args[i + 1], 10) || 0);
        i += 1;
      } else if (/^-\d+$/.test(args[i])) {
        count = Math.max(0, Number.parseInt(args[i].slice(1), 10) || 0);
      } else {
        files.push(args[i]);
      }
    }
    const content = this._readInputsOrStdin(files, stdin, state);
    if (!content || count === 0) return { exitCode: 0, stdout: '', stderr: '' };
    const lines = content.replace(/\n$/, '').split('\n').slice(-count);
    return { exitCode: 0, stdout: lines.length > 0 ? `${lines.join('\n')}\n` : '', stderr: '' };
  }

  _cmdWc(args, stdin, state) {
    let showL = false;
    let showW = false;
    let showC = false;
    const files = [];
    for (const arg of args) {
      if (arg.startsWith('-') && arg.length > 1) {
        for (const ch of arg.slice(1)) {
          if (ch === 'l') showL = true;
          else if (ch === 'w') showW = true;
          else if (ch === 'c') showC = true;
        }
      } else {
        files.push(arg);
      }
    }
    if (!showL && !showW && !showC) {
      showL = true;
      showW = true;
      showC = true;
    }
    const content = this._readInputsOrStdin(files, stdin, state);
    const lineCount = (content.match(/\n/g) || []).length;
    const wordCount = content.trim() ? content.trim().split(/\s+/).length : 0;
    const byteCount = Buffer.byteLength(content, 'utf8');
    const parts = [];
    if (showL) parts.push(String(lineCount));
    if (showW) parts.push(String(wordCount));
    if (showC) parts.push(String(byteCount));
    return { exitCode: 0, stdout: `${parts.join(' ')}\n`, stderr: '' };
  }

  // ---- Process & Kernel Commands ----

  _cmdPs(args) {
    const pm = this.os.processManager;
    const treeMode = args.includes('--tree');
    const includeAll = args.includes('-a') || args.includes('-e') || args.includes('aux');

    if (treeMode) {
      const roots = pm.getTree({ includeTerminated: includeAll });
      const lines = [];
      const walk = (node, indent) => {
        lines.push(`${indent}[${node.pid}] ${node.name} (${node.platform}/${node.state})`);
        for (const child of node.children ?? []) {
          walk(child, `${indent}  `);
        }
      };
      for (const root of roots) walk(root, '');
      return { exitCode: 0, stdout: `${lines.join('\n')}\n`, stderr: '' };
    }

    const procs = pm.list({ includeTerminated: includeAll });
    const header = 'PID   PPID  STATE        PLATFORM   ARCH     UID    NAME';
    const lines = [header];
    for (const p of procs) {
      lines.push(
        `${String(p.pid).padEnd(6)}${String(p.ppid).padEnd(6)}${String(p.state).padEnd(13)}${String(p.platform).padEnd(11)}${String(p.arch).padEnd(9)}${String(p.uid).padEnd(7)}${p.name}`
      );
    }
    return { exitCode: 0, stdout: `${lines.join('\n')}\n`, stderr: '' };
  }

  _cmdTasklist() {
    const procs = this.os.processManager.list({ includeTerminated: false });
    const lines = [
      'Image Name                     PID Platform     Status         Mem Usage',
      '========================= ======== ============ ============== ==========',
    ];
    for (const p of procs) {
      const memKb = Math.round((p.memory?.usedBytes ?? 0) / 1024);
      lines.push(
        `${String(p.name).slice(0, 25).padEnd(26)}${String(p.pid).padStart(8)} ${String(p.platform).padEnd(12)} ${String(p.state).padEnd(14)} ${String(memKb).padStart(7)} KB`
      );
    }
    return { exitCode: 0, stdout: `${lines.join('\n')}\n`, stderr: '' };
  }

  _cmdKill(args) {
    if (args.length === 0) {
      return { exitCode: 1, stdout: '', stderr: 'kill: usage: kill [-SIGNAL|-s SIGNAL] <pid>...\n' };
    }
    let signal = 'SIGTERM';
    const pids = [];
    for (let i = 0; i < args.length; i += 1) {
      const a = args[i];
      if ((a === '-s' || a === '--signal') && i + 1 < args.length) {
        signal = args[i + 1];
        i += 1;
      } else if (a.startsWith('-') && a.length > 1) {
        const raw = a.slice(1);
        signal = /^\d+$/.test(raw) ? Number.parseInt(raw, 10) : raw.toUpperCase();
      } else {
        const pid = parseStrictPid(a);
        if (pid === null) {
          return { exitCode: 1, stdout: '', stderr: `kill: invalid pid: ${a}\n` };
        }
        pids.push(pid);
      }
    }
    if (pids.length === 0) {
      return { exitCode: 1, stdout: '', stderr: 'kill: missing PID\n' };
    }
    const out = [];
    for (const pid of pids) {
      const res = this.os.processManager.kill(pid, signal);
      out.push(`Sent ${res.signal} to PID ${res.pid} (state=${res.state})`);
    }
    return { exitCode: 0, stdout: `${out.join('\n')}\n`, stderr: '' };
  }

  _cmdTaskkill(args) {
    let force = false;
    const pids = [];
    const names = [];
    for (let i = 0; i < args.length; i += 1) {
      const up = args[i].toUpperCase();
      if (up === '/F' || up === '-F') {
        force = true;
      } else if ((up === '/PID' || up === '-PID') && i + 1 < args.length) {
        const pid = parseStrictPid(args[i + 1]);
        if (pid === null) {
          return { exitCode: 1, stdout: '', stderr: `taskkill: invalid PID: ${args[i + 1]}\n` };
        }
        pids.push(pid);
        i += 1;
      } else if ((up === '/IM' || up === '-IM') && i + 1 < args.length) {
        names.push(args[i + 1].toLowerCase());
        i += 1;
      }
    }
    if (names.length > 0) {
      for (const p of this.os.processManager.list({ includeTerminated: false })) {
        if (names.includes(String(p.name).toLowerCase()) || names.includes(String(p.appId).toLowerCase())) {
          pids.push(p.pid);
        }
      }
    }
    if (pids.length === 0) {
      return { exitCode: 1, stdout: '', stderr: 'taskkill: specify /PID <pid> or /IM <imageName>\n' };
    }
    const signal = force ? 'SIGKILL' : 'SIGTERM';
    const lines = [];
    for (const pid of pids) {
      const res = this.os.processManager.kill(pid, signal);
      lines.push(`SUCCESS: Sent termination signal (${res.signal}) to process with PID ${res.pid}.`);
    }
    return { exitCode: 0, stdout: `${lines.join('\n')}\n`, stderr: '' };
  }

  _cmdDmesg(args) {
    let limit = 50;
    let subsystem;
    let level;
    for (let i = 0; i < args.length; i += 1) {
      if ((args[i] === '-n' || args[i] === '--limit') && i + 1 < args.length) {
        limit = Number.parseInt(args[i + 1], 10) || 50;
        i += 1;
      } else if (args[i] === '--subsystem' && i + 1 < args.length) {
        subsystem = args[i + 1];
        i += 1;
      } else if (args[i] === '--level' && i + 1 < args.length) {
        level = args[i + 1];
        i += 1;
      }
    }
    const entries = this.os.kernel.dmesg({ limit, subsystem, level });
    const lines = entries.map(
      (e) => `[${String(e.uptimeMs).padStart(8)}ms] [${e.level.toUpperCase()}] ${e.subsystem}: ${e.message}`
    );
    return { exitCode: 0, stdout: lines.length > 0 ? `${lines.join('\n')}\n` : '', stderr: '' };
  }

  // ---- Windows Registry (`reg`) ----

  _cmdReg(args, state) {
    const cfg = this._requireConfig();
    if (args.length === 0) {
      return {
        exitCode: 1,
        stdout: '',
        stderr: 'reg: usage: reg <query|list|get|add|set|delete> <HIVE\\KeyPath> [options]\n',
      };
    }
    const uid = Number.isInteger(state?.uid) ? state.uid : 1000;
    const regCtx = { uid, privileged: uid === 0 };
    const sub = args[0].toLowerCase();

    if (sub === 'query' || sub === 'list') {
      if (!args[1]) return { exitCode: 1, stdout: '', stderr: 'reg query: missing key path\n' };
      const { hive, keyPath } = parseRegistryPath(args[1]);
      let valueName = null;
      for (let i = 2; i < args.length; i += 1) {
        if ((args[i].toLowerCase() === '/v' || args[i] === '-v') && i + 1 < args.length) {
          valueName = args[i + 1];
          i += 1;
        }
      }
      if (valueName !== null) {
        const val = cfg.registry.getValue(hive, keyPath, valueName, regCtx);
        if (!val) return { exitCode: 1, stdout: '', stderr: `reg: value not found: ${valueName}\n` };
        return {
          exitCode: 0,
          stdout: `${valueName}  ${val.type}  ${formatRegValueData(val.data, { quoteStrings: true })}\n`,
          stderr: '',
        };
      }
      const res = cfg.registry.enumKey(hive, keyPath, regCtx);
      const lines = [`${res.hive}\\${res.keyPath}`];
      for (const [k, v] of Object.entries(res.values)) {
        lines.push(`    ${k}    ${v.type}    ${formatRegValueData(v.data)}`);
      }
      for (const sk of res.subkeys) {
        lines.push(`    ${res.hive}\\${keyPath ? `${keyPath}\\` : ''}${sk}`);
      }
      return { exitCode: 0, stdout: `${lines.join('\n')}\n`, stderr: '' };
    }

    if (sub === 'get') {
      if (args.length < 3) {
        return { exitCode: 1, stdout: '', stderr: 'reg get: usage: reg get <HIVE\\KeyPath> <valueName>\n' };
      }
      const { hive, keyPath } = parseRegistryPath(args[1]);
      const val = cfg.registry.getValue(hive, keyPath, args[2], regCtx);
      if (!val) return { exitCode: 1, stdout: '', stderr: `reg: value not found: ${args[2]}\n` };
      const formatted = formatRegValueData(val.data);
      return { exitCode: 0, stdout: `${formatted}\n`, stderr: '' };
    }

    if (sub === 'add' || sub === 'set') {
      if (!args[1]) return { exitCode: 1, stdout: '', stderr: 'reg add/set: missing key path\n' };
      const { hive, keyPath } = parseRegistryPath(args[1]);
      let valueName = null;
      let type = 'REG_SZ';
      let rawData = null;
      const positionals = [];
      for (let i = 2; i < args.length; i += 1) {
        const flag = args[i].toLowerCase();
        if ((flag === '/v' || flag === '-v') && i + 1 < args.length) {
          valueName = args[++i];
        } else if ((flag === '/t' || flag === '-t') && i + 1 < args.length) {
          type = args[++i].toUpperCase();
        } else if ((flag === '/d' || flag === '-d') && i + 1 < args.length) {
          rawData = args[++i];
        } else if (flag === '/f' || flag === '-f') {
          // force flag
        } else {
          positionals.push(args[i]);
        }
      }
      if (valueName === null && positionals.length >= 2) {
        valueName = positionals[0];
        rawData = positionals[1];
        if (positionals[2]) type = positionals[2].toUpperCase();
      }
      if (valueName === null) {
        cfg.registry.createKey(hive, keyPath, regCtx);
        return { exitCode: 0, stdout: `Key created: ${hive}\\${keyPath}\n`, stderr: '' };
      }
      const data = parseScalarValue(rawData ?? '', type);
      cfg.registry.setValue(hive, keyPath, valueName, type, data, regCtx);
      return { exitCode: 0, stdout: `The operation completed successfully.\n`, stderr: '' };
    }

    if (sub === 'delete') {
      if (!args[1]) return { exitCode: 1, stdout: '', stderr: 'reg delete: missing key path\n' };
      const { hive, keyPath } = parseRegistryPath(args[1]);
      let valueName = null;
      for (let i = 2; i < args.length; i += 1) {
        if ((args[i].toLowerCase() === '/v' || args[i] === '-v') && i + 1 < args.length) {
          valueName = args[++i];
        }
      }
      if (valueName !== null) {
        const ok = cfg.registry.deleteValue(hive, keyPath, valueName, regCtx);
        return {
          exitCode: ok ? 0 : 1,
          stdout: ok ? 'The operation completed successfully.\n' : '',
          stderr: ok ? '' : `reg delete: value not found: ${valueName}\n`,
        };
      }
      const ok = cfg.registry.deleteKey(hive, keyPath, regCtx);
      return {
        exitCode: ok ? 0 : 1,
        stdout: ok ? 'The operation completed successfully.\n' : '',
        stderr: ok ? '' : `reg delete: key not found: ${hive}\\${keyPath}\n`,
      };
    }

    return { exitCode: 1, stdout: '', stderr: `reg: unknown subcommand '${sub}'\n` };
  }

  // ---- macOS Commands (`defaults`, `open`) ----

  _cmdDefaults(args) {
    const cfg = this._requireConfig();
    if (args.length === 0) {
      return {
        exitCode: 1,
        stdout: '',
        stderr: 'defaults: usage: defaults <domains|read|write|delete|export> ...\n',
      };
    }
    const sub = args[0].toLowerCase();

    if (sub === 'domains') {
      const domains = cfg.defaults.listDomains();
      return { exitCode: 0, stdout: `${domains.join(', ')}\n`, stderr: '' };
    }

    if (sub === 'read') {
      if (!args[1]) {
        const domains = cfg.defaults.listDomains();
        const dump = {};
        for (const d of domains) dump[d] = cfg.defaults.readDomain(d);
        return { exitCode: 0, stdout: `${JSON.stringify(dump, null, 2)}\n`, stderr: '' };
      }
      const domain = args[1];
      if (args[2]) {
        const val = cfg.defaults.get(domain, args[2]);
        if (val === null || val === undefined) {
          return { exitCode: 1, stdout: '', stderr: `The domain/default pair of (${domain}, ${args[2]}) does not exist\n` };
        }
        return {
          exitCode: 0,
          stdout: `${typeof val === 'string' ? val : JSON.stringify(val)}\n`,
          stderr: '',
        };
      }
      const all = cfg.defaults.readDomain(domain);
      return { exitCode: 0, stdout: `${JSON.stringify(all, null, 2)}\n`, stderr: '' };
    }

    if (sub === 'write') {
      if (args.length < 4) {
        return { exitCode: 1, stdout: '', stderr: 'defaults write: usage: defaults write <domain> <key> [-type] <value>\n' };
      }
      const domain = args[1];
      const key = args[2];
      let typeHint = null;
      let rawVal;
      if (args[3].startsWith('-') && args.length >= 5) {
        typeHint = args[3];
        rawVal = args[4];
      } else {
        rawVal = args[3];
      }
      const val = parseScalarValue(rawVal, typeHint);
      cfg.defaults.set(domain, key, val);
      return { exitCode: 0, stdout: '', stderr: '' };
    }

    if (sub === 'delete') {
      if (args.length < 3) {
        return { exitCode: 1, stdout: '', stderr: 'defaults delete: usage: defaults delete <domain> <key>\n' };
      }
      const removed = cfg.defaults.remove(args[1], args[2]);
      return {
        exitCode: removed ? 0 : 1,
        stdout: '',
        stderr: removed ? '' : `defaults delete: key not found: ${args[2]}\n`,
      };
    }

    if (sub === 'export') {
      if (!args[1]) {
        return { exitCode: 1, stdout: '', stderr: 'defaults export: usage: defaults export <domain>\n' };
      }
      const xml = cfg.defaults.exportPlistXml(args[1]);
      return { exitCode: 0, stdout: `${xml}\n`, stderr: '' };
    }

    return { exitCode: 1, stdout: '', stderr: `defaults: unknown subcommand '${sub}'\n` };
  }

  async _cmdOpen(args, state) {
    if (args.length === 0) {
      return { exitCode: 1, stdout: '', stderr: 'open: usage: open [-a <appId>] <target>\n' };
    }
    let appOverride = null;
    const targets = [];
    for (let i = 0; i < args.length; i += 1) {
      if (args[i] === '-a' && i + 1 < args.length) {
        appOverride = args[++i];
      } else {
        targets.push(args[i]);
      }
    }

    const target = targets[0] ?? null;

    if (appOverride) {
      const intent = target ? { action: 'view', uri: target } : undefined;
      const launched = await this.os.launchApp(appOverride, { intent, pump: true, stepTicks: 10 });
      return {
        exitCode: 0,
        stdout: `Launched ${launched.appId} (PID ${launched.pid})\n`,
        stderr: '',
      };
    }

    if (!target) {
      return { exitCode: 1, stdout: '', stderr: 'open: missing target\n' };
    }

    // Direct app launch if target matches an installed app or system app
    if (this.os.systemApps?.resolveId(target) || (this.os.pkgManager?.isReady() && this.os.pkgManager.get(target))) {
      const launched = await this.os.launchApp(target, { pump: true, stepTicks: 10 });
      return { exitCode: 0, stdout: `Launched ${launched.appId} (PID ${launched.pid})\n`, stderr: '' };
    }

    // URL scheme
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(target)) {
      const res = await this.os.intentRouter.dispatch({ action: 'view', uri: target });
      return {
        exitCode: res.status === 'NO_HANDLER' ? 1 : 0,
        stdout: `${JSON.stringify(res)}\n`,
        stderr: res.status === 'NO_HANDLER' ? `open: no handler for ${target}\n` : '',
      };
    }

    // VFS path
    const { canonicalPath, platform } = this._resolvePath(target, state);
    const ext = extnameOf(canonicalPath);
    const mimeType = EXT_MIME_MAP[ext] ?? null;
    let isDir = false;
    if (this.os.vfs?.isReady) {
      try {
        const st = this.os.vfs.stat(canonicalPath, this._vfsCtx(state, platform));
        isDir = st.type === 'dir';
      } catch (_statErr) {
        // Proceed with intent dispatch even if stat fails
      }
    }
    if (isDir && this.os.systemApps) {
      const launched = await this.os.launchApp('com.omnios.files', { cwd: canonicalPath });
      return { exitCode: 0, stdout: `Opened directory in OmniFiles (PID ${launched.pid})\n`, stderr: '' };
    }
    const res = await this.os.intentRouter.dispatch({
      action: 'view',
      uri: `file://${canonicalPath}`,
      extension: ext || null,
      mimeType,
    });
    return {
      exitCode: res.status === 'NO_HANDLER' ? 1 : 0,
      stdout: `${JSON.stringify(res)}\n`,
      stderr: res.status === 'NO_HANDLER' ? `open: no handler for ${canonicalPath}\n` : '',
    };
  }

  // ---- Android Commands (`am`, `pm`, `prefs`) ----

  async _cmdAm(args) {
    if (args.length === 0) {
      return { exitCode: 1, stdout: '', stderr: 'am: usage: am <start|broadcast> [options]\n' };
    }
    const sub = args[0].toLowerCase();
    let action = null;
    let uri = null;
    let mimeType = null;
    let component = null;
    const extras = {};

    for (let i = 1; i < args.length; i += 1) {
      const flag = args[i];
      if (flag === '-a' && i + 1 < args.length) action = args[++i];
      else if (flag === '-d' && i + 1 < args.length) uri = args[++i];
      else if (flag === '-t' && i + 1 < args.length) mimeType = args[++i];
      else if (flag === '-n' && i + 1 < args.length) component = args[++i];
      else if (flag === '--es' && i + 2 < args.length) {
        extras[args[i + 1]] = args[i + 2];
        i += 2;
      } else if (flag === '--ei' && i + 2 < args.length) {
        extras[args[i + 1]] = Number.parseInt(args[i + 2], 10);
        i += 2;
      } else if (flag === '--ez' && i + 2 < args.length) {
        extras[args[i + 1]] = args[i + 2].toLowerCase() === 'true';
        i += 2;
      }
    }

    if (sub === 'start') {
      const appId = component ? component.split('/')[0] : null;
      if (appId && !action && !uri && !mimeType) {
        const res = await this.os.launchApp(appId, {
          intent: Object.keys(extras).length > 0 ? { action: 'main', extras } : undefined,
          pump: true,
          stepTicks: 10,
        });
        return { exitCode: 0, stdout: `Starting: ${res.appId} (PID ${res.pid})\n`, stderr: '' };
      }
      const dispatchRes = await this.os.intentRouter.dispatch({
        action: action ?? 'view',
        uri,
        mimeType,
        extras,
        preferredAppId: appId,
      });
      return {
        exitCode: dispatchRes.status === 'NO_HANDLER' ? 1 : 0,
        stdout: `${JSON.stringify(dispatchRes)}\n`,
        stderr: dispatchRes.status === 'NO_HANDLER' ? 'am start: no matching handler\n' : '',
      };
    }

    if (sub === 'broadcast') {
      const payload = { action: action ?? 'android.intent.action.CUSTOM', uri, extras, ts: new Date().toISOString() };
      if (this.os.ipc) {
        try {
          if (!this.os.ipc.listChannels().some((c) => c.name === 'android.broadcast')) {
            this.os.ipc.createChannel('android.broadcast', 0);
          }
          this.os.ipc.send('android.broadcast', 0, payload);
        } catch (_ipcErr) {
          // Fall back to eventBus broadcast
        }
      }
      this.os.eventBus?.emit('android:broadcast', payload);
      return { exitCode: 0, stdout: `Broadcast completed: action=${payload.action}\n`, stderr: '' };
    }

    return { exitCode: 1, stdout: '', stderr: `am: unknown subcommand '${sub}'\n` };
  }

  async _cmdPm(args, state) {
    const pm = this.os.pkgManager;
    if (args.length === 0) {
      return {
        exitCode: 1,
        stdout: '',
        stderr: 'pm: usage: pm <list packages|install|uninstall|grant|revoke> ...\n',
      };
    }
    const sub = args[0].toLowerCase();

    if (sub === 'list' && (args[1]?.toLowerCase() === 'packages' || !args[1])) {
      const pkgs = pm.list();
      const showPath = args.includes('-f');
      const lines = pkgs.map((p) => (showPath ? `package:${p.installDir}=${p.appId}` : `package:${p.appId}`));
      return { exitCode: 0, stdout: lines.length > 0 ? `${lines.join('\n')}\n` : '', stderr: '' };
    }

    if (sub === 'install') {
      const grantAll = args.includes('-g') || args.includes('--grant-all');
      const overwrite = args.includes('-r') || args.includes('--overwrite');
      const target = args.slice(1).find((a) => !a.startsWith('-'));
      if (!target) return { exitCode: 1, stdout: '', stderr: 'pm install: missing package VFS path\n' };
      const { canonicalPath } = this._resolvePath(target, state);
      const record = await pm.install(canonicalPath, { grantAll, overwrite });
      return { exitCode: 0, stdout: `Success: installed ${record.appId} (${record.platform})\n`, stderr: '' };
    }

    if (sub === 'uninstall') {
      const purgeData = args.includes('--purge');
      const appId = args.slice(1).find((a) => !a.startsWith('-'));
      if (!appId) return { exitCode: 1, stdout: '', stderr: 'pm uninstall: missing appId\n' };
      await pm.uninstall(appId, { purgeData });
      return { exitCode: 0, stdout: `Success: uninstalled ${appId}\n`, stderr: '' };
    }

    if (sub === 'grant' || sub === 'revoke') {
      const appId = args[1];
      const perm = args[2];
      if (!appId || !perm) {
        return { exitCode: 1, stdout: '', stderr: `pm ${sub}: usage: pm ${sub} <appId> <permission>\n` };
      }
      const mapped = mapNativePermission(perm, 'android') ?? perm;
      const grantState = sub === 'grant' ? 'allow' : 'deny';
      this.os.permissions.setGrant(appId, mapped, grantState, { source: 'pm' });
      return { exitCode: 0, stdout: `${sub === 'grant' ? 'Granted' : 'Revoked'} ${mapped} for ${appId}\n`, stderr: '' };
    }

    return { exitCode: 1, stdout: '', stderr: `pm: unknown subcommand '${sub}'\n` };
  }

  _cmdPrefs(args) {
    const cfg = this._requireConfig();
    if (args.length < 3) {
      return {
        exitCode: 1,
        stdout: '',
        stderr: 'prefs: usage: prefs <get|set|edit|delete> <packageName> <prefName> [key] [value]\n',
      };
    }
    const sub = args[0].toLowerCase();
    const pkg = args[1];
    const prefName = args[2];

    if (sub === 'get') {
      if (args[3]) {
        const val = cfg.sharedPrefs.get(pkg, prefName, args[3]);
        if (val === null || val === undefined) {
          return { exitCode: 1, stdout: '', stderr: `prefs: key not found: ${args[3]}\n` };
        }
        return { exitCode: 0, stdout: `${typeof val === 'string' ? val : JSON.stringify(val)}\n`, stderr: '' };
      }
      const all = cfg.sharedPrefs.getAll(pkg, prefName);
      return { exitCode: 0, stdout: `${JSON.stringify(all, null, 2)}\n`, stderr: '' };
    }

    if (sub === 'set') {
      if (args.length < 5) {
        return { exitCode: 1, stdout: '', stderr: 'prefs set: usage: prefs set <pkg> <prefName> <key> <value> [type]\n' };
      }
      const key = args[3];
      const value = parseScalarValue(args[4], args[5] ?? null);
      cfg.sharedPrefs.edit(pkg, prefName, [{ op: 'put', key, value }]);
      return { exitCode: 0, stdout: `Saved ${pkg}/${prefName}/${key}\n`, stderr: '' };
    }

    if (sub === 'delete' || sub === 'remove') {
      if (!args[3]) {
        return { exitCode: 1, stdout: '', stderr: 'prefs delete: usage: prefs delete <pkg> <prefName> <key>\n' };
      }
      cfg.sharedPrefs.edit(pkg, prefName, [{ op: 'remove', key: args[3] }]);
      return { exitCode: 0, stdout: `Removed ${pkg}/${prefName}/${args[3]}\n`, stderr: '' };
    }

    if (sub === 'edit') {
      const op = args[3]?.toLowerCase();
      if (op === 'clear') {
        cfg.sharedPrefs.edit(pkg, prefName, [{ op: 'clear' }]);
        return { exitCode: 0, stdout: `Cleared ${pkg}/${prefName}\n`, stderr: '' };
      }
      if (op === 'remove' && args[4]) {
        cfg.sharedPrefs.edit(pkg, prefName, [{ op: 'remove', key: args[4] }]);
        return { exitCode: 0, stdout: `Removed ${pkg}/${prefName}/${args[4]}\n`, stderr: '' };
      }
      if (op === 'put' && args[4] && args[5] !== undefined) {
        const value = parseScalarValue(args[5], args[6] ?? null);
        cfg.sharedPrefs.edit(pkg, prefName, [{ op: 'put', key: args[4], value }]);
        return { exitCode: 0, stdout: `Updated ${pkg}/${prefName}/${args[4]}\n`, stderr: '' };
      }
      return { exitCode: 1, stdout: '', stderr: 'prefs edit: expected put <k> <v> | remove <k> | clear\n' };
    }

    return { exitCode: 1, stdout: '', stderr: `prefs: unknown subcommand '${sub}'\n` };
  }

  // ---- OmniOS Native Commands (`ospm`, `intent`, `clip`, `notify`, `search`) ----

  async _cmdOspm(args, state) {
    const pm = this.os.pkgManager;
    if (args.length === 0) {
      return {
        exitCode: 1,
        stdout: '',
        stderr: 'ospm: usage: ospm <list|catalog|inspect|install|launch|stop|uninstall> ...\n',
      };
    }
    const sub = args[0].toLowerCase();

    if (sub === 'list') {
      let platform;
      const pIdx = args.indexOf('--platform');
      if (pIdx !== -1 && args[pIdx + 1]) platform = args[pIdx + 1];
      const list = pm.list(platform ? { platform } : {});
      if (list.length === 0) return { exitCode: 0, stdout: '(no installed packages)\n', stderr: '' };
      const lines = list.map((p) => `${p.appId}\t${p.platform}\t${p.arch}\tv${p.version}\t${p.name}`);
      return { exitCode: 0, stdout: `${lines.join('\n')}\n`, stderr: '' };
    }

    if (sub === 'catalog') {
      let platform;
      const pIdx = args.indexOf('--platform');
      if (pIdx !== -1 && args[pIdx + 1]) platform = args[pIdx + 1];
      const cat = pm.getCatalog(platform ? { platform } : {});
      if (cat.length === 0) return { exitCode: 0, stdout: '(catalog empty)\n', stderr: '' };
      const lines = cat.map(
        (c) => `${c.appId}\t${c.platform}\t${c.installed ? '[installed]' : '[available]'}\t${c.packagePath ?? ''}\t${c.name}`
      );
      return { exitCode: 0, stdout: `${lines.join('\n')}\n`, stderr: '' };
    }

    if (sub === 'inspect') {
      const target = args[1];
      if (!target) return { exitCode: 1, stdout: '', stderr: 'ospm inspect: missing VFS path\n' };
      const { canonicalPath } = this._resolvePath(target, state);
      const insp = await pm.inspect(canonicalPath);
      return { exitCode: 0, stdout: `${JSON.stringify(insp, null, 2)}\n`, stderr: '' };
    }

    if (sub === 'install') {
      const grantAll = args.includes('--grant-all') || args.includes('-g');
      const overwrite = args.includes('--overwrite');
      const upgrade = args.includes('--upgrade');
      const target = args.slice(1).find((a) => !a.startsWith('-'));
      if (!target) return { exitCode: 1, stdout: '', stderr: 'ospm install: missing VFS path\n' };
      const { canonicalPath } = this._resolvePath(target, state);
      const rec = await pm.install(canonicalPath, { grantAll, overwrite, upgrade });
      return { exitCode: 0, stdout: `Installed ${rec.appId} (${rec.platform}/${rec.arch})\n`, stderr: '' };
    }

    if (sub === 'launch') {
      let appId = null;
      let platform;
      let preferSystem = false;
      for (let i = 1; i < args.length; i += 1) {
        const arg = args[i];
        if (arg === '--platform' && i + 1 < args.length) {
          platform = args[++i];
        } else if (arg.startsWith('--platform=')) {
          platform = arg.slice('--platform='.length);
        } else if (arg === '--prefer-system') {
          preferSystem = true;
        } else if (!arg.startsWith('-') && appId === null) {
          appId = arg;
        }
      }
      if (!appId) return { exitCode: 1, stdout: '', stderr: 'ospm launch: missing appId\n' };
      const launchOpts = { pump: true, stepTicks: 10 };
      if (platform) launchOpts.platform = platform;
      if (preferSystem) launchOpts.preferSystem = true;
      const res = await this.os.launchApp(appId, launchOpts);
      return {
        exitCode: 0,
        stdout: `Launched ${res.appId} (PID ${res.pid}, platform=${res.platform}, windows=${res.windowIds.length})\n`,
        stderr: '',
      };
    }

    if (sub === 'stop') {
      const target = args[1];
      if (!target) return { exitCode: 1, stdout: '', stderr: 'ospm stop: missing pid or appId\n' };
      const pidOrId = /^\d+$/.test(target) ? Number.parseInt(target, 10) : target;
      const res = this.os.stopApp(pidOrId);
      return { exitCode: 0, stdout: `Stopped PIDs: ${res.stoppedPids.join(', ') || 'none'}\n`, stderr: '' };
    }

    if (sub === 'uninstall') {
      const purgeData = args.includes('--purge');
      const appId = args.slice(1).find((a) => !a.startsWith('-'));
      if (!appId) return { exitCode: 1, stdout: '', stderr: 'ospm uninstall: missing appId\n' };
      await pm.uninstall(appId, { purgeData });
      return { exitCode: 0, stdout: `Uninstalled ${appId}\n`, stderr: '' };
    }

    return { exitCode: 1, stdout: '', stderr: `ospm: unknown subcommand '${sub}'\n` };
  }

  async _cmdIntent(args) {
    if (args.length === 0) {
      return { exitCode: 1, stdout: '', stderr: 'intent: usage: intent <resolve|dispatch> [--action a] [--uri u] [--mime m] [--ext e] [--scheme s] [--app id]\n' };
    }
    const sub = args[0].toLowerCase();
    const q = { extras: {} };
    for (let i = 1; i < args.length; i += 1) {
      const a = args[i];
      if (a === '--action' && i + 1 < args.length) q.action = args[++i];
      else if (a === '--uri' && i + 1 < args.length) q.uri = args[++i];
      else if ((a === '--mime' || a === '--mime-type') && i + 1 < args.length) q.mimeType = args[++i];
      else if (a === '--ext' && i + 1 < args.length) q.extension = args[++i];
      else if (a === '--scheme' && i + 1 < args.length) q.scheme = args[++i];
      else if ((a === '--app' || a === '--preferred') && i + 1 < args.length) q.preferredAppId = args[++i];
      else if (a === '--extra' && i + 1 < args.length) {
        const kv = args[++i];
        const eq = kv.indexOf('=');
        if (eq > 0) q.extras[kv.slice(0, eq)] = kv.slice(eq + 1);
      }
    }

    if (sub === 'resolve') {
      const candidates = this.os.intentRouter.resolve(q);
      return { exitCode: 0, stdout: `${JSON.stringify(candidates, null, 2)}\n`, stderr: '' };
    }

    if (sub === 'dispatch') {
      const res = await this.os.intentRouter.dispatch(q);
      return {
        exitCode: res.status === 'NO_HANDLER' ? 1 : 0,
        stdout: `${JSON.stringify(res, null, 2)}\n`,
        stderr: '',
      };
    }

    return { exitCode: 1, stdout: '', stderr: `intent: unknown subcommand '${sub}'\n` };
  }

  _cmdClip(args, stdin) {
    const clip = this.os.clipboard;
    const sub = (args[0] ?? 'get').toLowerCase();

    if (sub === 'get') {
      const entry = args[1] ? clip.get(args[1]) : clip.get();
      if (entry === null || entry === undefined) return { exitCode: 0, stdout: '', stderr: '' };
      if (typeof entry === 'string') {
        return { exitCode: 0, stdout: `${entry}\n`, stderr: '' };
      }
      const text = entry.text ?? entry.formats?.['text/plain'] ?? JSON.stringify(entry.formats ?? entry);
      return { exitCode: 0, stdout: `${text}\n`, stderr: '' };
    }

    if (sub === 'set') {
      const text = args.length > 1 ? args.slice(1).join(' ') : stdin.replace(/\n$/, '');
      clip.set({ text, sourceAppId: 'com.omnios.terminal' });
      return { exitCode: 0, stdout: 'Clipboard updated.\n', stderr: '' };
    }

    if (sub === 'history') {
      const limit = args[1] ? Number.parseInt(args[1], 10) || 20 : 20;
      const hist = clip.history(limit);
      return { exitCode: 0, stdout: `${JSON.stringify(hist, null, 2)}\n`, stderr: '' };
    }

    if (sub === 'clear') {
      clip.clear();
      return { exitCode: 0, stdout: 'Clipboard cleared.\n', stderr: '' };
    }

    return { exitCode: 1, stdout: '', stderr: `clip: unknown subcommand '${sub}'\n` };
  }

  _cmdNotify(args) {
    const notif = this.os.notifications;
    const sub = (args[0] ?? 'list').toLowerCase();

    if (sub === 'send' || sub === 'post') {
      let appId = 'com.omnios.terminal';
      let priority = 'normal';
      let category = 'general';
      const rest = [];
      for (let i = 1; i < args.length; i += 1) {
        if (args[i] === '--app' && i + 1 < args.length) appId = args[++i];
        else if (args[i] === '--priority' && i + 1 < args.length) priority = args[++i];
        else if (args[i] === '--category' && i + 1 < args.length) category = args[++i];
        else rest.push(args[i]);
      }
      const title = rest[0] ?? 'OmniOS';
      const body = rest.slice(1).join(' ');
      const posted = notif.post({ appId, platform: 'system', title, body, priority, category });
      return { exitCode: 0, stdout: `Posted notification ${posted.id}\n`, stderr: '' };
    }

    if (sub === 'list') {
      const includeDismissed = args.includes('--all');
      const list = notif.list({ includeDismissed });
      if (list.length === 0) return { exitCode: 0, stdout: '(no notifications)\n', stderr: '' };
      const lines = list.map((n) => `${n.id}\t[${n.priority}]\t${n.appId}\t${n.title}: ${n.body}`);
      return { exitCode: 0, stdout: `${lines.join('\n')}\n`, stderr: '' };
    }

    if (sub === 'dismiss') {
      if (!args[1]) return { exitCode: 1, stdout: '', stderr: 'notify dismiss: missing notification id\n' };
      const res = notif.dismiss(args[1]);
      return { exitCode: res ? 0 : 1, stdout: res ? `Dismissed ${args[1]}\n` : '', stderr: res ? '' : `Notification not found: ${args[1]}\n` };
    }

    return { exitCode: 1, stdout: '', stderr: `notify: unknown subcommand '${sub}'\n` };
  }

  _cmdSearch(args) {
    if (!this.os.search || typeof this.os.search.query !== 'function') {
      return { exitCode: 1, stdout: '', stderr: 'search: Spotlight search engine is unavailable\n' };
    }
    const query = args.join(' ');
    const res = this.os.search.query(query);
    if (res.results.length === 0) {
      return { exitCode: 0, stdout: '(no results)\n', stderr: '' };
    }
    const lines = res.results.map((r) => `[${r.type}] ${r.title}${r.subtitle ? ` — ${r.subtitle}` : ''}`);
    return { exitCode: 0, stdout: `${lines.join('\n')}\n`, stderr: '' };
  }
}

export function createShellInterpreter(os, options = {}) {
  return new ShellInterpreter(os, options);
}
