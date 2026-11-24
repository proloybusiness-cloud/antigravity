/**
 * OmniOS Transparent 4-Platform PathTranslator & Sandbox Traversal Jail (F-017, F-018)
 * Bidirectional translation across POSIX, Windows, macOS, Android, iOS, and Universal platforms
 * with Shared User Space (/home/user/{Documents,Downloads,Desktop,Pictures}) unification.
 */

import { VfsError, ERROR_CODES } from '../common/errors.mjs';

function freezeLookup(obj) {
  return Object.freeze(Object.assign(Object.create(null), obj));
}

export const PLATFORMS = freezeLookup({
  POSIX: 'posix',
  WINDOWS: 'windows',
  MACOS: 'macos',
  ANDROID: 'android',
  IOS: 'ios',
  UNIVERSAL: 'universal',
});

const VALID_PLATFORMS = new Set(Object.values(PLATFORMS));

export const CASE_INSENSITIVE_PLATFORMS = Object.freeze(
  new Set([PLATFORMS.WINDOWS, PLATFORMS.MACOS])
);

export const MAX_PATH_LENGTH = 4096;
const CONTROL_CHAR_RE = /[\x00-\x1f\x7f]/;
const WINDOWS_DRIVE_RE = /^([a-zA-Z]):(.*)$/;

const SYMBOL_DESCRIPTION_GET =
  Object.getOwnPropertyDescriptor(Symbol.prototype, 'description')?.get ?? null;
const MAX_DISPLAY_BIGINT_ABS = 1n << 4096n;
const MIN_DISPLAY_BIGINT_NEG = -MAX_DISPLAY_BIGINT_ABS;

function safeDisplay(value, maxLen = 256) {
  if (typeof value === 'string') {
    return value.length > maxLen ? `${value.slice(0, maxLen)}...` : value;
  }
  if (value === null || value === undefined) return String(value);
  const t = typeof value;
  if (t === 'number' || t === 'boolean') return String(value);
  if (t === 'bigint') {
    if (value > MAX_DISPLAY_BIGINT_ABS || value < MIN_DISPLAY_BIGINT_NEG) {
      return '[BigInt(Truncated)]';
    }
    const str = value.toString(10);
    return str.length > maxLen ? `${str.slice(0, maxLen)}...` : str;
  }
  if (t === 'symbol') {
    try {
      const desc = SYMBOL_DESCRIPTION_GET ? SYMBOL_DESCRIPTION_GET.call(value) : undefined;
      if (typeof desc === 'string') {
        const innerMax = Math.max(0, maxLen - 8);
        const capped = desc.length > innerMax ? `${desc.slice(0, innerMax)}...` : desc;
        return `Symbol(${capped})`;
      }
      return 'Symbol()';
    } catch (_err) {
      return '[Symbol]';
    }
  }
  if (t === 'function') return '[Function]';
  if (t === 'object') {
    try {
      if (Array.isArray(value)) return '[Array]';
    } catch (_err) {
      return '[Unreadable]';
    }
    return '[Object]';
  }
  return '[Unreadable]';
}

function validateRawPath(rawPath, label = 'path') {
  if (typeof rawPath !== 'string' || rawPath.length === 0) {
    throw new VfsError(`${label} must be a non-empty string`, {
      code: ERROR_CODES.EINVAL,
      path: safeDisplay(rawPath ?? ''),
    });
  }
  if (rawPath.length > MAX_PATH_LENGTH) {
    throw new VfsError(`${label} exceeds maximum length (${MAX_PATH_LENGTH})`, {
      code: ERROR_CODES.EINVAL,
      path: rawPath.slice(0, 128),
    });
  }
  if (CONTROL_CHAR_RE.test(rawPath)) {
    throw new VfsError(`${label} contains NUL byte or ASCII control character`, {
      code: ERROR_CODES.EINVAL,
      path: rawPath.slice(0, 128),
    });
  }
}

function normalizePlatform(platform) {
  if (platform === undefined || platform === null || platform === '') {
    return PLATFORMS.POSIX;
  }
  if (typeof platform !== 'string') {
    throw new VfsError(`Invalid platform: ${safeDisplay(platform)}`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  if (platform.length > 64) {
    throw new VfsError(`Unsupported platform: ${safeDisplay(platform)}`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  const norm = platform.trim().toLowerCase();
  if (!VALID_PLATFORMS.has(norm)) {
    throw new VfsError(`Unsupported platform: ${safeDisplay(platform)}`, {
      code: ERROR_CODES.EINVAL,
    });
  }
  return norm;
}

/**
 * Collapses `.` and `..` segments on a POSIX path and returns a canonical `/` path.
 */
export function normalizePosixPath(input) {
  validateRawPath(input, 'path');
  const parts = input.split('/');
  const stack = [];
  for (const part of parts) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      if (stack.length > 0) stack.pop();
    } else {
      stack.push(part);
    }
  }
  return stack.length === 0 ? '/' : `/${stack.join('/')}`;
}

/**
 * Strict prefix-boundary containment check (`path === root || path.startsWith(root + '/')`).
 */
export function isPathWithinRoot(canonicalPath, sandboxRoot, opts = {}) {
  let caseInsensitive = false;
  if (opts !== null && opts !== undefined) {
    if (typeof opts !== 'object') {
      throw new VfsError('Invalid isPathWithinRoot options: expected object', {
        code: ERROR_CODES.EINVAL,
      });
    }
    try {
      caseInsensitive = Boolean(opts.caseInsensitive);
    } catch {
      throw new VfsError('Unreadable isPathWithinRoot options', {
        code: ERROR_CODES.EINVAL,
      });
    }
  }
  if (typeof canonicalPath !== 'string' || typeof sandboxRoot !== 'string') return false;
  if (canonicalPath.length > MAX_PATH_LENGTH || sandboxRoot.length > MAX_PATH_LENGTH) return false;
  if (!canonicalPath.startsWith('/') || !sandboxRoot.startsWith('/')) return false;
  const collapsedPath = canonicalPath.includes('//') ? canonicalPath.replace(/\/+/g, '/') : canonicalPath;
  const collapsedRoot = sandboxRoot.includes('//') ? sandboxRoot.replace(/\/+/g, '/') : sandboxRoot;
  const cleanPath =
    collapsedPath.length > 1 && collapsedPath.endsWith('/')
      ? collapsedPath.slice(0, -1)
      : collapsedPath;
  const cleanRoot =
    collapsedRoot.length > 1 && collapsedRoot.endsWith('/')
      ? collapsedRoot.slice(0, -1)
      : collapsedRoot;
  if (cleanRoot === '/') return cleanPath.startsWith('/');
  if (caseInsensitive) {
    const pLower = cleanPath.toLowerCase();
    const rLower = cleanRoot.toLowerCase();
    return pLower === rLower || pLower.startsWith(`${rLower}/`);
  }
  return cleanPath === cleanRoot || cleanPath.startsWith(`${cleanRoot}/`);
}

/**
 * Classifies a canonical path into its VFS mount name: `'proc' | 'dev' | 'tmp' | 'root'`.
 */
export function classifyMount(canonicalPath) {
  if (typeof canonicalPath !== 'string') return 'root';
  if (canonicalPath === '/proc' || canonicalPath.startsWith('/proc/')) return 'proc';
  if (canonicalPath === '/dev' || canonicalPath.startsWith('/dev/')) return 'dev';
  if (canonicalPath === '/tmp' || canonicalPath.startsWith('/tmp/')) return 'tmp';
  return 'root';
}

function matchPrefixCI(pathStr, prefixLower) {
  const lower = pathStr.toLowerCase();
  if (lower === prefixLower) {
    return { matched: true, rest: '' };
  }
  if (lower.startsWith(`${prefixLower}/`)) {
    return { matched: true, rest: pathStr.slice(prefixLower.length) };
  }
  return { matched: false, rest: '' };
}

function matchPrefixExact(pathStr, prefix) {
  if (pathStr === prefix) {
    return { matched: true, rest: '' };
  }
  if (pathStr.startsWith(`${prefix}/`)) {
    return { matched: true, rest: pathStr.slice(prefix.length) };
  }
  return { matched: false, rest: '' };
}

function stackToPosix(stack) {
  return stack.length === 0 ? '/' : `/${stack.join('/')}`;
}

function mapWindowsStack(driveLetter, stack) {
  const normRest = stackToPosix(stack);
  if (driveLetter === 'z') {
    return normRest;
  }
  if (driveLetter === 'c') {
    // Ordered strictly by prefix specificity (AppData MUST precede C:\Users\user)
    const rules = [
      { ciPrefix: '/users/user/appdata', canonicalBase: '/var/appdata/windows' },
      { ciPrefix: '/users/user', canonicalBase: '/home/user' },
      { ciPrefix: '/windows', canonicalBase: '/system/windows' },
      { ciPrefix: '/program files (x86)', canonicalBase: '/apps/windows' },
      { ciPrefix: '/program files', canonicalBase: '/apps/windows' },
      { ciPrefix: '/temp', canonicalBase: '/tmp' },
    ];
    for (const rule of rules) {
      const m = matchPrefixCI(normRest, rule.ciPrefix);
      if (m.matched) {
        return m.rest ? `${rule.canonicalBase}${m.rest}` : rule.canonicalBase;
      }
    }
    return normRest === '/' ? '/system/windows/drive_c' : `/system/windows/drive_c${normRest}`;
  }
  return normRest === '/' ? `/mnt/${driveLetter}` : `/mnt/${driveLetter}${normRest}`;
}

function mapMacosStack(stack) {
  const norm = stackToPosix(stack);
  // Prefix specificity: /Users/user/Library MUST precede /Users/user
  const mLib = matchPrefixCI(norm, '/users/user/library');
  if (mLib.matched) {
    return mLib.rest ? `/var/appdata/macos/Library${mLib.rest}` : '/var/appdata/macos/Library';
  }
  const mUser = matchPrefixCI(norm, '/users/user');
  if (mUser.matched) {
    return mUser.rest ? `/home/user${mUser.rest}` : '/home/user';
  }
  const mApps = matchPrefixCI(norm, '/applications');
  if (mApps.matched) {
    return mApps.rest ? `/apps/macos${mApps.rest}` : '/apps/macos';
  }
  const mPrivTmp = matchPrefixCI(norm, '/private/tmp');
  if (mPrivTmp.matched) {
    return mPrivTmp.rest ? `/tmp${mPrivTmp.rest}` : '/tmp';
  }
  const mSystem = matchPrefixExact(norm, '/System');
  if (mSystem.matched) {
    return mSystem.rest ? `/system/macos${mSystem.rest}` : '/system/macos';
  }
  return norm;
}

function mapAndroidStack(stack) {
  const norm = stackToPosix(stack);
  const mStorage = matchPrefixExact(norm, '/storage/emulated/0');
  if (mStorage.matched) {
    return mStorage.rest ? `/home/user${mStorage.rest}` : '/home/user';
  }
  const mSdcard = matchPrefixExact(norm, '/sdcard');
  if (mSdcard.matched) {
    return mSdcard.rest ? `/home/user${mSdcard.rest}` : '/home/user';
  }
  const mDataData = /^\/data\/data\/([^/]+)(\/.*)?$/.exec(norm);
  if (mDataData) {
    return `/var/appdata/android/${mDataData[1]}${mDataData[2] ?? ''}`;
  }
  const mDataUser = /^\/data\/user\/0\/([^/]+)(\/.*)?$/.exec(norm);
  if (mDataUser) {
    return `/var/appdata/android/${mDataUser[1]}${mDataUser[2] ?? ''}`;
  }
  const mSystem = matchPrefixExact(norm, '/system');
  if (mSystem.matched && !/^\/system\/(android|windows|macos|ios)(\/|$)/.test(norm)) {
    return mSystem.rest ? `/system/android${mSystem.rest}` : '/system/android';
  }
  return norm;
}

function mapIosStack(stack) {
  const norm = stackToPosix(stack);
  const mDataContainer = /^\/var\/mobile\/Containers\/Data\/Application\/([^/]+)(\/.*)?$/.exec(norm);
  if (mDataContainer) {
    return `/var/appdata/ios/${mDataContainer[1]}${mDataContainer[2] ?? ''}`;
  }
  const mBundleContainer = /^\/var\/containers\/Bundle\/Application\/([^/]+)(\/.*)?$/.exec(norm);
  if (mBundleContainer) {
    return `/apps/ios/${mBundleContainer[1]}${mBundleContainer[2] ?? ''}`;
  }
  const mDocs = matchPrefixExact(norm, '/var/mobile/Documents');
  if (mDocs.matched) {
    return mDocs.rest ? `/home/user/Documents${mDocs.rest}` : '/home/user/Documents';
  }
  const mDownloads = matchPrefixExact(norm, '/var/mobile/Downloads');
  if (mDownloads.matched) {
    return mDownloads.rest ? `/home/user/Downloads${mDownloads.rest}` : '/home/user/Downloads';
  }
  const mDesktop = matchPrefixExact(norm, '/var/mobile/Desktop');
  if (mDesktop.matched) {
    return mDesktop.rest ? `/home/user/Desktop${mDesktop.rest}` : '/home/user/Desktop';
  }
  const mPictures = matchPrefixExact(norm, '/var/mobile/Pictures');
  if (mPictures.matched) {
    return mPictures.rest ? `/home/user/Pictures${mPictures.rest}` : '/home/user/Pictures';
  }
  return norm;
}

function detectAndroidContainer(stack, curCanon, enforceExternalRoot) {
  const mApp = /^\/var\/appdata\/android\/([^/]+)(\/|$)/.exec(curCanon);
  if (mApp) {
    return {
      root: `/var/appdata/android/${mApp[1]}`,
      message: 'Path traversal outside Android app container',
      details: { container: mApp[1] },
    };
  }
  if (enforceExternalRoot) {
    if (stack[0] === 'sdcard') {
      return {
        root: '/home/user',
        message: 'Path traversal outside Android external storage root',
        details: { root: '/sdcard' },
      };
    }
    if (stack[0] === 'storage' && stack[1] === 'emulated' && stack[2] === '0') {
      return {
        root: '/home/user',
        message: 'Path traversal outside Android external storage root',
        details: { root: '/storage/emulated/0' },
      };
    }
  }
  return null;
}

function isForbiddenAndroidPop(stack) {
  if (stack.length === 2 && stack[0] === 'data' && stack[1] === 'data') {
    return { message: 'Path traversal outside Android app container' };
  }
  if (stack.length === 3 && stack[0] === 'data' && stack[1] === 'user' && stack[2] === '0') {
    return { message: 'Path traversal outside Android app container' };
  }
  return null;
}

function detectIosContainer(stack, curCanon) {
  void stack;
  const mData = /^\/var\/appdata\/ios\/([^/]+)(\/|$)/.exec(curCanon);
  if (mData) {
    return {
      root: `/var/appdata/ios/${mData[1]}`,
      message: 'Path traversal outside iOS app data container',
      details: { containerUuid: mData[1] },
    };
  }
  const mBundle = /^\/apps\/ios\/([^/]+)(\/|$)/.exec(curCanon);
  if (mBundle) {
    return {
      root: `/apps/ios/${mBundle[1]}`,
      message: 'Path traversal outside iOS app bundle container',
      details: { containerUuid: mBundle[1] },
    };
  }
  return null;
}

function isForbiddenIosPop(stack) {
  if (
    stack.length === 5 &&
    stack[0] === 'var' &&
    stack[1] === 'mobile' &&
    stack[2] === 'Containers' &&
    stack[3] === 'Data' &&
    stack[4] === 'Application'
  ) {
    return { message: 'Path traversal outside iOS app data container' };
  }
  if (
    stack.length === 4 &&
    stack[0] === 'var' &&
    stack[1] === 'containers' &&
    stack[2] === 'Bundle' &&
    stack[3] === 'Application'
  ) {
    return { message: 'Path traversal outside iOS app bundle container' };
  }
  return null;
}

/**
 * Walks raw segments step-by-step while mapping every intermediate prefix into canonical space,
 * enforcing inherent container jails AND explicit `sandboxRoot` entry/exit invariants at every step.
 */
function walkPlatformPathInternal({
  rawSegments,
  initialStack = [],
  mapStack = stackToPosix,
  cleanSandbox = null,
  caseInsensitive = false,
  originalPath,
  detectContainer = null,
  isForbiddenPop = null,
}) {
  const stack = initialStack.slice();
  const matchOpts = { caseInsensitive: Boolean(caseInsensitive) };

  let curCanon = mapStack(stack);
  let enteredSandbox = cleanSandbox ? isPathWithinRoot(curCanon, cleanSandbox, matchOpts) : false;
  let activeContainer = detectContainer ? detectContainer(stack, curCanon) : null;

  for (const seg of rawSegments) {
    if (seg === '' || seg === '.') continue;

    if (seg === '..') {
      if (isForbiddenPop) {
        const forbidden = isForbiddenPop(stack, curCanon);
        if (forbidden) {
          throw new VfsError(forbidden.message, {
            code: ERROR_CODES.EACCES,
            path: originalPath,
            details: {
              violation: ERROR_CODES.E_PATH_TRAVERSAL,
              ...(forbidden.details ?? {}),
            },
          });
        }
      }
      if (stack.length > 0) stack.pop();
    } else {
      stack.push(seg);
    }

    curCanon = mapStack(stack);

    if (activeContainer) {
      if (!isPathWithinRoot(curCanon, activeContainer.root, matchOpts)) {
        throw new VfsError(activeContainer.message, {
          code: ERROR_CODES.EACCES,
          path: originalPath,
          details: {
            violation: ERROR_CODES.E_PATH_TRAVERSAL,
            ...activeContainer.details,
            attemptedPath: curCanon,
          },
        });
      }
    } else if (detectContainer) {
      const detected = detectContainer(stack, curCanon);
      if (detected) {
        activeContainer = detected;
      }
    }

    if (cleanSandbox) {
      const inside = isPathWithinRoot(curCanon, cleanSandbox, matchOpts);
      if (enteredSandbox && !inside) {
        throw new VfsError(`Path traversal escapes sandbox root (${cleanSandbox})`, {
          code: ERROR_CODES.EACCES,
          path: originalPath,
          details: {
            violation: ERROR_CODES.E_PATH_TRAVERSAL,
            sandboxRoot: cleanSandbox,
            attemptedPath: curCanon,
          },
        });
      }
      if (inside) enteredSandbox = true;
    }
  }

  if (cleanSandbox && !isPathWithinRoot(curCanon, cleanSandbox, matchOpts)) {
    throw new VfsError(`Path traversal escapes sandbox root (${cleanSandbox})`, {
      code: ERROR_CODES.EACCES,
      path: originalPath,
      details: {
        violation: ERROR_CODES.E_PATH_TRAVERSAL,
        sandboxRoot: cleanSandbox,
        canonicalPath: curCanon,
      },
    });
  }

  return { canonicalPath: curCanon, stack };
}

function walkPlatformPath(opts) {
  return walkPlatformPathInternal(opts).canonicalPath;
}

export class PathTranslator {
  constructor(opts = {}) {
    let defaultUser = 'user';
    if (opts !== null && opts !== undefined) {
      if (typeof opts !== 'object') {
        throw new VfsError('Invalid PathTranslator constructor options', {
          code: ERROR_CODES.EINVAL,
        });
      }
      try {
        if (opts.defaultUser !== undefined) {
          defaultUser = opts.defaultUser;
        }
      } catch {
        throw new VfsError('Unreadable PathTranslator constructor options', {
          code: ERROR_CODES.EINVAL,
        });
      }
    }
    if (
      typeof defaultUser !== 'string' ||
      defaultUser.length === 0 ||
      defaultUser.length > 128 ||
      CONTROL_CHAR_RE.test(defaultUser)
    ) {
      throw new VfsError(
        'PathTranslator defaultUser must be a non-empty string (<= 128 chars, no control characters)',
        {
          code: ERROR_CODES.EINVAL,
        }
      );
    }
    this.defaultUser = defaultUser;
  }

  _canonicalizeCwd(cwd, platform) {
    if (typeof cwd !== 'string' || cwd.length === 0) {
      return '/home/user';
    }
    validateRawPath(cwd, 'cwd');
    const res = this.toCanonical(cwd, { platform, cwd: '/home/user', sandboxRoot: null });
    return res.canonicalPath;
  }

  _resolveNativeCwdStack(cwd, { mapStack, detectContainer = null, isForbiddenPop = null }) {
    if (typeof cwd !== 'string' || cwd.length === 0) {
      return ['home', 'user'];
    }
    validateRawPath(cwd, 'cwd');
    const initialStack = cwd.startsWith('/') ? [] : ['home', 'user'];
    const { stack } = walkPlatformPathInternal({
      rawSegments: cwd.split('/'),
      initialStack,
      mapStack,
      cleanSandbox: null,
      caseInsensitive: false,
      originalPath: cwd,
      detectContainer,
      isForbiddenPop,
    });
    return stack;
  }

  _canonicalizeSandboxRoot(sandboxRoot, platform) {
    if (sandboxRoot === null || sandboxRoot === undefined || sandboxRoot === '') {
      return null;
    }
    validateRawPath(sandboxRoot, 'sandboxRoot');
    const plat = normalizePlatform(platform);
    // Reject any `..` segment inside sandboxRoot itself rather than resolving/widening it
    let checkStr = sandboxRoot;
    if (plat === PLATFORMS.WINDOWS) {
      if (checkStr.startsWith('\\\\?\\') || checkStr.startsWith('//?/')) {
        checkStr = checkStr.slice(4);
      }
      checkStr = checkStr.replace(/^([a-zA-Z]):/, '$1/').replace(/\\/g, '/');
    }
    for (const seg of checkStr.split('/')) {
      if (seg === '..') {
        throw new VfsError('sandboxRoot must not contain parent directory traversal (..)', {
          code: ERROR_CODES.EACCES,
          path: sandboxRoot,
          details: {
            violation: ERROR_CODES.E_PATH_TRAVERSAL,
            sandboxRoot,
          },
        });
      }
    }
    const res = this.toCanonical(sandboxRoot, { platform: plat, cwd: '/', sandboxRoot: null });
    return res.canonicalPath;
  }

  toCanonical(rawPath, opts = {}) {
    validateRawPath(rawPath, 'path');
    let platform = 'posix';
    let cwd = '/home/user';
    let appId = '';
    let containerUuid = '';
    let sandboxRoot = null;
    if (opts !== null && opts !== undefined) {
      if (typeof opts !== 'object') {
        throw new VfsError('Invalid PathTranslator options', { code: ERROR_CODES.EINVAL, path: rawPath });
      }
      try {
        if (opts.platform !== undefined) platform = opts.platform;
        if (opts.cwd !== undefined) cwd = opts.cwd;
        if (opts.appId !== undefined) appId = opts.appId;
        if (opts.containerUuid !== undefined) containerUuid = opts.containerUuid;
        if (opts.sandboxRoot !== undefined) sandboxRoot = opts.sandboxRoot;
      } catch {
        throw new VfsError('Unreadable PathTranslator options', { code: ERROR_CODES.EINVAL, path: rawPath });
      }
    }
    const plat = normalizePlatform(platform);
    const caseInsensitive = CASE_INSENSITIVE_PLATFORMS.has(plat);
    const cleanSandbox = this._canonicalizeSandboxRoot(sandboxRoot, plat);

    let canonicalPath;

    if (plat === PLATFORMS.WINDOWS) {
      let work = rawPath;
      // Strip Win32 extended-length prefix \\?\ or //?/
      if (work.startsWith('\\\\?\\') || work.startsWith('//?/')) {
        work = work.slice(4);
        if (work.length === 0) {
          throw new VfsError('Invalid Windows extended path', {
            code: ERROR_CODES.EINVAL,
            path: rawPath,
          });
        }
      }

      const driveMatch = WINDOWS_DRIVE_RE.exec(work);
      if (driveMatch) {
        const drive = driveMatch[1].toLowerCase();
        const restSlash = driveMatch[2].replace(/\\/g, '/');
        canonicalPath = walkPlatformPath({
          rawSegments: restSlash.split('/'),
          initialStack: [],
          mapStack: (s) => mapWindowsStack(drive, s),
          cleanSandbox,
          caseInsensitive,
          originalPath: rawPath,
        });
      } else if (work.startsWith('\\')) {
        // Drive-relative root on C: (e.g. \Users\user\Documents)
        const restSlash = work.replace(/\\/g, '/');
        canonicalPath = walkPlatformPath({
          rawSegments: restSlash.split('/'),
          initialStack: [],
          mapStack: (s) => mapWindowsStack('c', s),
          cleanSandbox,
          caseInsensitive,
          originalPath: rawPath,
        });
      } else if (work.startsWith('/')) {
        // Already canonical POSIX path passed by a Windows process
        canonicalPath = walkPlatformPath({
          rawSegments: work.split('/'),
          initialStack: [],
          mapStack: stackToPosix,
          cleanSandbox,
          caseInsensitive,
          originalPath: rawPath,
        });
      } else {
        // Relative Windows path resolved against cwd
        const baseCwd = this._canonicalizeCwd(cwd, plat);
        const baseSegs = baseCwd.split('/').filter(Boolean);
        const relSegs = work.replace(/\\/g, '/').split('/');
        canonicalPath = walkPlatformPath({
          rawSegments: relSegs,
          initialStack: baseSegs,
          mapStack: stackToPosix,
          cleanSandbox,
          caseInsensitive,
          originalPath: rawPath,
        });
      }
    } else if (plat === PLATFORMS.MACOS) {
      if (rawPath.startsWith('/')) {
        canonicalPath = walkPlatformPath({
          rawSegments: rawPath.split('/'),
          initialStack: [],
          mapStack: mapMacosStack,
          cleanSandbox,
          caseInsensitive,
          originalPath: rawPath,
        });
      } else {
        const baseCwd = this._canonicalizeCwd(cwd, plat);
        const baseSegs = baseCwd.split('/').filter(Boolean);
        canonicalPath = walkPlatformPath({
          rawSegments: rawPath.split('/'),
          initialStack: baseSegs,
          mapStack: stackToPosix,
          cleanSandbox,
          caseInsensitive,
          originalPath: rawPath,
        });
      }
    } else if (plat === PLATFORMS.ANDROID) {
      const enforceExternal = Boolean(appId || cleanSandbox);
      const androidDetect = (s, c) => detectAndroidContainer(s, c, enforceExternal);
      if (rawPath.startsWith('/')) {
        canonicalPath = walkPlatformPath({
          rawSegments: rawPath.split('/'),
          initialStack: [],
          mapStack: mapAndroidStack,
          cleanSandbox,
          caseInsensitive,
          originalPath: rawPath,
          detectContainer: androidDetect,
          isForbiddenPop: isForbiddenAndroidPop,
        });
      } else {
        const cwdStack = this._resolveNativeCwdStack(cwd, {
          mapStack: mapAndroidStack,
          detectContainer: androidDetect,
          isForbiddenPop: isForbiddenAndroidPop,
        });
        canonicalPath = walkPlatformPath({
          rawSegments: rawPath.split('/'),
          initialStack: cwdStack,
          mapStack: mapAndroidStack,
          cleanSandbox,
          caseInsensitive,
          originalPath: rawPath,
          detectContainer: androidDetect,
          isForbiddenPop: isForbiddenAndroidPop,
        });
      }
    } else if (plat === PLATFORMS.IOS) {
      if (rawPath.startsWith('/')) {
        canonicalPath = walkPlatformPath({
          rawSegments: rawPath.split('/'),
          initialStack: [],
          mapStack: mapIosStack,
          cleanSandbox,
          caseInsensitive,
          originalPath: rawPath,
          detectContainer: detectIosContainer,
          isForbiddenPop: isForbiddenIosPop,
        });
      } else {
        const cwdStack = this._resolveNativeCwdStack(cwd, {
          mapStack: mapIosStack,
          detectContainer: detectIosContainer,
          isForbiddenPop: isForbiddenIosPop,
        });
        canonicalPath = walkPlatformPath({
          rawSegments: rawPath.split('/'),
          initialStack: cwdStack,
          mapStack: mapIosStack,
          cleanSandbox,
          caseInsensitive,
          originalPath: rawPath,
          detectContainer: detectIosContainer,
          isForbiddenPop: isForbiddenIosPop,
        });
      }
    } else {
      // POSIX or Universal
      if (rawPath.startsWith('/')) {
        canonicalPath = walkPlatformPath({
          rawSegments: rawPath.split('/'),
          initialStack: [],
          mapStack: stackToPosix,
          cleanSandbox,
          caseInsensitive,
          originalPath: rawPath,
        });
      } else {
        const baseCwd = this._canonicalizeCwd(cwd, plat);
        const baseSegs = baseCwd.split('/').filter(Boolean);
        canonicalPath = walkPlatformPath({
          rawSegments: rawPath.split('/'),
          initialStack: baseSegs,
          mapStack: stackToPosix,
          cleanSandbox,
          caseInsensitive,
          originalPath: rawPath,
        });
      }
    }

    // Keep containerUuid/appId referenced cleanly (available for diagnostics if needed)
    void containerUuid;

    return {
      canonicalPath,
      mount: classifyMount(canonicalPath),
      caseInsensitive,
      originalPath: rawPath,
    };
  }

  toPlatform(canonicalPath, platform = 'posix', opts = {}) {
    void opts;
    validateRawPath(canonicalPath, 'canonicalPath');
    const plat = normalizePlatform(platform);
    const norm = normalizePosixPath(canonicalPath);

    if (plat === PLATFORMS.POSIX || plat === PLATFORMS.UNIVERSAL) {
      return norm;
    }

    if (plat === PLATFORMS.WINDOWS) {
      const toWinRest = (rest) => rest.replace(/\//g, '\\');

      const mAppData = matchPrefixExact(norm, '/var/appdata/windows');
      if (mAppData.matched) {
        return `C:\\Users\\${this.defaultUser}\\AppData${toWinRest(mAppData.rest)}`;
      }
      const mHome = matchPrefixExact(norm, '/home/user');
      if (mHome.matched) {
        return `C:\\Users\\${this.defaultUser}${toWinRest(mHome.rest)}`;
      }
      const mDriveC = matchPrefixExact(norm, '/system/windows/drive_c');
      if (mDriveC.matched) {
        return mDriveC.rest ? `C:${toWinRest(mDriveC.rest)}` : 'C:\\';
      }
      const mWin = matchPrefixExact(norm, '/system/windows');
      if (mWin.matched) {
        return `C:\\Windows${toWinRest(mWin.rest)}`;
      }
      const mApps = matchPrefixExact(norm, '/apps/windows');
      if (mApps.matched) {
        return `C:\\Program Files${toWinRest(mApps.rest)}`;
      }
      const mMnt = /^\/mnt\/([a-y])(\/.*)?$/.exec(norm);
      if (mMnt) {
        const driveUpper = mMnt[1].toUpperCase();
        const rest = mMnt[2] ?? '';
        return rest ? `${driveUpper}:${toWinRest(rest)}` : `${driveUpper}:\\`;
      }
      if (norm === '/') {
        return 'Z:\\';
      }
      return `Z:${toWinRest(norm)}`;
    }

    if (plat === PLATFORMS.MACOS) {
      const mLib = matchPrefixExact(norm, '/var/appdata/macos/Library');
      if (mLib.matched) {
        return `/Users/${this.defaultUser}/Library${mLib.rest}`;
      }
      const mHome = matchPrefixExact(norm, '/home/user');
      if (mHome.matched) {
        return `/Users/${this.defaultUser}${mHome.rest}`;
      }
      const mApps = matchPrefixExact(norm, '/apps/macos');
      if (mApps.matched) {
        return `/Applications${mApps.rest}`;
      }
      const mSys = matchPrefixExact(norm, '/system/macos');
      if (mSys.matched) {
        return `/System${mSys.rest}`;
      }
      return norm;
    }

    if (plat === PLATFORMS.ANDROID) {
      const mHome = matchPrefixExact(norm, '/home/user');
      if (mHome.matched) {
        return `/sdcard${mHome.rest}`;
      }
      const mAppData = /^\/var\/appdata\/android\/([^/]+)(\/.*)?$/.exec(norm);
      if (mAppData) {
        return `/data/data/${mAppData[1]}${mAppData[2] ?? ''}`;
      }
      const mSys = matchPrefixExact(norm, '/system/android');
      if (mSys.matched) {
        return `/system${mSys.rest}`;
      }
      return norm;
    }

    if (plat === PLATFORMS.IOS) {
      const mDocs = matchPrefixExact(norm, '/home/user/Documents');
      if (mDocs.matched) {
        return `/var/mobile/Documents${mDocs.rest}`;
      }
      const mDownloads = matchPrefixExact(norm, '/home/user/Downloads');
      if (mDownloads.matched) {
        return `/var/mobile/Downloads${mDownloads.rest}`;
      }
      const mDesktop = matchPrefixExact(norm, '/home/user/Desktop');
      if (mDesktop.matched) {
        return `/var/mobile/Desktop${mDesktop.rest}`;
      }
      const mPictures = matchPrefixExact(norm, '/home/user/Pictures');
      if (mPictures.matched) {
        return `/var/mobile/Pictures${mPictures.rest}`;
      }
      const mAppData = /^\/var\/appdata\/ios\/([^/]+)(\/.*)?$/.exec(norm);
      if (mAppData) {
        return `/var/mobile/Containers/Data/Application/${mAppData[1]}${mAppData[2] ?? ''}`;
      }
      const mBundle = /^\/apps\/ios\/([^/]+)(\/.*)?$/.exec(norm);
      if (mBundle) {
        return `/var/containers/Bundle/Application/${mBundle[1]}${mBundle[2] ?? ''}`;
      }
      return norm;
    }

    return norm;
  }
}

export function createPathTranslator(options = {}) {
  return new PathTranslator(options);
}
