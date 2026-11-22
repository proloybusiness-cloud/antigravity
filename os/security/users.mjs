/**
 * OmniOS Security — Users, Groups, Sandbox UIDs (10000+) & POSIX ACL Evaluator (F-027)
 * Zero-dependency Node.js 24 ESM module backed by WAL SQLite (`security_users` namespace).
 */

import { types } from 'node:util';
import { SqliteStorage } from '../common/storage-sqlite.mjs';
import { OmniOSError, SecurityError, ERROR_CODES } from '../common/errors.mjs';

function freezeLookup(obj) {
  return Object.freeze(Object.assign(Object.create(null), obj));
}

export const ROOT_UID = 0;
export const ROOT_GID = 0;
export const DEFAULT_USER_UID = 1000;
export const DEFAULT_USER_GID = 1000;
export const SANDBOX_UID_BASE = 10000;
export const SANDBOX_GID_BASE = 10000;

export const ACCESS_MODES = freezeLookup({
  F_OK: 0,
  X_OK: 1,
  W_OK: 2,
  R_OK: 4,
});

export const SPECIAL_BITS = freezeLookup({
  S_ISUID: 0o4000,
  S_ISGID: 0o2000,
  S_ISVTX: 0o1000,
});

const PROTECTED_UIDS = Object.freeze(new Set([ROOT_UID, DEFAULT_USER_UID]));
const PROTECTED_GIDS = Object.freeze(new Set([ROOT_GID, 10, 20, DEFAULT_USER_GID]));

const CONTROL_CHAR_RE = /[\x00-\x1f\x7f]/;
const RESOLVED_ACTOR_SYM = Symbol('OmniOS.UserManager.resolvedActor');

export const USER_MIGRATIONS = Object.freeze([
  Object.freeze({
    version: 1,
    name: 'security_users_initial',
    sql: `
      CREATE TABLE IF NOT EXISTS security_users (
        uid INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        gid INTEGER NOT NULL,
        home TEXT NOT NULL,
        shell TEXT NOT NULL DEFAULT '/bin/sh',
        app_id TEXT UNIQUE,
        platform TEXT,
        sandbox_root TEXT,
        strict_sandbox INTEGER NOT NULL DEFAULT 0,
        is_system INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS security_groups (
        gid INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS security_group_members (
        gid INTEGER NOT NULL,
        uid INTEGER NOT NULL,
        PRIMARY KEY (gid, uid),
        FOREIGN KEY (gid) REFERENCES security_groups(gid) ON DELETE CASCADE,
        FOREIGN KEY (uid) REFERENCES security_users(uid) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_security_users_app_id ON security_users(app_id);
    `,
  }),
]);

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

function safeIsArray(value) {
  try {
    return Array.isArray(value);
  } catch {
    return null;
  }
}

function assertNonNegativeInt(val, label) {
  if (typeof val !== 'number' || !Number.isSafeInteger(val) || val < 0) {
    throw new SecurityError(`Invalid ${label}: expected non-negative safe integer`, {
      code: ERROR_CODES.EINVAL,
      details: { field: label },
    });
  }
  return val;
}

function assertSafeIdentifier(val, label, maxLen = 128) {
  if (
    typeof val !== 'string' ||
    val.length === 0 ||
    val.length > maxLen ||
    CONTROL_CHAR_RE.test(val) ||
    val.includes('/') ||
    val.includes('\\')
  ) {
    throw new SecurityError(`Invalid ${label}`, {
      code: ERROR_CODES.EINVAL,
      details: { field: label },
    });
  }
  return val;
}

function assertSafeAppId(appId) {
  assertSafeIdentifier(appId, 'appId', 256);
  if (appId === '.' || appId === '..' || appId.includes('..')) {
    throw new SecurityError(`Invalid appId (path traversal sequence rejected): ${appId}`, {
      code: ERROR_CODES.EINVAL,
      appId,
      details: { violation: ERROR_CODES.E_PATH_TRAVERSAL },
    });
  }
  return appId;
}

function normalizePlatformName(rawPlatform, label = 'platform') {
  if (typeof rawPlatform !== 'string') {
    throw new SecurityError(`Invalid ${label}: expected string`, {
      code: ERROR_CODES.EINVAL,
      details: { field: label },
    });
  }
  if (rawPlatform.length > 128) {
    throw new SecurityError(`Invalid ${label}: ${safeDisplay(rawPlatform)}`, {
      code: ERROR_CODES.EINVAL,
      details: { field: label },
    });
  }
  const norm = rawPlatform.trim().toLowerCase();
  if (norm.length === 0 || norm === '.' || norm === '..' || norm.includes('..')) {
    throw new SecurityError(`Invalid ${label}: ${safeDisplay(norm)}`, {
      code: ERROR_CODES.EINVAL,
      details: { field: label, violation: ERROR_CODES.E_PATH_TRAVERSAL },
    });
  }
  return assertSafeIdentifier(norm, label, 64);
}

function normalizeRootPath(root) {
  if (
    typeof root !== 'string' ||
    root.length === 0 ||
    root.length > 4096 ||
    !root.startsWith('/') ||
    CONTROL_CHAR_RE.test(root)
  ) {
    throw new SecurityError('Invalid path: expected canonical absolute path', {
      code: ERROR_CODES.EINVAL,
      details: { path: safeDisplay(root ?? '') },
    });
  }
  const segments = root.split('/');
  const cleanSegs = [];
  for (const seg of segments) {
    if (seg === '..') {
      throw new SecurityError('Sandbox root must not contain ".." segments', {
        code: ERROR_CODES.EINVAL,
        details: { violation: ERROR_CODES.E_PATH_TRAVERSAL, path: safeDisplay(root) },
      });
    }
    if (seg !== '' && seg !== '.') {
      cleanSegs.push(seg);
    }
  }
  return cleanSegs.length === 0 ? '/' : `/${cleanSegs.join('/')}`;
}

/**
 * Strict prefix-boundary containment check preventing `/var/appdata/ios/app1-evil`
 * from matching `/var/appdata/ios/app1`.
 */
export function isWithinRoot(canonicalPath, root, opts = {}) {
  let caseInsensitive = false;
  if (opts !== null && opts !== undefined) {
    if (typeof opts !== 'object') {
      throw new SecurityError('Invalid isWithinRoot options: expected object', {
        code: ERROR_CODES.EINVAL,
      });
    }
    try {
      caseInsensitive = Boolean(opts.caseInsensitive);
    } catch {
      throw new SecurityError('Unreadable isWithinRoot options', {
        code: ERROR_CODES.EINVAL,
      });
    }
  }
  if (typeof canonicalPath !== 'string' || typeof root !== 'string') return false;
  if (canonicalPath.length > 4096 || root.length > 4096) return false;
  if (!canonicalPath.startsWith('/') || !root.startsWith('/')) return false;
  const pathParts = canonicalPath.split('/');
  const rootParts = root.split('/');
  const cleanPathSegs = [];
  for (const seg of pathParts) {
    if (seg === '..') return false;
    if (seg !== '' && seg !== '.') cleanPathSegs.push(seg);
  }
  const cleanRootSegs = [];
  for (const seg of rootParts) {
    if (seg === '..') return false;
    if (seg !== '' && seg !== '.') cleanRootSegs.push(seg);
  }
  const cleanPath = cleanPathSegs.length === 0 ? '/' : `/${cleanPathSegs.join('/')}`;
  const cleanRoot = cleanRootSegs.length === 0 ? '/' : `/${cleanRootSegs.join('/')}`;
  if (cleanRoot === '/') return cleanPath.startsWith('/');
  if (caseInsensitive) {
    const pLower = cleanPath.toLowerCase();
    const rLower = cleanRoot.toLowerCase();
    return pLower === rLower || pLower.startsWith(`${rLower}/`);
  }
  return cleanPath === cleanRoot || cleanPath.startsWith(`${cleanRoot}/`);
}

function cloneUserRecord(rec, gids) {
  return {
    uid: rec.uid,
    username: rec.username,
    gid: rec.gid,
    gids: Array.isArray(gids) ? gids.slice() : [rec.gid],
    home: rec.home,
    shell: rec.shell,
    appId: rec.appId,
    platform: rec.platform,
    sandboxRoot: rec.sandboxRoot,
    strictSandbox: rec.strictSandbox,
    isSystem: rec.isSystem,
    createdAt: rec.createdAt,
  };
}

function cloneGroupRecord(rec, members) {
  return {
    gid: rec.gid,
    name: rec.name,
    members: Array.isArray(members) ? members.slice() : [],
    createdAt: rec.createdAt,
  };
}

export class UserManager {
  constructor(opts = {}) {
    let storage = null;
    let getStorage = null;
    let kernel = null;
    let eventBus = null;
    if (opts !== null && opts !== undefined) {
      if (typeof opts !== 'object') {
        throw new SecurityError('Invalid UserManager constructor options: expected object', {
          code: ERROR_CODES.EINVAL,
        });
      }
      try {
        if (opts.storage !== undefined) storage = opts.storage;
        if (opts.getStorage !== undefined) getStorage = opts.getStorage;
        if (opts.kernel !== undefined) kernel = opts.kernel;
        if (opts.eventBus !== undefined) eventBus = opts.eventBus;
      } catch {
        throw new SecurityError('Unreadable UserManager constructor options', {
          code: ERROR_CODES.EINVAL,
        });
      }
    }

    if (kernel !== null && kernel !== undefined && typeof kernel !== 'object') {
      throw new SecurityError('Invalid UserManager kernel dependency', { code: ERROR_CODES.EINVAL });
    }
    if (storage !== null && storage !== undefined && typeof storage !== 'object') {
      throw new SecurityError('Invalid UserManager storage dependency', { code: ERROR_CODES.EINVAL });
    }
    if (eventBus !== null && eventBus !== undefined && typeof eventBus !== 'object') {
      throw new SecurityError('Invalid UserManager eventBus dependency', { code: ERROR_CODES.EINVAL });
    }

    let kernelEventBus = null;
    let kernelStorage = null;
    let kernelStorageOpen = false;
    let storageOpen = false;
    try {
      if (kernel !== null && kernel !== undefined) {
        kernelEventBus = kernel.eventBus ?? null;
        kernelStorage = kernel.storage ?? null;
        kernelStorageOpen = Boolean(kernelStorage?.isOpen);
      }
      if (storage !== null && storage !== undefined) {
        storageOpen = Boolean(storage.isOpen);
      }
      const resolvedEventBus = eventBus ?? kernelEventBus ?? null;
      if (resolvedEventBus !== null && resolvedEventBus !== undefined) {
        if (typeof resolvedEventBus !== 'object' || typeof resolvedEventBus.emit !== 'function') {
          throw new SecurityError('Invalid UserManager eventBus dependency: missing emit()', {
            code: ERROR_CODES.EINVAL,
          });
        }
      }
    } catch (err) {
      if (err instanceof OmniOSError) throw err;
      throw new SecurityError('Unreadable UserManager dependency option', {
        code: ERROR_CODES.EINVAL,
      });
    }

    this._kernel = kernel;
    this._getStorage = typeof getStorage === 'function' ? getStorage : null;
    this._eventBus = eventBus ?? kernelEventBus ?? null;
    this._storage = storage;
    this._ownsStorage = false;
    this._initialized = false;

    // Prototype-safe in-memory caches hydrated from SQLite
    this._usersByUid = new Map();
    this._usersByName = new Map();
    this._usersByAppId = new Map();
    this._groupsByGid = new Map();
    this._groupsByName = new Map();
    this._userGroups = new Map(); // uid -> Set<gid>
    this._groupMembers = new Map(); // gid -> Set<uid>

    if (storageOpen) {
      this.init(storage);
    } else if (!storage && kernelStorageOpen) {
      this.init(kernelStorage);
    } else if (!storage && this._getStorage) {
      let candidate;
      let candidateOpen = false;
      try {
        candidate = this._getStorage();
        candidateOpen = Boolean(candidate?.isOpen);
      } catch (err) {
        if (err instanceof OmniOSError) throw err;
        throw new SecurityError('Unreadable UserManager getStorage() dependency', {
          code: ERROR_CODES.EINVAL,
        });
      }
      if (candidateOpen) {
        this.init(candidate);
      }
    } else if (!storage && !kernel && !this._getStorage) {
      this.init();
    }
  }

  get isReady() {
    try {
      return Boolean(this._initialized && this._storage?.isOpen);
    } catch {
      return false;
    }
  }

  init(storage = null) {
    let db;
    let isOpen = false;
    try {
      db =
        storage ??
        this._kernel?.storage ??
        (this._getStorage ? this._getStorage() : null) ??
        this._storage ??
        null;
    } catch (err) {
      if (err instanceof OmniOSError) throw err;
      throw new SecurityError('Unreadable storage dependency in UserManager.init()', {
        code: ERROR_CODES.EINVAL,
      });
    }

    let createdPrivate = false;
    if (!db && !this._kernel && !this._getStorage) {
      db = new SqliteStorage(':memory:');
      createdPrivate = true;
    }

    try {
      isOpen = Boolean(db && db.isOpen);
    } catch {
      throw new SecurityError('Unreadable storage in UserManager.init()', {
        code: ERROR_CODES.EINVAL,
      });
    }

    if (!isOpen) {
      throw new OmniOSError('UserManager requires an open SqliteStorage', {
        code: ERROR_CODES.E_STORAGE_CLOSED,
      });
    }

    if (createdPrivate) {
      this._ownsStorage = true;
    } else if (db !== this._storage) {
      if (this._ownsStorage && this._storage?.isOpen) {
        this._storage.close();
      }
      this._ownsStorage = false;
    }

    this._storage = db;
    if (!this._eventBus && this._kernel) {
      try {
        if (this._kernel.eventBus) {
          this._eventBus = this._kernel.eventBus;
        }
      } catch {
        // Ignore unreadable kernel.eventBus
      }
    }

    db.migrate('security_users', USER_MIGRATIONS);

    const now = new Date().toISOString();
    db.transaction((tx) => {
      const seedGroups = [
        [ROOT_GID, 'root'],
        [10, 'wheel'],
        [20, 'staff'],
        [DEFAULT_USER_GID, 'user'],
      ];
      for (const [gid, name] of seedGroups) {
        tx.run(
          'INSERT OR IGNORE INTO security_groups (gid, name, created_at) VALUES (?, ?, ?)',
          gid,
          name,
          now
        );
      }

      tx.run(
        `INSERT OR IGNORE INTO security_users
          (uid, username, gid, home, shell, app_id, platform, sandbox_root, strict_sandbox, is_system, created_at)
         VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, 0, 1, ?)`,
        ROOT_UID,
        'root',
        ROOT_GID,
        '/root',
        '/bin/sh',
        now
      );

      tx.run(
        `INSERT OR IGNORE INTO security_users
          (uid, username, gid, home, shell, app_id, platform, sandbox_root, strict_sandbox, is_system, created_at)
         VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, 0, 0, ?)`,
        DEFAULT_USER_UID,
        'user',
        DEFAULT_USER_GID,
        '/home/user',
        '/bin/sh',
        now
      );

      const memberships = [
        [ROOT_GID, ROOT_UID],
        [10, ROOT_UID],
        [20, ROOT_UID],
        [DEFAULT_USER_GID, DEFAULT_USER_UID],
        [20, DEFAULT_USER_UID],
      ];
      for (const [gid, uid] of memberships) {
        tx.run(
          'INSERT OR IGNORE INTO security_group_members (gid, uid) VALUES (?, ?)',
          gid,
          uid
        );
      }
    });

    this._reloadCaches();
    this._initialized = true;
    return this;
  }

  close() {
    if (this._ownsStorage && this._storage?.isOpen) {
      this._storage.close();
    }
    this._initialized = false;
  }

  _requireStorage() {
    let currentOpen = false;
    if (this._initialized && this._storage) {
      try {
        currentOpen = Boolean(this._storage.isOpen);
      } catch (err) {
        if (err instanceof OmniOSError) throw err;
        throw new SecurityError('Unreadable UserManager storage', {
          code: ERROR_CODES.EINVAL,
        });
      }
      if (currentOpen) {
        return this._storage;
      }
    }
    let lazy = null;
    let lazyOpen = false;
    try {
      lazy = this._kernel?.storage ?? (this._getStorage ? this._getStorage() : null);
      lazyOpen = Boolean(lazy?.isOpen);
    } catch (err) {
      if (err instanceof OmniOSError) throw err;
      throw new SecurityError('Unreadable UserManager storage dependency', {
        code: ERROR_CODES.EINVAL,
      });
    }
    if (lazyOpen) {
      this.init(lazy);
      return this._storage;
    }
    throw new OmniOSError('UserManager storage is not open or initialized', {
      code: ERROR_CODES.E_STORAGE_CLOSED,
    });
  }

  _reloadCaches() {
    const db = this._storage;
    this._usersByUid.clear();
    this._usersByName.clear();
    this._usersByAppId.clear();
    this._groupsByGid.clear();
    this._groupsByName.clear();
    this._userGroups.clear();
    this._groupMembers.clear();

    const groups = db.all('SELECT gid, name, created_at FROM security_groups ORDER BY gid ASC');
    for (const row of groups) {
      const grp = {
        gid: Number(row.gid),
        name: row.name,
        createdAt: row.created_at,
      };
      this._groupsByGid.set(grp.gid, grp);
      this._groupsByName.set(grp.name, grp);
      this._groupMembers.set(grp.gid, new Set());
    }

    const users = db.all(
      `SELECT uid, username, gid, home, shell, app_id, platform, sandbox_root,
              strict_sandbox, is_system, created_at
       FROM security_users
       ORDER BY uid ASC`
    );
    for (const row of users) {
      const rec = {
        uid: Number(row.uid),
        username: row.username,
        gid: Number(row.gid),
        home: row.home,
        shell: row.shell,
        appId: row.app_id ?? null,
        platform: row.platform ?? null,
        sandboxRoot: row.sandbox_root ?? null,
        strictSandbox: Boolean(row.strict_sandbox),
        isSystem: Boolean(row.is_system),
        createdAt: row.created_at,
      };
      this._usersByUid.set(rec.uid, rec);
      this._usersByName.set(rec.username, rec);
      if (rec.appId !== null) {
        this._usersByAppId.set(rec.appId, rec);
      }
      const gSet = new Set([rec.gid]);
      this._userGroups.set(rec.uid, gSet);
    }

    const members = db.all('SELECT gid, uid FROM security_group_members');
    for (const row of members) {
      const gid = Number(row.gid);
      const uid = Number(row.uid);
      let gSet = this._userGroups.get(uid);
      if (!gSet) {
        gSet = new Set();
        this._userGroups.set(uid, gSet);
      }
      gSet.add(gid);
      let mSet = this._groupMembers.get(gid);
      if (!mSet) {
        mSet = new Set();
        this._groupMembers.set(gid, mSet);
      }
      mSet.add(uid);
    }
  }

  _sortedGidsForUid(uid) {
    const rec = this._usersByUid.get(uid);
    const set = new Set();
    if (rec) set.add(rec.gid);
    const memberships = this._userGroups.get(uid);
    if (memberships) {
      for (const g of memberships) set.add(g);
    }
    if (set.size === 0) set.add(uid);
    return Array.from(set).sort((a, b) => a - b);
  }

  _emit(event, payload) {
    if (!this._eventBus) return;
    try {
      if (typeof this._eventBus.emit === 'function') {
        this._eventBus.emit(event, payload);
      }
    } catch {
      // Ignore revoked or throwing eventBus after state commit so mutations stay consistent
    }
  }

  // ---- User Queries ----

  getUserByUid(uid) {
    this._requireStorage();
    if (typeof uid !== 'number' || !Number.isSafeInteger(uid) || uid < 0) {
      return null;
    }
    const rec = this._usersByUid.get(uid);
    return rec ? cloneUserRecord(rec, this._sortedGidsForUid(rec.uid)) : null;
  }

  getUserByUsername(username) {
    this._requireStorage();
    if (typeof username !== 'string' || username.length === 0) return null;
    const rec = this._usersByName.get(username);
    return rec ? cloneUserRecord(rec, this._sortedGidsForUid(rec.uid)) : null;
  }

  getUserByAppId(appId) {
    this._requireStorage();
    if (typeof appId !== 'string' || appId.length === 0) return null;
    const rec = this._usersByAppId.get(appId);
    return rec ? cloneUserRecord(rec, this._sortedGidsForUid(rec.uid)) : null;
  }

  getAppUser(appId) {
    return this.getUserByAppId(appId);
  }

  getUser(uidOrUsername) {
    if (typeof uidOrUsername === 'number') {
      return this.getUserByUid(uidOrUsername);
    }
    if (typeof uidOrUsername === 'string') {
      return this.getUserByUsername(uidOrUsername);
    }
    return null;
  }

  listUsers(opts = {}) {
    this._requireStorage();
    let includeSystem = true;
    let sandboxOnly = false;
    if (opts !== null && opts !== undefined) {
      if (typeof opts !== 'object') {
        throw new SecurityError('Invalid listUsers options: expected object', {
          code: ERROR_CODES.EINVAL,
        });
      }
      try {
        if (opts.includeSystem !== undefined) includeSystem = Boolean(opts.includeSystem);
        if (opts.sandboxOnly !== undefined) sandboxOnly = Boolean(opts.sandboxOnly);
      } catch {
        throw new SecurityError('Unreadable listUsers options', {
          code: ERROR_CODES.EINVAL,
        });
      }
    }
    const out = [];
    for (const rec of this._usersByUid.values()) {
      if (!includeSystem && rec.isSystem) continue;
      if (sandboxOnly && rec.uid < SANDBOX_UID_BASE && rec.appId === null) continue;
      out.push(cloneUserRecord(rec, this._sortedGidsForUid(rec.uid)));
    }
    out.sort((a, b) => a.uid - b.uid);
    return out;
  }

  // ---- User Mutation ----

  createUser(opts = {}) {
    const db = this._requireStorage();
    if (opts === null || opts === undefined || typeof opts !== 'object') {
      throw new SecurityError('Invalid createUser options', { code: ERROR_CODES.EINVAL });
    }
    let uid = null;
    let username;
    let gid = null;
    let home = null;
    let shell = '/bin/sh';
    let appId = null;
    let platform = null;
    let sandboxRoot = null;
    let strictSandbox = false;
    let isSystem = false;
    let groups = [];
    try {
      if (opts.uid !== undefined) uid = opts.uid;
      username = opts.username;
      if (opts.gid !== undefined) gid = opts.gid;
      if (opts.home !== undefined) home = opts.home;
      if (opts.shell !== undefined) shell = opts.shell;
      if (opts.appId !== undefined) appId = opts.appId;
      if (opts.platform !== undefined) platform = opts.platform;
      if (opts.sandboxRoot !== undefined) sandboxRoot = opts.sandboxRoot;
      if (opts.strictSandbox !== undefined) strictSandbox = opts.strictSandbox;
      if (opts.isSystem !== undefined) isSystem = opts.isSystem;
      if (opts.groups !== undefined) groups = opts.groups;
    } catch {
      throw new SecurityError('Unreadable createUser options', { code: ERROR_CODES.EINVAL });
    }

    assertSafeIdentifier(username, 'username', 128);
    if (username === '.' || username === '..') {
      throw new SecurityError('Invalid username', {
        code: ERROR_CODES.EINVAL,
        details: { field: 'username', violation: ERROR_CODES.E_PATH_TRAVERSAL },
      });
    }
    if (this._usersByName.has(username)) {
      throw new SecurityError(`User already exists: ${username}`, {
        code: ERROR_CODES.EEXIST,
      });
    }

    if (appId !== null && appId !== undefined) {
      assertSafeAppId(appId);
      if (this._usersByAppId.has(appId)) {
        throw new SecurityError(`App sandbox user already exists for appId: ${appId}`, {
          code: ERROR_CODES.EEXIST,
          appId,
        });
      }
    }

    if (typeof shell !== 'string' || shell.length === 0 || shell.length > 4096 || CONTROL_CHAR_RE.test(shell)) {
      throw new SecurityError('Invalid shell path', { code: ERROR_CODES.EINVAL });
    }

    let finalSandboxRoot = null;
    if (sandboxRoot !== null && sandboxRoot !== undefined) {
      finalSandboxRoot = normalizeRootPath(sandboxRoot);
    }

    let finalPlatform = null;
    if (platform !== null && platform !== undefined) {
      finalPlatform = normalizePlatformName(platform, 'platform');
    }

    let finalUid;
    if (uid !== null && uid !== undefined) {
      finalUid = assertNonNegativeInt(uid, 'uid');
      if (this._usersByUid.has(finalUid)) {
        throw new SecurityError(`UID already in use: ${finalUid}`, {
          code: ERROR_CODES.EEXIST,
        });
      }
    } else if (appId !== null && appId !== undefined) {
      let maxSandbox = SANDBOX_UID_BASE - 1;
      for (const existingUid of this._usersByUid.keys()) {
        if (existingUid > maxSandbox) maxSandbox = existingUid;
      }
      finalUid = maxSandbox + 1;
    } else {
      let candidate = DEFAULT_USER_UID + 1;
      while (this._usersByUid.has(candidate) && candidate < SANDBOX_UID_BASE) {
        candidate += 1;
      }
      if (candidate >= SANDBOX_UID_BASE) {
        while (this._usersByUid.has(candidate)) candidate += 1;
      }
      finalUid = candidate;
    }

    let finalGid;
    let createPrimaryGroup = false;
    if (gid !== null && gid !== undefined) {
      finalGid = assertNonNegativeInt(gid, 'gid');
      if (!this._groupsByGid.has(finalGid)) {
        createPrimaryGroup = true;
      }
    } else {
      finalGid = finalUid;
      if (this._groupsByGid.has(finalGid)) {
        while (this._groupsByGid.has(finalGid)) finalGid += 1;
      }
      createPrimaryGroup = true;
    }

    const finalHome = normalizeRootPath(
      home !== null && home !== undefined
        ? home
        : finalSandboxRoot ?? `/home/${username}`
    );

    if (safeIsArray(groups) !== true) {
      throw new SecurityError('groups must be an array', { code: ERROR_CODES.EINVAL });
    }
    let groupsLen;
    try {
      groupsLen = groups.length;
    } catch {
      throw new SecurityError('Unreadable groups array', { code: ERROR_CODES.EINVAL });
    }
    if (typeof groupsLen !== 'number' || !Number.isSafeInteger(groupsLen) || groupsLen < 0 || groupsLen > 4096) {
      throw new SecurityError('Invalid groups array length', { code: ERROR_CODES.EINVAL });
    }

    const resolvedExtraGids = [];
    for (let i = 0; i < groupsLen; i += 1) {
      let g;
      try {
        g = groups[i];
      } catch {
        throw new SecurityError('Unreadable group entry', { code: ERROR_CODES.EINVAL });
      }
      const grp = typeof g === 'number' ? this._groupsByGid.get(g) : typeof g === 'string' ? this._groupsByName.get(g) : null;
      if (!grp) {
        throw new SecurityError(`Group not found: ${safeDisplay(g)}`, { code: ERROR_CODES.ENOENT });
      }
      resolvedExtraGids.push(grp.gid);
    }

    const now = new Date().toISOString();
    db.transaction((tx) => {
      if (createPrimaryGroup) {
        let groupName = username;
        if (this._groupsByName.has(groupName)) {
          groupName = `grp_${finalGid}`;
          let suffix = 1;
          while (this._groupsByName.has(groupName)) {
            groupName = `grp_${finalGid}_${suffix++}`;
          }
        }
        tx.run(
          'INSERT INTO security_groups (gid, name, created_at) VALUES (?, ?, ?)',
          finalGid,
          groupName,
          now
        );
      }

      tx.run(
        `INSERT INTO security_users
          (uid, username, gid, home, shell, app_id, platform, sandbox_root, strict_sandbox, is_system, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        finalUid,
        username,
        finalGid,
        finalHome,
        shell,
        appId ?? null,
        finalPlatform,
        finalSandboxRoot,
        strictSandbox ? 1 : 0,
        isSystem ? 1 : 0,
        now
      );

      tx.run(
        'INSERT OR IGNORE INTO security_group_members (gid, uid) VALUES (?, ?)',
        finalGid,
        finalUid
      );
      for (const extraGid of resolvedExtraGids) {
        tx.run(
          'INSERT OR IGNORE INTO security_group_members (gid, uid) VALUES (?, ?)',
          extraGid,
          finalUid
        );
      }
    });

    this._reloadCaches();
    const created = this.getUserByUid(finalUid);
    this._emit('security:user_created', {
      uid: created.uid,
      gid: created.gid,
      username: created.username,
      appId: created.appId,
      sandboxRoot: created.sandboxRoot,
    });
    return created;
  }

  deleteUser(uid) {
    const db = this._requireStorage();
    assertNonNegativeInt(uid, 'uid');
    if (PROTECTED_UIDS.has(uid)) {
      throw new SecurityError(`Cannot delete protected system user UID ${uid}`, {
        code: ERROR_CODES.EPERM,
      });
    }
    const existing = this._usersByUid.get(uid);
    if (!existing) return false;

    db.transaction((tx) => {
      tx.run('DELETE FROM security_users WHERE uid = ?', uid);
    });

    this._reloadCaches();
    this._emit('security:user_deleted', {
      uid: existing.uid,
      username: existing.username,
      appId: existing.appId,
    });
    return true;
  }

  // ---- Per-App Sandbox UID Allocation (10000+) ----

  allocateAppUid(appId, opts = {}) {
    const db = this._requireStorage();
    assertSafeAppId(appId);

    let platform = 'posix';
    let sandboxRoot = null;
    let containerUuid = null;
    let strictSandbox = false;
    if (opts !== null && opts !== undefined) {
      if (typeof opts !== 'object') {
        throw new SecurityError('Invalid allocateAppUid options', { code: ERROR_CODES.EINVAL });
      }
      try {
        if (opts.platform !== undefined) platform = opts.platform;
        if (opts.sandboxRoot !== undefined) sandboxRoot = opts.sandboxRoot;
        if (opts.containerUuid !== undefined) containerUuid = opts.containerUuid;
        if (opts.strictSandbox !== undefined) strictSandbox = opts.strictSandbox;
      } catch {
        throw new SecurityError('Unreadable allocateAppUid options', { code: ERROR_CODES.EINVAL });
      }
    }

    const cleanPlatform =
      platform === null || platform === undefined
        ? 'posix'
        : normalizePlatformName(platform, 'platform');

    let cleanUuid = null;
    if (containerUuid !== null && containerUuid !== undefined && containerUuid !== '') {
      if (typeof containerUuid !== 'string') {
        throw new SecurityError('Invalid containerUuid: expected string', { code: ERROR_CODES.EINVAL });
      }
      cleanUuid = assertSafeAppId(containerUuid);
    }

    let rawSandboxRoot;
    if (sandboxRoot !== null && sandboxRoot !== undefined && sandboxRoot !== '') {
      rawSandboxRoot = sandboxRoot;
    } else if (cleanPlatform === 'android') {
      rawSandboxRoot = `/var/appdata/android/${appId}`;
    } else if (cleanPlatform === 'ios') {
      rawSandboxRoot = `/var/appdata/ios/${cleanUuid || appId}`;
    } else if (cleanPlatform === 'macos') {
      rawSandboxRoot = `/var/appdata/macos/${appId}`;
    } else if (cleanPlatform === 'windows') {
      rawSandboxRoot = `/var/appdata/windows/${appId}`;
    } else {
      rawSandboxRoot = `/var/appdata/${cleanPlatform}/${appId}`;
    }
    const finalSandboxRoot = normalizeRootPath(rawSandboxRoot);
    const finalHome = normalizeRootPath(finalSandboxRoot);

    const existing = this._usersByAppId.get(appId);
    if (existing) {
      return cloneUserRecord(existing, this._sortedGidsForUid(existing.uid));
    }

    const now = new Date().toISOString();
    let allocatedUid;
    db.transaction((tx) => {
      const maxUserRow = tx.get('SELECT COALESCE(MAX(uid), 0) AS m FROM security_users');
      const maxGroupRow = tx.get('SELECT COALESCE(MAX(gid), 0) AS m FROM security_groups');
      const highWater = Math.max(
        SANDBOX_UID_BASE - 1,
        Number(maxUserRow?.m ?? 0),
        Number(maxGroupRow?.m ?? 0)
      );
      allocatedUid = highWater + 1;
      const allocatedGid = allocatedUid;

      let username = `app_${allocatedUid}`;
      let attempt = 1;
      while (this._usersByName.has(username) || this._groupsByName.has(username)) {
        username = `app_${allocatedUid}_${attempt++}`;
      }

      tx.run(
        'INSERT INTO security_groups (gid, name, created_at) VALUES (?, ?, ?)',
        allocatedGid,
        username,
        now
      );

      tx.run(
        `INSERT INTO security_users
          (uid, username, gid, home, shell, app_id, platform, sandbox_root, strict_sandbox, is_system, created_at)
         VALUES (?, ?, ?, ?, '/bin/sh', ?, ?, ?, ?, 0, ?)`,
        allocatedUid,
        username,
        allocatedGid,
        finalHome,
        appId,
        cleanPlatform,
        finalSandboxRoot,
        strictSandbox ? 1 : 0,
        now
      );

      tx.run(
        'INSERT OR IGNORE INTO security_group_members (gid, uid) VALUES (?, ?)',
        allocatedGid,
        allocatedUid
      );
    });

    this._reloadCaches();
    const created = this.getUserByUid(allocatedUid);
    this._emit('security:sandbox_allocated', {
      uid: created.uid,
      gid: created.gid,
      appId: created.appId,
      platform: created.platform,
      sandboxRoot: created.sandboxRoot,
      strictSandbox: created.strictSandbox,
    });
    return created;
  }

  allocateSandboxUid(appId, opts = {}) {
    return this.allocateAppUid(appId, opts);
  }

  updateAppSandbox(appId, opts = {}) {
    const db = this._requireStorage();
    assertSafeAppId(appId);

    if (opts !== null && opts !== undefined && typeof opts !== 'object') {
      throw new SecurityError('Invalid updateAppSandbox options: expected object', {
        code: ERROR_CODES.EINVAL,
      });
    }

    let rawPlatform;
    let rawSandboxRoot;
    let rawStrictSandbox;
    if (opts !== null && opts !== undefined) {
      try {
        rawPlatform = opts.platform;
        rawSandboxRoot = opts.sandboxRoot;
        rawStrictSandbox = opts.strictSandbox;
      } catch {
        throw new SecurityError('Unreadable updateAppSandbox options', {
          code: ERROR_CODES.EINVAL,
        });
      }
    }

    const existing = this._usersByAppId.get(appId);
    if (!existing) {
      throw new SecurityError(`App user not found for appId: ${appId}`, {
        code: ERROR_CODES.ENOENT,
        appId,
      });
    }
    if (PROTECTED_UIDS.has(existing.uid)) {
      throw new SecurityError(`Cannot update sandbox for protected UID ${existing.uid}`, {
        code: ERROR_CODES.EPERM,
        appId,
      });
    }

    let nextPlatform = existing.platform;
    if (rawPlatform !== undefined) {
      nextPlatform = normalizePlatformName(rawPlatform, 'platform');
    }

    let nextSandboxRoot = existing.sandboxRoot;
    let nextHome = existing.home;
    if (rawSandboxRoot !== undefined) {
      nextSandboxRoot = normalizeRootPath(rawSandboxRoot);
      nextHome = nextSandboxRoot;
    }

    let nextStrictSandbox;
    if (rawStrictSandbox !== undefined) {
      if (typeof rawStrictSandbox !== 'boolean') {
        throw new SecurityError('Invalid strictSandbox for updateAppSandbox: expected boolean', {
          code: ERROR_CODES.EINVAL,
        });
      }
      nextStrictSandbox = rawStrictSandbox;
    } else if (rawPlatform !== undefined) {
      nextStrictSandbox = nextPlatform === 'android' || nextPlatform === 'ios';
    } else {
      nextStrictSandbox = Boolean(existing.strictSandbox);
    }

    db.transaction((tx) => {
      tx.run(
        `UPDATE security_users
         SET platform = ?, sandbox_root = ?, home = ?, strict_sandbox = ?
         WHERE uid = ? AND app_id = ?`,
        nextPlatform,
        nextSandboxRoot,
        nextHome,
        nextStrictSandbox ? 1 : 0,
        existing.uid,
        appId
      );
    });

    this._reloadCaches();
    const updated = this.getUserByUid(existing.uid);
    this._emit('security:sandbox_updated', {
      uid: updated.uid,
      gid: updated.gid,
      appId: updated.appId,
      platform: updated.platform,
      sandboxRoot: updated.sandboxRoot,
      strictSandbox: updated.strictSandbox,
    });
    return updated;
  }

  releaseAppUid(appId) {
    const db = this._requireStorage();
    if (typeof appId !== 'string' || appId.length === 0) return false;
    const existing = this._usersByAppId.get(appId);
    if (!existing) return false;
    if (PROTECTED_UIDS.has(existing.uid)) {
      throw new SecurityError(`Cannot release protected UID ${existing.uid}`, {
        code: ERROR_CODES.EPERM,
        appId,
      });
    }

    db.transaction((tx) => {
      tx.run('DELETE FROM security_users WHERE uid = ?', existing.uid);
      if (existing.gid === existing.uid && existing.gid >= SANDBOX_GID_BASE) {
        const remaining = tx.get(
          'SELECT COUNT(*) AS cnt FROM security_users WHERE gid = ?',
          existing.gid
        );
        if (Number(remaining?.cnt ?? 0) === 0) {
          tx.run('DELETE FROM security_groups WHERE gid = ?', existing.gid);
        }
      }
    });

    this._reloadCaches();
    this._emit('security:sandbox_released', {
      uid: existing.uid,
      gid: existing.gid,
      appId: existing.appId,
    });
    return true;
  }

  removeAppUser(appId) {
    return this.releaseAppUid(appId);
  }

  // ---- Groups ----

  createGroup(opts = {}) {
    const db = this._requireStorage();
    if (opts === null || opts === undefined || typeof opts !== 'object') {
      throw new SecurityError('Invalid createGroup options', { code: ERROR_CODES.EINVAL });
    }
    let gid = null;
    let name;
    try {
      if (opts.gid !== undefined) gid = opts.gid;
      name = opts.name;
    } catch {
      throw new SecurityError('Unreadable createGroup options', { code: ERROR_CODES.EINVAL });
    }
    assertSafeIdentifier(name, 'group name', 128);
    if (this._groupsByName.has(name)) {
      throw new SecurityError(`Group already exists: ${name}`, {
        code: ERROR_CODES.EEXIST,
      });
    }

    let finalGid;
    if (gid !== null && gid !== undefined) {
      finalGid = assertNonNegativeInt(gid, 'gid');
      if (this._groupsByGid.has(finalGid)) {
        throw new SecurityError(`GID already in use: ${finalGid}`, {
          code: ERROR_CODES.EEXIST,
        });
      }
    } else {
      let candidate = 100;
      while (this._groupsByGid.has(candidate)) candidate += 1;
      finalGid = candidate;
    }

    const now = new Date().toISOString();
    db.transaction((tx) => {
      tx.run(
        'INSERT INTO security_groups (gid, name, created_at) VALUES (?, ?, ?)',
        finalGid,
        name,
        now
      );
    });

    this._reloadCaches();
    return this.getGroup(finalGid);
  }

  getGroup(gidOrName) {
    this._requireStorage();
    let grp = null;
    if (typeof gidOrName === 'number' && Number.isSafeInteger(gidOrName) && gidOrName >= 0) {
      grp = this._groupsByGid.get(gidOrName) ?? null;
    } else if (typeof gidOrName === 'string' && gidOrName.length > 0) {
      grp = this._groupsByName.get(gidOrName) ?? null;
    }
    if (!grp) return null;
    const members = Array.from(this._groupMembers.get(grp.gid) ?? []).sort((a, b) => a - b);
    return cloneGroupRecord(grp, members);
  }

  listGroups() {
    this._requireStorage();
    const out = [];
    for (const grp of this._groupsByGid.values()) {
      const members = Array.from(this._groupMembers.get(grp.gid) ?? []).sort((a, b) => a - b);
      out.push(cloneGroupRecord(grp, members));
    }
    out.sort((a, b) => a.gid - b.gid);
    return out;
  }

  deleteGroup(gidOrName) {
    const db = this._requireStorage();
    const grp =
      typeof gidOrName === 'number'
        ? this._groupsByGid.get(gidOrName)
        : typeof gidOrName === 'string'
          ? this._groupsByName.get(gidOrName)
          : null;
    if (!grp) return false;
    if (PROTECTED_GIDS.has(grp.gid)) {
      throw new SecurityError(`Cannot delete protected system group ${grp.name} (${grp.gid})`, {
        code: ERROR_CODES.EPERM,
      });
    }
    db.transaction((tx) => {
      tx.run('DELETE FROM security_groups WHERE gid = ?', grp.gid);
    });
    this._reloadCaches();
    return true;
  }

  addUserToGroup(uid, gidOrName) {
    const db = this._requireStorage();
    assertNonNegativeInt(uid, 'uid');
    if (!this._usersByUid.has(uid)) {
      throw new SecurityError(`User not found: UID ${uid}`, { code: ERROR_CODES.ENOENT });
    }
    const grp =
      typeof gidOrName === 'number'
        ? this._groupsByGid.get(gidOrName)
        : typeof gidOrName === 'string'
          ? this._groupsByName.get(gidOrName)
          : null;
    if (!grp) {
      throw new SecurityError(`Group not found: ${safeDisplay(gidOrName)}`, { code: ERROR_CODES.ENOENT });
    }
    const res = db.transaction((tx) =>
      tx.run(
        'INSERT OR IGNORE INTO security_group_members (gid, uid) VALUES (?, ?)',
        grp.gid,
        uid
      )
    );
    this._reloadCaches();
    return res.changes > 0;
  }

  removeUserFromGroup(uid, gidOrName) {
    const db = this._requireStorage();
    assertNonNegativeInt(uid, 'uid');
    const grp =
      typeof gidOrName === 'number'
        ? this._groupsByGid.get(gidOrName)
        : typeof gidOrName === 'string'
          ? this._groupsByName.get(gidOrName)
          : null;
    if (!grp) return false;
    const res = db.transaction((tx) =>
      tx.run('DELETE FROM security_group_members WHERE gid = ? AND uid = ?', grp.gid, uid)
    );
    this._reloadCaches();
    return res.changes > 0;
  }

  getUserGroups(uid) {
    this._requireStorage();
    assertNonNegativeInt(uid, 'uid');
    return this._sortedGidsForUid(uid);
  }

  // ---- POSIX ACL Evaluation (Strict No-Fallthrough Semantics) ----

  _resolveActor(actor) {
    if (!this._initialized) {
      let lazy = null;
      let lazyOpen = false;
      try {
        if (this._storage?.isOpen) {
          lazy = this._storage;
          lazyOpen = true;
        } else {
          lazy = this._kernel?.storage ?? (this._getStorage ? this._getStorage() : null);
          lazyOpen = Boolean(lazy?.isOpen);
        }
      } catch (err) {
        if (err instanceof OmniOSError) throw err;
        throw new SecurityError('Unreadable UserManager storage dependency', {
          code: ERROR_CODES.EINVAL,
        });
      }
      if (lazyOpen) {
        this.init(lazy);
      }
    }

    let uid = DEFAULT_USER_UID;
    let explicitGid;
    let explicitGids = null;
    let explicitAppId = null;
    let explicitSandboxRoot = null;
    let explicitStrictSandbox;

    let isAlreadyResolved = false;

    if (actor === null || actor === undefined) {
      uid = DEFAULT_USER_UID;
    } else if (typeof actor === 'number') {
      uid = assertNonNegativeInt(actor, 'actor.uid');
    } else if (typeof actor === 'object') {
      try {
        isAlreadyResolved = actor[RESOLVED_ACTOR_SYM] === true;
        const aUid = actor.uid;
        if (aUid !== undefined && aUid !== null) {
          uid = assertNonNegativeInt(aUid, 'actor.uid');
        }
        const aGid = actor.gid;
        if (aGid !== undefined && aGid !== null) {
          explicitGid = assertNonNegativeInt(aGid, 'actor.gid');
        }
        const aGids = actor.gids;
        const aGroups = actor.groups;
        const aGidSet = actor.gidSet;
        if (aGids !== undefined && aGids !== null) {
          const isArr = safeIsArray(aGids);
          if (isArr === null) {
            throw new SecurityError('Invalid actor.gids', { code: ERROR_CODES.EINVAL });
          }
          if (isArr) {
            const len = aGids.length;
            if (typeof len !== 'number' || !Number.isSafeInteger(len) || len < 0 || len > 4096) {
              throw new SecurityError('Invalid actor.gids length', { code: ERROR_CODES.EINVAL });
            }
            explicitGids = [];
            for (let i = 0; i < len; i += 1) {
              explicitGids.push(aGids[i]);
            }
          }
        } else if (aGroups !== undefined && aGroups !== null) {
          const isArr = safeIsArray(aGroups);
          if (isArr === null) {
            throw new SecurityError('Invalid actor.groups', { code: ERROR_CODES.EINVAL });
          }
          if (isArr) {
            const len = aGroups.length;
            if (typeof len !== 'number' || !Number.isSafeInteger(len) || len < 0 || len > 4096) {
              throw new SecurityError('Invalid actor.groups length', { code: ERROR_CODES.EINVAL });
            }
            explicitGids = [];
            for (let i = 0; i < len; i += 1) {
              explicitGids.push(aGroups[i]);
            }
          }
        } else if (aGidSet !== undefined && aGidSet !== null) {
          if (types.isSet(aGidSet) && !types.isProxy(aGidSet)) {
            explicitGids = [];
            for (const g of Set.prototype.values.call(aGidSet)) {
              if (explicitGids.length >= 4096) {
                throw new SecurityError('Invalid actor.gidSet length', { code: ERROR_CODES.EINVAL });
              }
              explicitGids.push(g);
            }
          } else {
            throw new SecurityError('Invalid actor.gidSet: expected Set', { code: ERROR_CODES.EINVAL });
          }
        }

        if (typeof actor.appId === 'string' && actor.appId.length > 0) {
          explicitAppId = actor.appId;
        }
        if (isAlreadyResolved) {
          if (typeof actor.explicitSandboxRoot === 'string' && actor.explicitSandboxRoot.length > 0) {
            explicitSandboxRoot = normalizeRootPath(actor.explicitSandboxRoot);
          }
          if (typeof actor.explicitStrictSandbox === 'boolean') {
            explicitStrictSandbox = actor.explicitStrictSandbox;
          }
        } else {
          if (typeof actor.sandboxRoot === 'string' && actor.sandboxRoot.length > 0) {
            explicitSandboxRoot = normalizeRootPath(actor.sandboxRoot);
          }
          if (typeof actor.strictSandbox === 'boolean') {
            explicitStrictSandbox = actor.strictSandbox;
          }
        }
      } catch (err) {
        if (err instanceof SecurityError) throw err;
        throw new SecurityError('Invalid or unreadable actor descriptor', {
          code: ERROR_CODES.EINVAL,
        });
      }
    } else {
      throw new SecurityError('Invalid actor descriptor', { code: ERROR_CODES.EINVAL });
    }

    const persisted = this._usersByUid.get(uid) ?? null;
    const gid = explicitGid !== undefined ? explicitGid : (persisted ? persisted.gid : uid);
    const gidSet = new Set([gid]);
    if (persisted) {
      gidSet.add(persisted.gid);
      const cached = this._userGroups.get(uid);
      if (cached) {
        for (const g of cached) gidSet.add(g);
      }
    }
    if (explicitGids) {
      for (const g of explicitGids) {
        if (typeof g === 'number' && Number.isSafeInteger(g) && g >= 0) {
          gidSet.add(g);
        } else if (typeof g === 'string') {
          const grp = this._groupsByName.get(g);
          if (grp) gidSet.add(grp.gid);
        }
      }
    }

    const persistedSandboxRoot = persisted?.sandboxRoot ?? null;
    const persistedStrictSandbox = Boolean(persisted?.strictSandbox);
    const actorStrict = Boolean(explicitStrictSandbox);

    return {
      [RESOLVED_ACTOR_SYM]: true,
      uid,
      gid,
      gidSet,
      appId: persisted?.appId ?? explicitAppId ?? null,
      sandboxRoot: persistedSandboxRoot,
      persistedSandboxRoot,
      explicitSandboxRoot,
      strictSandbox: persistedStrictSandbox || actorStrict,
      persistedStrictSandbox,
      explicitStrictSandbox: actorStrict,
    };
  }

  _validateTarget(target) {
    if (!target || typeof target !== 'object') {
      throw new SecurityError('Invalid ACL target', { code: ERROR_CODES.EINVAL });
    }
    let tUid;
    let tGid;
    let tMode;
    try {
      tUid = target.uid;
      tGid = target.gid;
      tMode = target.mode;
    } catch {
      throw new SecurityError('Unreadable ACL target', { code: ERROR_CODES.EINVAL });
    }
    const uid = assertNonNegativeInt(tUid, 'target.uid');
    const gid = assertNonNegativeInt(tGid, 'target.gid');
    if (typeof tMode !== 'number' || !Number.isSafeInteger(tMode) || tMode < 0) {
      throw new SecurityError('Invalid target.mode', { code: ERROR_CODES.EINVAL });
    }
    return { uid, gid, mode: tMode };
  }

  checkAccess(actor, target, requestedMask) {
    if (
      typeof requestedMask !== 'number' ||
      !Number.isSafeInteger(requestedMask) ||
      requestedMask < 0 ||
      requestedMask > 7
    ) {
      throw new SecurityError('Invalid requested access mask (must be integer 0..7)', {
        code: ERROR_CODES.EINVAL,
      });
    }
    const resolved = this._resolveActor(actor);
    const t = this._validateTarget(target);

    if (requestedMask === ACCESS_MODES.F_OK) {
      return true;
    }

    // 1. Root bypass
    if (resolved.uid === ROOT_UID) {
      return true;
    }

    // 2. Owner class (STRICT POSIX: no fallthrough to group/other!)
    if (resolved.uid === t.uid) {
      const ownerBits = (t.mode >> 6) & 0o7;
      return (ownerBits & requestedMask) === requestedMask;
    }

    // 3. Group class (STRICT POSIX: no fallthrough to other!)
    if (resolved.gidSet.has(t.gid)) {
      const groupBits = (t.mode >> 3) & 0o7;
      return (groupBits & requestedMask) === requestedMask;
    }

    // 4. Other class
    const otherBits = t.mode & 0o7;
    return (otherBits & requestedMask) === requestedMask;
  }

  canRead(actor, target) {
    return this.checkAccess(actor, target, ACCESS_MODES.R_OK);
  }

  canWrite(actor, target) {
    return this.checkAccess(actor, target, ACCESS_MODES.W_OK);
  }

  canExec(actor, target) {
    return this.checkAccess(actor, target, ACCESS_MODES.X_OK);
  }

  canChmod(actor, target) {
    const resolved = this._resolveActor(actor);
    const t = this._validateTarget(target);
    return resolved.uid === ROOT_UID || resolved.uid === t.uid;
  }

  canChown(actor, target, newUid, newGid) {
    const resolved = this._resolveActor(actor);
    const t = this._validateTarget(target);
    assertNonNegativeInt(newUid, 'newUid');
    assertNonNegativeInt(newGid, 'newGid');
    if (resolved.uid === ROOT_UID) {
      return true;
    }
    return resolved.uid === t.uid && newUid === t.uid && resolved.gidSet.has(newGid);
  }

  canDeleteInDir(actor, dirInode, entryInode) {
    const resolved = this._resolveActor(actor);
    const dir = this._validateTarget(dirInode);
    const entry = this._validateTarget(entryInode);

    if (!this.checkAccess(resolved, dir, ACCESS_MODES.W_OK | ACCESS_MODES.X_OK)) {
      return false;
    }

    if ((dir.mode & SPECIAL_BITS.S_ISVTX) !== 0) {
      return (
        resolved.uid === ROOT_UID ||
        resolved.uid === dir.uid ||
        resolved.uid === entry.uid
      );
    }

    return true;
  }

  // ---- Per-App Sandbox Isolation ----

  checkSandboxAccess(actor, canonicalPath, opts = {}) {
    let mode = 'read';
    let explicitSandboxRoot = null;
    let caseInsensitive = false;
    if (opts !== null && opts !== undefined) {
      if (typeof opts !== 'object') {
        throw new SecurityError('Invalid checkSandboxAccess options', { code: ERROR_CODES.EINVAL });
      }
      try {
        if (opts.mode !== undefined) mode = opts.mode;
        if (opts.explicitSandboxRoot !== undefined) explicitSandboxRoot = opts.explicitSandboxRoot;
        if (opts.caseInsensitive !== undefined) caseInsensitive = opts.caseInsensitive;
      } catch {
        throw new SecurityError('Unreadable checkSandboxAccess options', { code: ERROR_CODES.EINVAL });
      }
    }

    if (
      typeof canonicalPath !== 'string' ||
      canonicalPath.length === 0 ||
      canonicalPath.length > 4096 ||
      !canonicalPath.startsWith('/') ||
      CONTROL_CHAR_RE.test(canonicalPath)
    ) {
      return { allowed: false, reason: 'invalid_path' };
    }

    const rawSegs = canonicalPath.split('/');
    const cleanSegs = [];
    for (const seg of rawSegs) {
      if (seg === '..') {
        return { allowed: false, reason: 'path_traversal' };
      }
      if (seg !== '' && seg !== '.') {
        cleanSegs.push(seg);
      }
    }
    const cleanPath = cleanSegs.length === 0 ? '/' : `/${cleanSegs.join('/')}`;
    const resolved = this._resolveActor(actor);

    const normalizedExplicit =
      typeof explicitSandboxRoot === 'string' && explicitSandboxRoot.length > 0
        ? normalizeRootPath(explicitSandboxRoot)
        : null;
    const actorExplicit = resolved.explicitSandboxRoot ?? null;
    const matchOpts = { caseInsensitive: Boolean(caseInsensitive) };

    if (
      resolved.uid === ROOT_UID &&
      !normalizedExplicit &&
      !actorExplicit &&
      !resolved.strictSandbox
    ) {
      return { allowed: true, reason: 'root' };
    }

    // 1. Explicit sandbox roots ALWAYS tighten/intersect (never widen or short-circuit persisted isolation)
    if (normalizedExplicit && !isWithinRoot(cleanPath, normalizedExplicit, matchOpts)) {
      return { allowed: false, reason: 'outside_sandbox_root' };
    }
    if (actorExplicit && !isWithinRoot(cleanPath, actorExplicit, matchOpts)) {
      return { allowed: false, reason: 'outside_sandbox_root' };
    }

    // 2. Persisted strictSandbox jail (cannot be loosened by explicitSandboxRoot or strictSandbox: false)
    if (resolved.strictSandbox && resolved.persistedSandboxRoot) {
      if (!isWithinRoot(cleanPath, resolved.persistedSandboxRoot, matchOpts)) {
        return { allowed: false, reason: 'outside_sandbox_root' };
      }
    }

    // 3. Always-on cross-app /var/appdata/* & /root isolation for sandbox UIDs (10000+)
    if (resolved.uid >= SANDBOX_UID_BASE) {
      if (isWithinRoot(cleanPath, '/root', matchOpts)) {
        return { allowed: false, reason: 'root_home_denied' };
      }
      if (isWithinRoot(cleanPath, '/var/appdata', matchOpts)) {
        if (!resolved.persistedSandboxRoot || !isWithinRoot(cleanPath, resolved.persistedSandboxRoot, matchOpts)) {
          return { allowed: false, reason: 'cross_app_sandbox_violation' };
        }
        return {
          allowed: true,
          reason:
            normalizedExplicit || actorExplicit || resolved.strictSandbox
              ? 'within_sandbox_root'
              : 'within_app_container',
        };
      }
    }

    if (normalizedExplicit || actorExplicit || resolved.strictSandbox) {
      return { allowed: true, reason: 'within_sandbox_root' };
    }

    return { allowed: true, reason: `allowed_${safeDisplay(mode)}` };
  }

  assertSandboxAccess(actor, canonicalPath, opts = {}) {
    const resolved = this._resolveActor(actor);
    const result = this.checkSandboxAccess(resolved, canonicalPath, opts);
    if (!result.allowed) {
      const displayPath = safeDisplay(canonicalPath);
      throw new SecurityError(
        `Sandbox access denied to ${displayPath}: ${result.reason}`,
        {
          code: ERROR_CODES.EACCES,
          appId: resolved.appId,
          details: {
            violation: ERROR_CODES.E_SANDBOX_VIOLATION,
            path: displayPath,
            reason: result.reason,
          },
        }
      );
    }
    return result;
  }
}

export function createUserManager(options = {}) {
  return new UserManager(options);
}
