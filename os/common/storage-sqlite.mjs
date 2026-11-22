/**
 * OmniOS Unified WAL SQLite Wrapper (`node:sqlite` DatabaseSync)
 * Provides automatic WAL/FK/synchronous/busy_timeout setup, plain-object row normalization,
 * nested SAVEPOINT transactions with async-callback rejection, and idempotent schema migrations.
 */

import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { types } from 'node:util';
import { OmniOSError, ERROR_CODES } from './errors.mjs';

const VALID_SYNC_MODES = new Set(['OFF', 'NORMAL', 'FULL', 'EXTRA']);

function isThenable(value) {
  if (value === null || value === undefined) return false;
  if (typeof value !== 'object' && typeof value !== 'function') return false;
  try {
    if (types.isPromise(value)) return true;
  } catch {
    // Fall through to guarded thenable check.
  }
  try {
    return typeof value.then === 'function';
  } catch {
    return false;
  }
}

function suppressThenableRejection(thenable) {
  try {
    if (types.isPromise(thenable)) {
      try {
        Promise.prototype.then.call(thenable, () => {}, () => {});
        return;
      } catch {
        // Fall through to guarded .then() if Promise.prototype.then fails.
      }
    }
  } catch {
    // Ignore types.isPromise failures.
  }
  try {
    if (typeof thenable.then === 'function') {
      thenable.then(undefined, () => {});
    }
  } catch {
    // Ignore hostile thenable .then() errors during rejection suppression.
  }
}

export class SqliteStorage {
  constructor(
    dbPath = ':memory:',
    { wal = true, foreignKeys = true, synchronous = 'NORMAL', busyTimeoutMs = 5000 } = {}
  ) {
    if (typeof dbPath !== 'string' || dbPath.length === 0) {
      throw new OmniOSError('SqliteStorage dbPath must be a non-empty string', {
        code: ERROR_CODES.EINVAL,
        details: { dbPath },
      });
    }

    this.dbPath = dbPath;
    this.isMemory = dbPath === ':memory:';
    this._closed = false;
    this._txDepth = 0;
    this._savepointSeq = 0;

    if (!this.isMemory) {
      fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    }

    this.db = new DatabaseSync(dbPath);

    try {
      if (!this.isMemory && wal) {
        this.db.exec('PRAGMA journal_mode = WAL;');
      }
      if (foreignKeys) {
        this.db.exec('PRAGMA foreign_keys = ON;');
      }
      if (synchronous !== null && synchronous !== undefined) {
        const syncMode = String(synchronous).toUpperCase();
        if (!VALID_SYNC_MODES.has(syncMode)) {
          throw new OmniOSError(`Invalid SQLite synchronous mode: ${synchronous}`, {
            code: ERROR_CODES.EINVAL,
          });
        }
        this.db.exec(`PRAGMA synchronous = ${syncMode};`);
      }
      if (busyTimeoutMs !== null && busyTimeoutMs !== undefined) {
        if (typeof busyTimeoutMs !== 'number' || !Number.isFinite(busyTimeoutMs) || busyTimeoutMs < 0) {
          throw new OmniOSError(`Invalid SQLite busyTimeoutMs: ${busyTimeoutMs}`, {
            code: ERROR_CODES.EINVAL,
          });
        }
        this.db.exec(`PRAGMA busy_timeout = ${Math.floor(busyTimeoutMs)};`);
      }
    } catch (err) {
      this.close();
      throw err;
    }
  }

  get isOpen() {
    if (this._closed) return false;
    return typeof this.db.isOpen === 'boolean' ? this.db.isOpen : true;
  }

  get inTransaction() {
    if (!this.isOpen) return false;
    return this._txDepth > 0 || Boolean(this.db.isTransaction);
  }

  _assertOpen() {
    if (!this.isOpen) {
      throw new OmniOSError('SqliteStorage is closed', {
        code: ERROR_CODES.E_STORAGE_CLOSED,
        details: { dbPath: this.dbPath },
      });
    }
  }

  exec(sql) {
    this._assertOpen();
    this.db.exec(sql);
  }

  prepare(sql) {
    this._assertOpen();
    return this.db.prepare(sql);
  }

  run(sql, ...params) {
    this._assertOpen();
    const res = this.db.prepare(sql).run(...params);
    return {
      changes: Number(res.changes),
      lastInsertRowid: typeof res.lastInsertRowid === 'bigint' ? Number(res.lastInsertRowid) : res.lastInsertRowid,
    };
  }

  get(sql, ...params) {
    this._assertOpen();
    const row = this.db.prepare(sql).get(...params);
    return row === undefined ? null : { ...row };
  }

  all(sql, ...params) {
    this._assertOpen();
    const rows = this.db.prepare(sql).all(...params);
    return rows.map((r) => ({ ...r }));
  }

  getJournalMode() {
    this._assertOpen();
    const row = this.db.prepare('PRAGMA journal_mode').get();
    return String(row?.journal_mode ?? '').toLowerCase();
  }

  getPragma(name) {
    this._assertOpen();
    if (typeof name !== 'string' || !/^[a-z_]+$/i.test(name)) {
      throw new OmniOSError(`Invalid PRAGMA name: ${name}`, { code: ERROR_CODES.EINVAL });
    }
    const row = this.db.prepare(`PRAGMA ${name}`).get();
    if (!row) return null;
    const keys = Object.keys(row);
    return keys.length > 0 ? row[keys[0]] : null;
  }

  transaction(fn) {
    this._assertOpen();
    if (typeof fn !== 'function') {
      throw new OmniOSError('SqliteStorage.transaction() requires a callback function', {
        code: ERROR_CODES.EINVAL,
      });
    }

    if (this._txDepth === 0) {
      this.db.exec('BEGIN IMMEDIATE');
      this._txDepth = 1;
      try {
        const result = fn(this);
        if (isThenable(result)) {
          suppressThenableRejection(result);
          throw new OmniOSError('SqliteStorage.transaction() requires a synchronous callback', {
            code: ERROR_CODES.E_ASYNC_TRANSACTION,
          });
        }
        this.db.exec('COMMIT');
        return result;
      } catch (err) {
        if (this.isOpen) {
          try {
            this.db.exec('ROLLBACK');
          } catch {
            // Ignore secondary rollback error if SQLite already rolled back.
          }
        }
        throw err;
      } finally {
        this._txDepth = 0;
      }
    }

    // Nested transaction via SQLite SAVEPOINT
    const sp = `sp_${++this._savepointSeq}`;
    this.db.exec(`SAVEPOINT ${sp}`);
    this._txDepth += 1;
    try {
      const result = fn(this);
      if (isThenable(result)) {
        suppressThenableRejection(result);
        throw new OmniOSError('SqliteStorage.transaction() requires a synchronous callback', {
          code: ERROR_CODES.E_ASYNC_TRANSACTION,
        });
      }
      this.db.exec(`RELEASE SAVEPOINT ${sp}`);
      return result;
    } catch (err) {
      if (this.isOpen) {
        try {
          this.db.exec(`ROLLBACK TO SAVEPOINT ${sp}`);
          this.db.exec(`RELEASE SAVEPOINT ${sp}`);
        } catch {
          // Ignore secondary savepoint rollback error.
        }
      }
      throw err;
    } finally {
      this._txDepth -= 1;
    }
  }

  migrate(namespaceOrMigrations, maybeMigrations = undefined) {
    this._assertOpen();

    let namespace = null;
    let migrations;
    if (typeof namespaceOrMigrations === 'string') {
      namespace = namespaceOrMigrations.trim();
      if (namespace.length === 0) {
        throw new OmniOSError('Migration namespace must be a non-empty string', {
          code: ERROR_CODES.EINVAL,
        });
      }
      migrations = maybeMigrations;
    } else {
      migrations = namespaceOrMigrations;
    }

    if (!Array.isArray(migrations)) {
      throw new OmniOSError('SqliteStorage.migrate() expects an array of migration definitions', {
        code: ERROR_CODES.EINVAL,
      });
    }

    this.exec(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL DEFAULT '',
        applied_at TEXT NOT NULL
      );
    `);

    const appliedRows = this.all('SELECT id FROM schema_migrations');
    const appliedSet = new Set(appliedRows.map((r) => String(r.id)));

    const applied = [];
    const skipped = [];

    for (const m of migrations) {
      if (!m || typeof m !== 'object') {
        throw new OmniOSError('Invalid migration entry', {
          code: ERROR_CODES.E_MIGRATION_FAILED,
        });
      }
      const rawId = m.id !== undefined ? m.id : m.version;
      if (rawId === undefined || rawId === null || String(rawId).length === 0) {
        throw new OmniOSError('Migration entry must specify id or version', {
          code: ERROR_CODES.E_MIGRATION_FAILED,
        });
      }
      const migId = namespace ? `${namespace}_${rawId}` : String(rawId);
      if (appliedSet.has(migId)) {
        skipped.push(migId);
        continue;
      }

      const upAction = m.up !== undefined ? m.up : m.sql;
      if (typeof upAction !== 'string' && typeof upAction !== 'function') {
        throw new OmniOSError(`Migration "${migId}" must define an "up" function/SQL or "sql" string`, {
          code: ERROR_CODES.E_MIGRATION_FAILED,
          details: { id: migId },
        });
      }

      try {
        this.transaction(() => {
          if (typeof upAction === 'function') {
            const upResult = upAction(this);
            if (isThenable(upResult)) {
              suppressThenableRejection(upResult);
              throw new OmniOSError(
                'Async migration callbacks are not supported in synchronous SqliteStorage',
                { code: ERROR_CODES.E_ASYNC_TRANSACTION }
              );
            }
          } else {
            this.exec(upAction);
          }
          this.run(
            'INSERT INTO schema_migrations (id, name, applied_at) VALUES (?, ?, ?)',
            migId,
            String(m.name ?? migId),
            new Date().toISOString()
          );
        });
      } catch (err) {
        throw new OmniOSError(`Migration "${migId}" failed: ${err.message}`, {
          code: ERROR_CODES.E_MIGRATION_FAILED,
          details: { id: migId },
          cause: err,
        });
      }

      appliedSet.add(migId);
      applied.push(migId);
    }

    return {
      applied,
      skipped,
      totalApplied: appliedSet.size,
    };
  }

  getAppliedMigrations() {
    this._assertOpen();
    const table = this.get(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'"
    );
    if (!table) return [];
    return this.all('SELECT id, name, applied_at FROM schema_migrations ORDER BY rowid ASC').map(
      (r) => ({
        id: String(r.id),
        name: String(r.name),
        appliedAt: String(r.applied_at),
      })
    );
  }

  close() {
    if (this._closed) return;
    this._closed = true;
    const stillOpen = typeof this.db.isOpen === 'boolean' ? this.db.isOpen : true;
    if (stillOpen) {
      try {
        this.db.close();
      } catch {
        // Ignore if already closed natively.
      }
    }
  }
}

export function openSqliteStorage(dbPath = ':memory:', options = {}) {
  return new SqliteStorage(dbPath, options);
}
