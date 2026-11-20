import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

/**
 * CoreMemory represents the Hostinger-hosted persistent state & fast structured
 * memory ("RAM / Brain Store") backed by SQLite via Node 24's built-in node:sqlite.
 */
export class CoreMemory {
  constructor(dbPath) {
    this.dbPath = dbPath;
    if (dbPath !== ':memory:') {
      fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    }
    this.db = new DatabaseSync(dbPath);
    this.db.exec('PRAGMA journal_mode = WAL;');
    this.db.exec('PRAGMA foreign_keys = ON;');
    this._initSchema();
  }

  _initSchema() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS memory_entries (
        namespace TEXT NOT NULL,
        key TEXT NOT NULL,
        value_json TEXT NOT NULL,
        tags_json TEXT NOT NULL DEFAULT '[]',
        summary TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (namespace, key)
      );

      CREATE TABLE IF NOT EXISTS workflows (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        runner TEXT NOT NULL DEFAULT 'hostinger',
        enabled INTEGER NOT NULL DEFAULT 1,
        definition_json TEXT NOT NULL,
        source TEXT NOT NULL DEFAULT 'repo',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS executions (
        id TEXT PRIMARY KEY,
        workflow_id TEXT NOT NULL,
        workflow_name TEXT NOT NULL DEFAULT '',
        trigger_type TEXT NOT NULL,
        status TEXT NOT NULL,
        input_json TEXT NOT NULL DEFAULT '{}',
        output_json TEXT,
        error TEXT,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        duration_ms INTEGER,
        FOREIGN KEY (workflow_id) REFERENCES workflows(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS execution_steps (
        id TEXT PRIMARY KEY,
        execution_id TEXT NOT NULL,
        node_id TEXT NOT NULL,
        node_name TEXT NOT NULL DEFAULT '',
        node_type TEXT NOT NULL,
        status TEXT NOT NULL,
        input_json TEXT,
        output_json TEXT,
        error TEXT,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        duration_ms INTEGER,
        FOREIGN KEY (execution_id) REFERENCES executions(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS activity_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        level TEXT NOT NULL DEFAULT 'info',
        source TEXT NOT NULL DEFAULT 'engine',
        message TEXT NOT NULL,
        meta_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_executions_workflow ON executions(workflow_id, started_at DESC);
      CREATE INDEX IF NOT EXISTS idx_steps_execution ON execution_steps(execution_id, started_at ASC);
      CREATE INDEX IF NOT EXISTS idx_activity_created ON activity_log(created_at DESC);
    `);
  }

  close() {
    this.db.close();
  }

  // ---------------------------------------------------------------------------
  // Persistent Core Memory KV Store
  // ---------------------------------------------------------------------------

  getMemory(namespace, key) {
    const row = this.db
      .prepare('SELECT * FROM memory_entries WHERE namespace = ? AND key = ?')
      .get(namespace, key);
    return row ? this._formatMemoryRow(row) : null;
  }

  setMemory(namespace, key, value, { tags = [], summary = '' } = {}) {
    const now = new Date().toISOString();
    const existing = this.getMemory(namespace, key);
    const valueJson = JSON.stringify(value ?? null);
    const tagsJson = JSON.stringify(Array.isArray(tags) ? tags : []);

    if (existing) {
      this.db
        .prepare(
          `UPDATE memory_entries
           SET value_json = ?, tags_json = ?, summary = ?, updated_at = ?
           WHERE namespace = ? AND key = ?`
        )
        .run(valueJson, tagsJson, summary || existing.summary, now, namespace, key);
    } else {
      this.db
        .prepare(
          `INSERT INTO memory_entries (namespace, key, value_json, tags_json, summary, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`
        )
        .run(namespace, key, valueJson, tagsJson, summary, now, now);
    }
    return this.getMemory(namespace, key);
  }

  deleteMemory(namespace, key) {
    const result = this.db
      .prepare('DELETE FROM memory_entries WHERE namespace = ? AND key = ?')
      .run(namespace, key);
    return result.changes > 0;
  }

  listMemory({ namespace = '', tag = '', query = '', limit = 200 } = {}) {
    let sql = 'SELECT * FROM memory_entries WHERE 1=1';
    const params = [];

    if (namespace) {
      sql += ' AND namespace = ?';
      params.push(namespace);
    }
    if (tag) {
      sql += ' AND tags_json LIKE ?';
      params.push(`%"${tag}"%`);
    }
    if (query) {
      sql += ' AND (key LIKE ? OR summary LIKE ? OR value_json LIKE ? OR namespace LIKE ?)';
      const like = `%${query}%`;
      params.push(like, like, like, like);
    }

    sql += ' ORDER BY updated_at DESC LIMIT ?';
    params.push(Number(limit) || 200);

    return this.db
      .prepare(sql)
      .all(...params)
      .map((r) => this._formatMemoryRow(r));
  }

  getNamespaces() {
    const rows = this.db
      .prepare(
        'SELECT namespace, COUNT(*) as count FROM memory_entries GROUP BY namespace ORDER BY namespace ASC'
      )
      .all();
    return rows.map((r) => ({ namespace: r.namespace, count: Number(r.count) }));
  }

  /**
   * Builds a nested map `{ [namespace]: { [key]: value } }` for template lookups.
   */
  getMemoryMap() {
    const rows = this.db.prepare('SELECT namespace, key, value_json FROM memory_entries').all();
    const map = {};
    for (const row of rows) {
      if (!map[row.namespace]) map[row.namespace] = {};
      map[row.namespace][row.key] = safeJsonParse(row.value_json, row.value_json);
    }
    return map;
  }

  exportSnapshot() {
    const entries = this.listMemory({ limit: 5000 });
    const workflows = this.listWorkflows();
    const recentRuns = this.listExecutions({ limit: 25 });
    return {
      schemaVersion: '1.0',
      exportedAt: new Date().toISOString(),
      stats: this.getStats(),
      memory: entries,
      workflows: workflows.map((w) => ({
        id: w.id,
        name: w.name,
        enabled: w.enabled,
        runner: w.runner,
        nodeCount: w.definition.nodes?.length || 0,
      })),
      recentRuns: recentRuns.map((r) => ({
        id: r.id,
        workflowId: r.workflowId,
        status: r.status,
        startedAt: r.startedAt,
        durationMs: r.durationMs,
      })),
    };
  }

  _formatMemoryRow(row) {
    return {
      namespace: row.namespace,
      key: row.key,
      value: safeJsonParse(row.value_json, row.value_json),
      tags: safeJsonParse(row.tags_json, []),
      summary: row.summary,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  // ---------------------------------------------------------------------------
  // Workflows Store
  // ---------------------------------------------------------------------------

  upsertWorkflow(definition, { source = 'repo' } = {}) {
    const now = new Date().toISOString();
    const existing = this.getWorkflow(definition.id);
    const enabled = definition.enabled === false ? 0 : 1;
    const runner = definition.runner || 'hostinger';
    const defJson = JSON.stringify(definition);

    if (existing) {
      this.db
        .prepare(
          `UPDATE workflows
           SET name = ?, description = ?, runner = ?, enabled = ?, definition_json = ?, source = ?, updated_at = ?
           WHERE id = ?`
        )
        .run(
          definition.name || definition.id,
          definition.description || '',
          runner,
          enabled,
          defJson,
          source,
          now,
          definition.id
        );
    } else {
      this.db
        .prepare(
          `INSERT INTO workflows (id, name, description, runner, enabled, definition_json, source, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          definition.id,
          definition.name || definition.id,
          definition.description || '',
          runner,
          enabled,
          defJson,
          source,
          now,
          now
        );
    }
    return this.getWorkflow(definition.id);
  }

  getWorkflow(id) {
    const row = this.db.prepare('SELECT * FROM workflows WHERE id = ?').get(id);
    return row ? this._formatWorkflowRow(row) : null;
  }

  listWorkflows() {
    return this.db
      .prepare('SELECT * FROM workflows ORDER BY updated_at DESC')
      .all()
      .map((r) => this._formatWorkflowRow(r));
  }

  deleteWorkflow(id) {
    const result = this.db.prepare('DELETE FROM workflows WHERE id = ?').run(id);
    return result.changes > 0;
  }

  _formatWorkflowRow(row) {
    const definition = safeJsonParse(row.definition_json, {});
    return {
      id: row.id,
      name: row.name,
      description: row.description,
      runner: row.runner,
      enabled: Boolean(row.enabled),
      source: row.source,
      definition,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  // ---------------------------------------------------------------------------
  // Execution Runs & Step Traces
  // ---------------------------------------------------------------------------

  createExecution({ workflowId, workflowName, triggerType, input }) {
    const id = `run_${Date.now().toString(36)}_${crypto.randomBytes(3).toString('hex')}`;
    const now = new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO executions (id, workflow_id, workflow_name, trigger_type, status, input_json, started_at)
         VALUES (?, ?, ?, ?, 'running', ?, ?)`
      )
      .run(id, workflowId, workflowName || workflowId, triggerType || 'manual', JSON.stringify(input ?? {}), now);
    return id;
  }

  finishExecution(id, { status, output = null, error = null, durationMs = 0 }) {
    const now = new Date().toISOString();
    this.db
      .prepare(
        `UPDATE executions
         SET status = ?, output_json = ?, error = ?, finished_at = ?, duration_ms = ?
         WHERE id = ?`
      )
      .run(
        status,
        output !== null ? JSON.stringify(output) : null,
        error ? String(error) : null,
        now,
        Math.max(0, Math.round(durationMs)),
        id
      );
    return this.getExecution(id);
  }

  recordStep({
    executionId,
    nodeId,
    nodeName,
    nodeType,
    status,
    input = null,
    output = null,
    error = null,
    startedAt,
    finishedAt,
    durationMs = 0,
  }) {
    const id = `step_${crypto.randomBytes(6).toString('hex')}`;
    this.db
      .prepare(
        `INSERT INTO execution_steps
         (id, execution_id, node_id, node_name, node_type, status, input_json, output_json, error, started_at, finished_at, duration_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        id,
        executionId,
        nodeId,
        nodeName || nodeId,
        nodeType,
        status,
        input !== null ? JSON.stringify(input) : null,
        output !== null ? JSON.stringify(output) : null,
        error ? String(error) : null,
        startedAt || new Date().toISOString(),
        finishedAt || new Date().toISOString(),
        Math.max(0, Math.round(durationMs))
      );
    return id;
  }

  getExecution(id) {
    const row = this.db.prepare('SELECT * FROM executions WHERE id = ?').get(id);
    if (!row) return null;
    const steps = this.db
      .prepare('SELECT * FROM execution_steps WHERE execution_id = ? ORDER BY rowid ASC')
      .all(id)
      .map((s) => ({
        id: s.id,
        executionId: s.execution_id,
        nodeId: s.node_id,
        nodeName: s.node_name,
        nodeType: s.node_type,
        status: s.status,
        input: safeJsonParse(s.input_json, null),
        output: safeJsonParse(s.output_json, null),
        error: s.error,
        startedAt: s.started_at,
        finishedAt: s.finished_at,
        durationMs: s.duration_ms,
      }));
    return {
      ...this._formatExecutionRow(row),
      steps,
    };
  }

  listExecutions({ workflowId = '', limit = 50 } = {}) {
    let sql = 'SELECT * FROM executions';
    const params = [];
    if (workflowId) {
      sql += ' WHERE workflow_id = ?';
      params.push(workflowId);
    }
    sql += ' ORDER BY started_at DESC LIMIT ?';
    params.push(Number(limit) || 50);
    return this.db
      .prepare(sql)
      .all(...params)
      .map((r) => this._formatExecutionRow(r));
  }

  _formatExecutionRow(row) {
    return {
      id: row.id,
      workflowId: row.workflow_id,
      workflowName: row.workflow_name,
      triggerType: row.trigger_type,
      status: row.status,
      input: safeJsonParse(row.input_json, {}),
      output: safeJsonParse(row.output_json, null),
      error: row.error,
      startedAt: row.started_at,
      finishedAt: row.finished_at,
      durationMs: row.duration_ms,
    };
  }

  // ---------------------------------------------------------------------------
  // Audit Activity Log
  // ---------------------------------------------------------------------------

  logActivity(source, message, { level = 'info', meta = {} } = {}) {
    const now = new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO activity_log (level, source, message, meta_json, created_at)
         VALUES (?, ?, ?, ?, ?)`
      )
      .run(level, source, message, JSON.stringify(meta), now);
  }

  listActivity(limit = 80) {
    return this.db
      .prepare('SELECT * FROM activity_log ORDER BY id DESC LIMIT ?')
      .all(Number(limit) || 80)
      .map((r) => ({
        id: r.id,
        level: r.level,
        source: r.source,
        message: r.message,
        meta: safeJsonParse(r.meta_json, {}),
        createdAt: r.created_at,
      }));
  }

  getStats() {
    const memoryCount = Number(this.db.prepare('SELECT COUNT(*) as c FROM memory_entries').get().c);
    const workflowCount = Number(this.db.prepare('SELECT COUNT(*) as c FROM workflows').get().c);
    const enabledWorkflowCount = Number(
      this.db.prepare('SELECT COUNT(*) as c FROM workflows WHERE enabled = 1').get().c
    );
    const executionCount = Number(this.db.prepare('SELECT COUNT(*) as c FROM executions').get().c);
    const successCount = Number(
      this.db.prepare("SELECT COUNT(*) as c FROM executions WHERE status = 'success'").get().c
    );
    const failedCount = Number(
      this.db.prepare("SELECT COUNT(*) as c FROM executions WHERE status = 'failed'").get().c
    );

    let dbSizeBytes = 0;
    if (this.dbPath !== ':memory:' && fs.existsSync(this.dbPath)) {
      dbSizeBytes = fs.statSync(this.dbPath).size;
    }

    return {
      memoryCount,
      workflowCount,
      enabledWorkflowCount,
      executionCount,
      successCount,
      failedCount,
      dbSizeBytes,
      dbPath: this.dbPath,
    };
  }
}

function safeJsonParse(str, fallback) {
  if (str === null || str === undefined) return fallback;
  try {
    return JSON.parse(str);
  } catch {
    return fallback;
  }
}
