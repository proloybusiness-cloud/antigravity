import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { createApp } from '../src/server.mjs';
import { validateWorkflow } from '../src/engine.mjs';
import { resolveTemplates, evaluateCondition } from '../src/template.mjs';
import { matchesCron, getNextRunTime } from '../src/scheduler.mjs';

test('template resolver handles nested objects, fallbacks, filters, and prevents prototype traversal', () => {
  const ctx = {
    $runId: 'run_123',
    $trigger: { payload: { title: 'Launch', count: 5 } },
    $nodes: { step1: { output: { items: ['a', 'b'] } } },
  };

  assert.equal(resolveTemplates('reports/{{ $runId }}.md', ctx), 'reports/run_123.md');
  assert.equal(resolveTemplates('{{ $trigger.payload.count }}', ctx), 5);
  assert.equal(resolveTemplates('{{ $trigger.payload.missing ?? "fallback" }}', ctx), 'fallback');
  assert.equal(resolveTemplates('{{ $trigger.payload.title | upper }}', ctx), 'LAUNCH');
  assert.equal(resolveTemplates('{{ $nodes.step1.output.items | length }}', ctx), 2);
  assert.equal(resolveTemplates('{{ $trigger.__proto__.polluted }}', ctx), '');

  assert.equal(evaluateCondition({ left: 'high', operator: 'eq', right: 'high' }), true);
  assert.equal(evaluateCondition({ left: 10, operator: 'gt', right: 3 }), true);
  assert.equal(evaluateCondition({ left: 'Antigravity Flow', operator: 'contains', right: 'flow' }), true);
});

test('cron parser matches expressions and computes next UTC run time', () => {
  const dt = new Date('2026-11-20T06:00:00.000Z');
  assert.equal(matchesCron('0 */6 * * *', dt), true);
  assert.equal(matchesCron('15 */6 * * *', dt), false);
  assert.equal(matchesCron('0 9 * * *', new Date('2026-11-20T09:00:00.000Z')), true);

  const next = getNextRunTime('0 */6 * * *', dt);
  assert.equal(next, '2026-11-20T12:00:00.000Z');
});

test('DAG validator rejects cycles and missing nodes', () => {
  const cyclic = {
    id: 'bad-cycle',
    name: 'Cycle Test',
    nodes: [
      { id: 'a', type: 'trigger.manual' },
      { id: 'b', type: 'logic.transform' },
    ],
    edges: [
      { from: 'a', to: 'b' },
      { from: 'b', to: 'a' },
    ],
  };
  const check = validateWorkflow(cyclic);
  assert.equal(check.valid, false);
  assert.ok(check.errors.some((e) => e.includes('cycle')));
});

test('end-to-end Gen-1 system: Core Memory <-> Drive backup, branching webhook, and HTTP API', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ag-flow-test-'));
  const app = createApp({
    dataDir: tmpDir,
    dbPath: path.join(tmpDir, 'core-memory.sqlite'),
    localDriveDir: path.join(tmpDir, 'drive'),
    gdriveMode: 'local',
    schedulerEnabled: false,
    apiKey: '',
    webhookSecret: '',
  });

  const { port } = await app.start(0, '127.0.0.1');
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // 1. Health & status check
    const healthRes = await fetch(`${baseUrl}/api/health`);
    assert.equal(healthRes.status, 200);
    const health = await healthRes.json();
    assert.equal(health.ok, true);
    assert.equal(health.generation, 'Gen-1');

    // 2. Verify starter workflows were synced from workflows/
    const wfRes = await fetch(`${baseUrl}/api/workflows`);
    const { workflows } = await wfRes.json();
    assert.ok(workflows.length >= 3, 'Expected at least 3 starter workflows');

    // 3. Run Core Memory Snapshot -> Drive Backup workflow
    const backupRunRes = await fetch(`${baseUrl}/api/workflows/wf-core-heartbeat-backup/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ triggerType: 'test', payload: {} }),
    });
    const { run: backupRun } = await backupRunRes.json();
    assert.equal(backupRun.status, 'success');
    assert.equal(backupRun.steps.length, 6);

    // Check Core Memory heartbeat incremented to 1 and backup receipt saved
    const heartbeat = app.memory.getMemory('system', 'heartbeat_count');
    assert.equal(heartbeat.value, 1);
    const receipt = app.memory.getMemory('backups', 'last_drive_backup');
    assert.equal(receipt.value.fileName, 'backups/core-memory-latest.json');

    // Check Google Drive (local sandbox) received the backup file
    const driveList = await app.drive.list();
    assert.ok(driveList.some((f) => f.name === 'backups/core-memory-latest.json'));

    // 4. Test Webhook Intake — HIGH priority branch (should archive brief to Drive)
    const highWebhookRes = await fetch(`${baseUrl}/api/webhooks/wf-webhook-intake-router`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: 'Urgent Client Onboarding',
        priority: 'high',
        owner: 'antigravity',
        notes: 'Must be archived in Drive.',
      }),
    });
    assert.equal(highWebhookRes.status, 200);
    const { run: highRun } = await highWebhookRes.json();
    assert.equal(highRun.status, 'success');

    const highSteps = new Map(highRun.steps.map((s) => [s.nodeId, s.status]));
    assert.equal(highSteps.get('brain_brief'), 'success');
    assert.equal(highSteps.get('archive_drive'), 'success');
    assert.equal(highSteps.get('log_normal'), 'skipped');

    const archivedIndex = app.memory.getMemory('intake', 'archived_reports');
    assert.equal(archivedIndex.value.length, 1);
    assert.ok(archivedIndex.value[0].drivePath.startsWith('reports/intake-'));

    // 5. Test Webhook Intake — NORMAL priority branch (should stay in Core Memory only)
    const normalWebhookRes = await fetch(`${baseUrl}/api/webhooks/wf-webhook-intake-router`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: 'Routine Weekly Check',
        priority: 'normal',
        owner: 'team',
      }),
    });
    assert.equal(normalWebhookRes.status, 200);
    const { run: normalRun } = await normalWebhookRes.json();
    assert.equal(normalRun.status, 'success');

    const normalSteps = new Map(normalRun.steps.map((s) => [s.nodeId, s.status]));
    assert.equal(normalSteps.get('brain_brief'), 'skipped');
    assert.equal(normalSteps.get('archive_drive'), 'skipped');
    assert.equal(normalSteps.get('log_normal'), 'success');

    const standardQueue = app.memory.getMemory('intake', 'standard_queue');
    assert.equal(standardQueue.value.length, 1);

    // 6. Test Drive read via HTTP API
    const filesRes = await fetch(`${baseUrl}/api/drive/files`);
    const { files } = await filesRes.json();
    assert.ok(files.length >= 2, 'Expected backup JSON + high-priority markdown brief in Drive');

    const reportFile = files.find((f) => f.name.startsWith('reports/intake-'));
    const readRes = await fetch(`${baseUrl}/api/drive/files/${encodeURIComponent(reportFile.id)}`);
    const { file } = await readRes.json();
    assert.ok(file.content.includes('Urgent Client Onboarding'));
  } finally {
    await app.stop();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
