/**
 * Antigravity Flow — Gen-1 Interactive Visual Studio Client
 */

const state = {
  view: 'studio',
  status: null,
  catalog: [],
  workflows: [],
  activeWorkflowId: null,
  selectedNodeId: null,
  lastRunByWorkflow: new Map(),
  executions: [],
  selectedExecutionId: null,
  memoryEntries: [],
  memoryNamespaces: [],
  driveFiles: [],
  driveInfo: null,
};

const VIEW_META = {
  studio: ['Workflow Studio', 'Visual n8n-style node graph & live execution runner'],
  memory: ['Core Memory', 'Hostinger persistent SQLite state, counters & shared agent context'],
  drive: ['Storage Drive', 'Google Drive API v3 layer (with instant local sandbox mirror)'],
  runs: ['Executions & Logs', 'Step-by-step trace of every automated workflow run'],
  webhook: ['Webhook Tester', 'Fire live HTTP webhooks into your running workflow engine'],
  deploy: ['Architecture & Deploy', '4-pillar Gen-1 telemetry and Hostinger / Google Drive connect guide'],
};

const CATEGORY_DOT = {
  trigger: 'dot-trigger',
  memory: 'dot-memory',
  drive: 'dot-drive',
  logic: 'dot-logic',
  integration: 'dot-integration',
  brain: 'dot-brain',
};

const $ = (id) => document.getElementById(id);

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

function showToast(msg) {
  const el = $('toast');
  el.textContent = msg;
  el.classList.remove('hidden');
  clearTimeout(showToast._timer);
  showToast._timer = setTimeout(() => el.classList.add('hidden'), 3200);
}

function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatBytes(bytes) {
  const n = Number(bytes || 0);
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

function shortTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

// =============================================================================
// Data Loading & Navigation
// =============================================================================

async function refreshAll() {
  const [status, catalogRes, wfRes, memRes, driveRes, runsRes] = await Promise.all([
    api('/api/status'),
    api('/api/catalog'),
    api('/api/workflows'),
    api('/api/memory'),
    api('/api/drive/files'),
    api('/api/executions?limit=40'),
  ]);

  state.status = status;
  state.catalog = catalogRes.nodes || [];
  state.workflows = wfRes.workflows || [];
  state.memoryEntries = memRes.entries || [];
  state.memoryNamespaces = memRes.namespaces || [];
  state.driveFiles = driveRes.files || [];
  state.driveInfo = driveRes.info;
  state.executions = runsRes.executions || [];

  if (!state.activeWorkflowId && state.workflows.length > 0) {
    state.activeWorkflowId = state.workflows[0].id;
  }

  renderSidebarStatus();
  renderCurrentView();
}

function renderSidebarStatus() {
  if (!state.status) return;
  $('badge-memory').textContent = state.status.memory.memoryCount;
  $('badge-drive').textContent = state.status.drive.fileCount;
  $('badge-runs').textContent = state.status.memory.executionCount;

  $('status-brain').textContent = state.status.brain.llmConfigured ? state.status.brain.model : 'Gen-1 Active';
  $('status-memory').textContent = `${state.status.memory.memoryCount} keys (${formatBytes(state.status.memory.dbSizeBytes)})`;
  $('status-drive').textContent = state.status.drive.live ? 'Google Drive Live' : 'Local Sandbox';
}

function switchView(view) {
  state.view = view;
  document.querySelectorAll('.nav-item').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.view === view);
  });
  document.querySelectorAll('.view').forEach((sec) => {
    sec.classList.toggle('active', sec.id === `view-${view}`);
  });
  const [title, subtitle] = VIEW_META[view] || ['Studio', ''];
  $('page-title').textContent = title;
  $('page-subtitle').textContent = subtitle;
  renderCurrentView();
}

function renderCurrentView() {
  if (state.view === 'studio') renderStudio();
  if (state.view === 'memory') renderMemory();
  if (state.view === 'drive') renderDrive();
  if (state.view === 'runs') renderRuns();
  if (state.view === 'webhook') renderWebhookView();
  if (state.view === 'deploy') renderDeployView();
}

// =============================================================================
// VIEW 1: Visual Workflow Studio
// =============================================================================

function getActiveWorkflow() {
  return state.workflows.find((w) => w.id === state.activeWorkflowId) || null;
}

function renderStudio() {
  $('wf-count-label').textContent = `${state.workflows.length} total`;
  const listEl = $('wf-list');
  listEl.innerHTML = state.workflows
    .map(
      (wf) => `
      <button class="wf-card ${wf.id === state.activeWorkflowId ? 'selected' : ''}" data-wf-id="${escapeHtml(wf.id)}">
        <div class="wf-card-title">${escapeHtml(wf.name)}</div>
        <div class="wf-card-desc">${escapeHtml(wf.description || wf.id)}</div>
        <div class="wf-card-meta">
          <span class="tag">${escapeHtml(wf.runner)}</span>
          <span class="tag">${wf.definition.nodes?.length || 0} nodes</span>
          <span class="tag ${wf.enabled ? 'tag-ok' : ''}">${wf.enabled ? 'enabled' : 'paused'}</span>
        </div>
      </button>`
    )
    .join('');

  listEl.querySelectorAll('.wf-card').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.activeWorkflowId = btn.dataset.wfId;
      state.selectedNodeId = null;
      renderStudio();
    });
  });

  const wf = getActiveWorkflow();
  if (!wf) return;

  $('active-wf-name').textContent = wf.name;
  $('active-wf-runner').textContent = `runner: ${wf.runner}`;
  const statusEl = $('active-wf-status');
  statusEl.textContent = wf.enabled ? 'enabled' : 'paused';
  statusEl.className = `tag ${wf.enabled ? 'tag-ok' : 'tag-warn'}`;

  renderCanvas(wf);
  renderInspector(wf);
  renderLastRunStrip(wf);
}

function renderCanvas(wf) {
  const nodes = wf.definition.nodes || [];
  const edges = wf.definition.edges || [];
  const lastRun = state.lastRunByWorkflow.get(wf.id);
  const stepMap = new Map((lastRun?.steps || []).map((s) => [s.nodeId, s]));

  // Auto-layout fallback positions
  nodes.forEach((n, idx) => {
    if (!n.position) {
      n.position = { x: 40 + idx * 240, y: 140 };
    }
  });

  const maxX = Math.max(1420, ...nodes.map((n) => (n.position?.x || 0) + 280));
  const maxY = Math.max(460, ...nodes.map((n) => (n.position?.y || 0) + 180));
  const stage = $('canvas-stage');
  stage.style.width = `${maxX}px`;
  stage.style.height = `${maxY}px`;

  const nodesEl = $('canvas-nodes');
  nodesEl.innerHTML = '';

  const catalogMap = new Map(state.catalog.map((c) => [c.type, c]));

  for (const node of nodes) {
    const cat = catalogMap.get(node.type)?.category || 'logic';
    const step = stepMap.get(node.id);
    const el = document.createElement('div');
    el.className = `flow-node ${state.selectedNodeId === node.id ? 'selected' : ''}`;
    el.style.left = `${node.position.x}px`;
    el.style.top = `${node.position.y}px`;
    el.dataset.nodeId = node.id;

    const statusBadge = step
      ? `<span class="node-status-chip node-status-${step.status}">${step.status}${step.durationMs ? ` ${step.durationMs}ms` : ''}</span>`
      : '';

    el.innerHTML = `
      <div class="flow-node-head">
        <span class="node-cat-pill">
          <span class="nav-dot ${CATEGORY_DOT[cat] || 'dot-logic'}"></span>
          ${escapeHtml(cat)}
        </span>
        ${statusBadge}
      </div>
      <div class="flow-node-body">
        <div class="flow-node-name">${escapeHtml(node.name || node.id)}</div>
        <div class="flow-node-type">${escapeHtml(node.type)}</div>
      </div>
    `;

    // Drag & select interaction
    let startX = 0;
    let startY = 0;
    let origX = 0;
    let origY = 0;
    let dragged = false;

    el.addEventListener('pointerdown', (ev) => {
      startX = ev.clientX;
      startY = ev.clientY;
      origX = node.position.x;
      origY = node.position.y;
      dragged = false;
      el.setPointerCapture(ev.pointerId);

      const onMove = (moveEv) => {
        const dx = moveEv.clientX - startX;
        const dy = moveEv.clientY - startY;
        if (Math.abs(dx) > 3 || Math.abs(dy) > 3) dragged = true;
        node.position.x = Math.max(16, Math.round(origX + dx));
        node.position.y = Math.max(16, Math.round(origY + dy));
        el.style.left = `${node.position.x}px`;
        el.style.top = `${node.position.y}px`;
        drawEdges(wf);
      };

      const onUp = async () => {
        el.removeEventListener('pointermove', onMove);
        el.removeEventListener('pointerup', onUp);
        state.selectedNodeId = node.id;
        renderInspector(wf);
        document.querySelectorAll('.flow-node').forEach((nEl) => {
          nEl.classList.toggle('selected', nEl.dataset.nodeId === node.id);
        });
        if (dragged) {
          try {
            await api(`/api/workflows/${encodeURIComponent(wf.id)}`, {
              method: 'PUT',
              body: { definition: wf.definition, persistToRepo: true },
            });
          } catch (err) {
            showToast(`Position save failed: ${err.message}`);
          }
        }
      };

      el.addEventListener('pointermove', onMove);
      el.addEventListener('pointerup', onUp);
    });

    nodesEl.appendChild(el);
  }

  drawEdges(wf);
}

function drawEdges(wf) {
  const svg = $('canvas-edges');
  const nodes = new Map((wf.definition.nodes || []).map((n) => [n.id, n]));
  const NODE_W = 196;
  const NODE_H = 82;

  const parts = [];
  for (const edge of wf.definition.edges || []) {
    const src = nodes.get(edge.from);
    const dst = nodes.get(edge.to);
    if (!src || !dst) continue;

    const x1 = (src.position?.x || 0) + NODE_W;
    const y1 = (src.position?.y || 0) + NODE_H / 2;
    const x2 = dst.position?.x || 0;
    const y2 = (dst.position?.y || 0) + NODE_H / 2;
    const dx = Math.max(46, Math.abs(x2 - x1) * 0.45);
    const d = `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;

    const cls =
      edge.when === 'true'
        ? 'edge-path edge-true'
        : edge.when === 'false'
          ? 'edge-path edge-false'
          : 'edge-path';
    parts.push(`<path class="${cls}" d="${d}" />`);

    if (edge.when) {
      const mx = (x1 + x2) / 2;
      const my = (y1 + y2) / 2 - 6;
      parts.push(`<text class="edge-label" x="${mx}" y="${my}" text-anchor="middle">${escapeHtml(edge.when)}</text>`);
    }
  }
  svg.innerHTML = parts.join('');
}

function renderInspector(wf) {
  const body = $('inspector-body');
  const node = (wf.definition.nodes || []).find((n) => n.id === state.selectedNodeId);

  if (!node) {
    $('inspector-title').textContent = 'Workflow Overview';
    $('inspector-type').textContent = wf.id;
    body.innerHTML = `
      <div class="inspector-block">
        <h3>Description</h3>
        <p class="muted" style="margin:0">${escapeHtml(wf.description || 'No description')}</p>
      </div>
      <div class="inspector-block">
        <h3>Source</h3>
        <span class="mono">${escapeHtml(wf.source)}</span>
      </div>
      <div class="inspector-block">
        <h3>Webhook URL</h3>
        <code class="mono" style="font-size:11.5px;color:var(--accent-drive)">/api/webhooks/${escapeHtml(wf.id)}</code>
      </div>
      <p class="empty-hint">Click any node on the canvas to view its resolved config and live run output.</p>
    `;
    return;
  }

  const lastRun = state.lastRunByWorkflow.get(wf.id);
  const step = (lastRun?.steps || []).find((s) => s.nodeId === node.id);

  $('inspector-title').textContent = node.name || node.id;
  $('inspector-type').textContent = node.type;

  body.innerHTML = `
    <div class="inspector-block">
      <h3>Node ID</h3>
      <span class="mono">${escapeHtml(node.id)}</span>
    </div>
    <div class="inspector-block">
      <h3>Configuration</h3>
      <pre class="code-viewer">${escapeHtml(JSON.stringify(node.config || {}, null, 2))}</pre>
    </div>
    ${
      step
        ? `<div class="inspector-block">
            <h3>Latest Execution Output (${escapeHtml(step.status)} · ${step.durationMs}ms)</h3>
            <pre class="code-viewer">${escapeHtml(JSON.stringify(step.error ? { error: step.error } : step.output, null, 2))}</pre>
          </div>`
        : `<p class="empty-hint">Run this workflow to inspect this node's live output.</p>`
    }
  `;
}

function renderLastRunStrip(wf) {
  const strip = $('last-run-strip');
  const lastRun = state.lastRunByWorkflow.get(wf.id);
  if (!lastRun) {
    strip.classList.add('hidden');
    return;
  }
  strip.classList.remove('hidden');
  const badge = $('run-strip-badge');
  badge.textContent = lastRun.status;
  badge.className = `tag ${lastRun.status === 'success' ? 'tag-ok' : 'tag-err'}`;
  $('run-strip-text').textContent = `${lastRun.id} · ${lastRun.durationMs}ms · ${lastRun.steps?.length || 0} steps`;
}

async function runActiveWorkflow() {
  const wf = getActiveWorkflow();
  if (!wf) return;
  const triggerNode = (wf.definition.nodes || []).find((n) => n.type.startsWith('trigger.'));
  const samplePayload = triggerNode?.config?.samplePayload || { triggeredFrom: 'studio-ui' };

  const btn = $('btn-run-active');
  btn.disabled = true;
  btn.textContent = 'Running...';
  try {
    const { run } = await api(`/api/workflows/${encodeURIComponent(wf.id)}/run`, {
      method: 'POST',
      body: { triggerType: 'studio-ui', payload: samplePayload },
    });
    state.lastRunByWorkflow.set(wf.id, run);
    showToast(`Run ${run.status}: ${wf.name} (${run.durationMs}ms)`);
    await refreshAll();
  } catch (err) {
    showToast(`Run error: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Run Workflow';
  }
}

// =============================================================================
// VIEW 2: Core Memory (Hostinger)
// =============================================================================

function renderMemory() {
  const nsSelect = $('memory-ns-filter');
  const currentNs = nsSelect.value;
  nsSelect.innerHTML =
    '<option value="">All namespaces</option>' +
    state.memoryNamespaces
      .map((n) => `<option value="${escapeHtml(n.namespace)}">${escapeHtml(n.namespace)} (${n.count})</option>`)
      .join('');
  nsSelect.value = currentNs;

  const query = $('memory-search').value.trim().toLowerCase();
  const filtered = state.memoryEntries.filter((e) => {
    if (currentNs && e.namespace !== currentNs) return false;
    if (!query) return true;
    return JSON.stringify(e).toLowerCase().includes(query);
  });

  const tbody = $('memory-tbody');
  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="muted">No matching Core Memory entries.</td></tr>';
    return;
  }

  tbody.innerHTML = filtered
    .map(
      (entry) => `
      <tr>
        <td>
          <div class="mono"><strong>${escapeHtml(entry.namespace)}</strong> / ${escapeHtml(entry.key)}</div>
          <div class="muted" style="font-size:12px">${escapeHtml(entry.summary || '')}</div>
        </td>
        <td><div class="cell-preview" title="${escapeHtml(JSON.stringify(entry.value))}">${escapeHtml(JSON.stringify(entry.value))}</div></td>
        <td>${(entry.tags || []).map((t) => `<span class="tag">${escapeHtml(t)}</span>`).join(' ')}</td>
        <td class="mono muted">${shortTime(entry.updatedAt)}</td>
        <td>
          <button class="btn btn-danger" data-del-ns="${escapeHtml(entry.namespace)}" data-del-key="${escapeHtml(entry.key)}">Delete</button>
        </td>
      </tr>`
    )
    .join('');

  tbody.querySelectorAll('[data-del-key]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      await api(
        `/api/memory/${encodeURIComponent(btn.dataset.delNs)}/${encodeURIComponent(btn.dataset.delKey)}`,
        { method: 'DELETE' }
      );
      showToast(`Deleted ${btn.dataset.delNs}/${btn.dataset.delKey}`);
      await refreshAll();
    });
  });
}

// =============================================================================
// VIEW 3: Storage Drive (Google Drive)
// =============================================================================

function renderDrive() {
  const modeTag = $('drive-mode-tag');
  const modeDesc = $('drive-mode-desc');
  if (state.driveInfo?.live) {
    modeTag.textContent = 'google-drive-live';
    modeTag.className = 'tag tag-ok';
    modeDesc.textContent = `Connected live to Google Drive API v3 (${state.driveInfo.authType}).`;
  } else {
    modeTag.textContent = 'local-sandbox';
    modeTag.className = 'tag tag-warn';
    modeDesc.textContent =
      'Testing with local Drive mirror (./data/drive). Add Google credentials in .env to go live on Google Drive.';
  }

  const tbody = $('drive-tbody');
  if (!state.driveFiles.length) {
    tbody.innerHTML =
      '<tr><td colspan="5" class="muted">No files in Drive yet. Run a workflow or click "+ Upload File".</td></tr>';
    return;
  }

  tbody.innerHTML = state.driveFiles
    .map(
      (f) => `
      <tr>
        <td>
          <button class="btn btn-ghost mono" data-open-file="${escapeHtml(f.id)}">${escapeHtml(f.name)}</button>
        </td>
        <td class="mono muted">${escapeHtml(f.mimeType)}</td>
        <td class="mono muted">${formatBytes(f.size)}</td>
        <td class="mono muted">${shortTime(f.updatedAt)}</td>
        <td>
          <button class="btn btn-danger" data-del-file="${escapeHtml(f.id)}">Delete</button>
        </td>
      </tr>`
    )
    .join('');

  tbody.querySelectorAll('[data-open-file]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      try {
        const { file } = await api(`/api/drive/files/${encodeURIComponent(btn.dataset.openFile)}`);
        $('preview-file-name').textContent = file.name;
        $('preview-file-meta').textContent = `${file.mimeType} · ${formatBytes(file.size)}`;
        $('preview-file-content').textContent = file.content;
      } catch (err) {
        showToast(err.message);
      }
    });
  });

  tbody.querySelectorAll('[data-del-file]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      await api(`/api/drive/files/${encodeURIComponent(btn.dataset.delFile)}`, { method: 'DELETE' });
      showToast('File deleted from Drive');
      await refreshAll();
    });
  });
}

// =============================================================================
// VIEW 4: Executions & Traces
// =============================================================================

async function renderRuns() {
  const listEl = $('runs-list');
  if (!state.executions.length) {
    listEl.innerHTML = '<p class="empty-hint" style="padding:12px">No executions yet. Click "Run Workflow" in the top bar.</p>';
    return;
  }

  if (!state.selectedExecutionId) {
    state.selectedExecutionId = state.executions[0].id;
  }

  listEl.innerHTML = state.executions
    .map(
      (r) => `
      <button class="run-item ${r.id === state.selectedExecutionId ? 'selected' : ''}" data-run-id="${escapeHtml(r.id)}">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
          <strong style="font-size:13px">${escapeHtml(r.workflowName)}</strong>
          <span class="tag ${r.status === 'success' ? 'tag-ok' : 'tag-err'}">${escapeHtml(r.status)}</span>
        </div>
        <div class="mono muted" style="font-size:11px">
          ${escapeHtml(r.triggerType)} · ${r.durationMs ?? 0}ms · ${shortTime(r.startedAt)}
        </div>
      </button>`
    )
    .join('');

  listEl.querySelectorAll('.run-item').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.selectedExecutionId = btn.dataset.runId;
      renderRuns();
    });
  });

  const { execution } = await api(`/api/executions/${encodeURIComponent(state.selectedExecutionId)}`);
  $('run-detail-title').textContent = execution.workflowName;
  $('run-detail-meta').textContent = `${execution.id} · ${execution.status} · ${execution.durationMs}ms`;

  $('run-steps-list').innerHTML = (execution.steps || [])
    .map(
      (step) => `
      <div class="step-card">
        <div class="step-card-head">
          <div>
            <strong>${escapeHtml(step.nodeName)}</strong>
            <span class="mono muted" style="margin-left:8px;font-size:11.5px">${escapeHtml(step.nodeType)}</span>
          </div>
          <span class="tag ${step.status === 'success' ? 'tag-ok' : step.status === 'failed' ? 'tag-err' : ''}">
            ${escapeHtml(step.status)} · ${step.durationMs}ms
          </span>
        </div>
        <pre class="code-viewer">${escapeHtml(JSON.stringify(step.error ? { error: step.error } : step.output, null, 2))}</pre>
      </div>`
    )
    .join('');
}

// =============================================================================
// VIEW 5: Webhook Tester & VIEW 6: Deploy
// =============================================================================

function renderWebhookView() {
  const select = $('webhook-wf-select');
  const prev = select.value;
  select.innerHTML = state.workflows
    .map((wf) => `<option value="${escapeHtml(wf.id)}">${escapeHtml(wf.name)} (${escapeHtml(wf.id)})</option>`)
    .join('');
  if (prev && state.workflows.some((w) => w.id === prev)) {
    select.value = prev;
  } else if (state.workflows.some((w) => w.id === 'wf-webhook-intake-router')) {
    select.value = 'wf-webhook-intake-router';
  }
  updateWebhookUrl();
  if (!$('webhook-payload').value.trim()) {
    setWebhookPreset('high');
  }
}

function updateWebhookUrl() {
  const id = $('webhook-wf-select').value;
  $('webhook-url-display').value = `${window.location.origin}/api/webhooks/${id}`;
}

function setWebhookPreset(priority) {
  const payload =
    priority === 'high'
      ? {
          title: 'Production Sync Alert',
          priority: 'high',
          owner: 'antigravity',
          notes: 'High priority triggers the Brain brief + automatic Google Drive archive branch.',
        }
      : {
          title: 'Routine Check-in Note',
          priority: 'normal',
          owner: 'team',
          notes: 'Standard priority stays lightweight in Hostinger Core Memory only.',
        };
  $('webhook-payload').value = JSON.stringify(payload, null, 2);
}

function renderDeployView() {
  $('deploy-status-json').textContent = JSON.stringify(state.status || {}, null, 2);
}

// =============================================================================
// Modal Helpers (Write Memory, Upload Drive, Edit Workflow JSON, New Workflow)
// =============================================================================

let modalHandler = null;

function openModal({ title, bodyHtml, submitLabel = 'Save', onSubmit }) {
  $('modal-title').textContent = title;
  $('modal-body').innerHTML = bodyHtml;
  $('modal-submit').textContent = submitLabel;
  modalHandler = onSubmit;
  $('modal-backdrop').classList.remove('hidden');
}

function closeModal() {
  $('modal-backdrop').classList.add('hidden');
  modalHandler = null;
}

$('modal-close').addEventListener('click', closeModal);
$('modal-cancel').addEventListener('click', closeModal);
$('modal-submit').addEventListener('click', async () => {
  if (!modalHandler) return;
  try {
    await modalHandler();
    closeModal();
    await refreshAll();
  } catch (err) {
    showToast(err.message);
  }
});

// =============================================================================
// Wire Up Event Handlers
// =============================================================================

document.querySelectorAll('.nav-item').forEach((btn) => {
  btn.addEventListener('click', () => switchView(btn.dataset.view));
});

$('btn-run-active').addEventListener('click', runActiveWorkflow);

$('btn-sync-repo').addEventListener('click', async () => {
  const res = await api('/api/workflows/sync', { method: 'POST' });
  showToast(`Synced ${res.synced} workflow(s) from workflows/`);
  await refreshAll();
});

$('btn-toggle-wf').addEventListener('click', async () => {
  const wf = getActiveWorkflow();
  if (!wf) return;
  await api(`/api/workflows/${encodeURIComponent(wf.id)}/toggle`, { method: 'POST' });
  showToast(`Toggled ${wf.name}`);
  await refreshAll();
});

$('btn-inspect-last-run').addEventListener('click', () => {
  const wf = getActiveWorkflow();
  const run = wf && state.lastRunByWorkflow.get(wf.id);
  if (run) {
    state.selectedExecutionId = run.id;
    switchView('runs');
  }
});

$('btn-edit-json').addEventListener('click', () => {
  const wf = getActiveWorkflow();
  if (!wf) return;
  openModal({
    title: `Edit Workflow JSON (${wf.id})`,
    submitLabel: 'Save Workflow',
    bodyHtml: `
      <label class="field">
        <span>Workflow Definition JSON</span>
        <textarea id="m-wf-json" class="textarea mono" rows="18">${escapeHtml(JSON.stringify(wf.definition, null, 2))}</textarea>
      </label>`,
    onSubmit: async () => {
      const def = JSON.parse($('m-wf-json').value);
      await api(`/api/workflows/${encodeURIComponent(wf.id)}`, {
        method: 'PUT',
        body: { definition: def, persistToRepo: true },
      });
      showToast(`Saved ${def.name}`);
    },
  });
});

$('btn-new-workflow').addEventListener('click', () => {
  const template = {
    id: `wf-custom-${Date.now().toString(36).slice(-4)}`,
    name: 'New Custom Automation',
    description: 'Created from Visual Studio',
    runner: 'hostinger',
    enabled: true,
    nodes: [
      { id: 'trig', name: 'Manual Trigger', type: 'trigger.manual', position: { x: 60, y: 140 }, config: {} },
      {
        id: 'mem',
        name: 'Save Note to Memory',
        type: 'memory.write',
        position: { x: 320, y: 140 },
        config: { namespace: 'custom', key: 'last_note', value: 'Hello from Gen-1 at {{ $now }}' },
      },
    ],
    edges: [{ from: 'trig', to: 'mem' }],
  };
  openModal({
    title: 'Create New Workflow',
    submitLabel: 'Create & Save to Repo',
    bodyHtml: `
      <label class="field">
        <span>Workflow Definition JSON</span>
        <textarea id="m-new-wf" class="textarea mono" rows="16">${escapeHtml(JSON.stringify(template, null, 2))}</textarea>
      </label>`,
    onSubmit: async () => {
      const def = JSON.parse($('m-new-wf').value);
      const { workflow } = await api('/api/workflows', {
        method: 'POST',
        body: { definition: def, persistToRepo: true },
      });
      state.activeWorkflowId = workflow.id;
      showToast(`Created workflow "${workflow.name}"`);
    },
  });
});

$('btn-add-node').addEventListener('click', () => {
  const wf = getActiveWorkflow();
  if (!wf) return;
  const options = state.catalog
    .map((n) => `<option value="${escapeHtml(n.type)}">${escapeHtml(n.label)} (${escapeHtml(n.type)})</option>`)
    .join('');
  const existingNodes = (wf.definition.nodes || [])
    .map((n) => `<option value="${escapeHtml(n.id)}">${escapeHtml(n.name || n.id)} (${escapeHtml(n.id)})</option>`)
    .join('');

  openModal({
    title: `Add Node to ${wf.name}`,
    submitLabel: 'Add Node',
    bodyHtml: `
      <label class="field">
        <span>Node Type</span>
        <select id="m-node-type" class="input">${options}</select>
      </label>
      <label class="field">
        <span>Display Name</span>
        <input id="m-node-name" class="input" placeholder="e.g. Archive Summary" />
      </label>
      <label class="field">
        <span>Connect From Existing Node (optional)</span>
        <select id="m-node-from" class="input"><option value="">None</option>${existingNodes}</select>
      </label>`,
    onSubmit: async () => {
      const type = $('m-node-type').value;
      const cat = state.catalog.find((c) => c.type === type);
      const id = `node_${Date.now().toString(36).slice(-4)}`;
      const lastNode = wf.definition.nodes[wf.definition.nodes.length - 1];
      const newNode = {
        id,
        name: $('m-node-name').value.trim() || cat?.label || type,
        type,
        position: {
          x: (lastNode?.position?.x || 40) + 230,
          y: lastNode?.position?.y || 140,
        },
        config: structuredClone(cat?.defaultConfig || {}),
      };
      wf.definition.nodes.push(newNode);
      const fromId = $('m-node-from').value;
      if (fromId) {
        wf.definition.edges.push({ from: fromId, to: id });
      }
      await api(`/api/workflows/${encodeURIComponent(wf.id)}`, {
        method: 'PUT',
        body: { definition: wf.definition, persistToRepo: true },
      });
      state.selectedNodeId = id;
      showToast(`Added node "${newNode.name}"`);
    },
  });
});

$('memory-ns-filter').addEventListener('change', renderMemory);
$('memory-search').addEventListener('input', renderMemory);

$('btn-trigger-backup').addEventListener('click', async () => {
  const { run } = await api('/api/workflows/wf-core-heartbeat-backup/run', {
    method: 'POST',
    body: { triggerType: 'manual-backup', payload: {} },
  });
  showToast(`Core Memory backed up to Drive (${run.durationMs}ms)`);
  await refreshAll();
});

$('btn-add-memory').addEventListener('click', () => {
  openModal({
    title: 'Write to Core Memory (Hostinger)',
    submitLabel: 'Save Entry',
    bodyHtml: `
      <label class="field"><span>Namespace</span><input id="m-mem-ns" class="input" value="notes" /></label>
      <label class="field"><span>Key</span><input id="m-mem-key" class="input" placeholder="e.g. launch_plan" /></label>
      <label class="field"><span>Summary</span><input id="m-mem-summary" class="input" placeholder="Short description" /></label>
      <label class="field"><span>Value (JSON or plain text)</span><textarea id="m-mem-val" class="textarea mono" rows="5">{"status": "ready"}</textarea></label>`,
    onSubmit: async () => {
      const raw = $('m-mem-val').value;
      let value = raw;
      try {
        value = JSON.parse(raw);
      } catch {
        // plain string
      }
      await api('/api/memory', {
        method: 'POST',
        body: {
          namespace: $('m-mem-ns').value.trim() || 'default',
          key: $('m-mem-key').value.trim(),
          summary: $('m-mem-summary').value.trim(),
          value,
        },
      });
      showToast('Saved to Core Memory');
    },
  });
});

$('btn-upload-drive').addEventListener('click', () => {
  openModal({
    title: 'Upload File to Storage Drive',
    submitLabel: 'Upload',
    bodyHtml: `
      <label class="field"><span>File Path / Name</span><input id="m-drv-name" class="input" placeholder="notes/hello.md" /></label>
      <label class="field"><span>Content</span><textarea id="m-drv-content" class="textarea mono" rows="8"># Hello from Antigravity Flow</textarea></label>`,
    onSubmit: async () => {
      await api('/api/drive/files', {
        method: 'POST',
        body: {
          name: $('m-drv-name').value.trim(),
          content: $('m-drv-content').value,
        },
      });
      showToast('Uploaded to Storage Drive');
    },
  });
});

$('btn-refresh-runs').addEventListener('click', refreshAll);
$('webhook-wf-select').addEventListener('change', updateWebhookUrl);
$('preset-high').addEventListener('click', () => setWebhookPreset('high'));
$('preset-normal').addEventListener('click', () => setWebhookPreset('normal'));

$('btn-send-webhook').addEventListener('click', async () => {
  const wfId = $('webhook-wf-select').value;
  $('webhook-status-meta').textContent = 'Sending...';
  try {
    const payload = JSON.parse($('webhook-payload').value || '{}');
    const res = await api(`/api/webhooks/${encodeURIComponent(wfId)}`, {
      method: 'POST',
      body: payload,
    });
    $('webhook-status-meta').textContent = `200 OK · ${res.run.durationMs}ms`;
    $('webhook-response').textContent = JSON.stringify(res, null, 2);
    state.lastRunByWorkflow.set(wfId, res.run);
    showToast(`Webhook triggered "${wfId}" (${res.run.status})`);
    await refreshAll();
  } catch (err) {
    $('webhook-status-meta').textContent = 'Error';
    $('webhook-response').textContent = err.message;
    showToast(err.message);
  }
});

// Boot
refreshAll().catch((err) => showToast(`Init error: ${err.message}`));
