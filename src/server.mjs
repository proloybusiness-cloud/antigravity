import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import crypto from 'node:crypto';
import { getConfig } from './config.mjs';
import { CoreMemory } from './memory.mjs';
import { StorageDrive } from './drive.mjs';
import { WorkflowEngine, validateWorkflow } from './engine.mjs';
import { NODE_CATALOG } from './nodes.mjs';
import { CronScheduler } from './scheduler.mjs';

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

/**
 * Creates the full Gen-1 runtime (CoreMemory + StorageDrive + WorkflowEngine +
 * CronScheduler + HTTP API/UI Server). Exported for both CLI/production and tests.
 */
export function createApp(overrides = {}) {
  const config = getConfig(overrides);
  const memory = new CoreMemory(config.dbPath);
  const drive = new StorageDrive(config);
  const engine = new WorkflowEngine({ config, memory, drive });
  const scheduler = new CronScheduler({ engine, memory });
  const startedAt = new Date().toISOString();
  const publicDir = path.join(config.rootDir, 'public');

  // Seed default system memory keys if empty
  if (!memory.getMemory('system', 'generation')) {
    memory.setMemory('system', 'generation', 'Gen-1', {
      tags: ['system', 'core'],
      summary: 'Active Antigravity Flow architecture generation',
    });
    memory.setMemory('system', 'architecture', {
      brain: 'Antigravity (Chat + GitHub GitOps)',
      coreMemory: 'Hostinger SQLite Engine',
      storageDrive: drive.mode,
      ciRunner: 'GitHub Actions 24/7',
    }, {
      tags: ['system', 'architecture'],
      summary: '4-pillar system architecture map',
    });
    memory.setMemory('system', 'heartbeat_count', 0, {
      tags: ['system', 'metrics'],
      summary: 'Total core memory heartbeat backup cycles completed',
    });
  }

  // Sync GitOps workflow definitions from workflows/ folder
  const synced = engine.syncFromDirectory();
  memory.logActivity('engine', `Booted Antigravity Flow Gen-1 (${synced.length} workflows synced)`, {
    meta: { driveMode: drive.mode, port: config.port },
  });

  if (config.schedulerEnabled) {
    scheduler.start();
  }

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
      const pathname = url.pathname;
      const method = (req.method || 'GET').toUpperCase();

      // CORS headers for tooling/remote Brain access
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key, X-Webhook-Secret');
      if (method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
      }

      // -----------------------------------------------------------------------
      // API Routes
      // -----------------------------------------------------------------------
      if (pathname.startsWith('/api/')) {
        // Public health check (no auth required so Hostinger/uptime probes work)
        if (pathname === '/api/health' && method === 'GET') {
          return sendJson(res, 200, {
            ok: true,
            service: 'antigravity-flow',
            generation: 'Gen-1',
            startedAt,
            uptimeSec: Math.round(process.uptime()),
            drive: drive.getInfo(),
          });
        }

        // Public Webhook Trigger Endpoint
        const webhookMatch = pathname.match(/^\/api\/webhooks\/([a-zA-Z0-9_-]+)$/);
        if (webhookMatch && method === 'POST') {
          const workflowId = webhookMatch[1];
          if (config.webhookSecret) {
            const supplied = req.headers['x-webhook-secret'] || url.searchParams.get('secret') || '';
            if (!safeEqual(String(supplied), config.webhookSecret)) {
              return sendJson(res, 401, { error: 'Invalid webhook secret' });
            }
          }
          const payload = await readJsonBody(req);
          const run = await engine.runWorkflow(workflowId, {
            triggerType: 'webhook',
            payload,
          });
          return sendJson(res, run.status === 'success' ? 200 : 500, { ok: run.status === 'success', run });
        }

        // Optional API key protection when ANTIGRAVITY_API_KEY is configured
        if (config.apiKey) {
          const authHeader = String(req.headers.authorization || '');
          const bearer = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
          const headerKey = String(req.headers['x-api-key'] || '');
          if (!safeEqual(bearer || headerKey, config.apiKey)) {
            return sendJson(res, 401, { error: 'Unauthorized: provide valid Authorization Bearer or X-API-Key' });
          }
        }

        // --- System Status & Architecture ---
        if (pathname === '/api/status' && method === 'GET') {
          const driveStats = await drive.getStats();
          return sendJson(res, 200, {
            service: 'antigravity-flow',
            generation: 'Gen-1',
            startedAt,
            uptimeSec: Math.round(process.uptime()),
            schedulerEnabled: config.schedulerEnabled,
            authProtected: Boolean(config.apiKey),
            memory: memory.getStats(),
            drive: driveStats,
            schedules: scheduler.getScheduledWorkflows(),
            github: {
              repository: config.github.repository,
              tokenConfigured: Boolean(config.github.token),
            },
            brain: {
              llmConfigured: Boolean(config.brain.apiKey),
              model: config.brain.apiKey ? config.brain.model : 'deterministic-local',
            },
          });
        }

        if (pathname === '/api/catalog' && method === 'GET') {
          return sendJson(res, 200, { nodes: NODE_CATALOG });
        }

        if (pathname === '/api/activity' && method === 'GET') {
          const limit = Number(url.searchParams.get('limit') || 60);
          return sendJson(res, 200, { items: memory.listActivity(limit) });
        }

        // --- Workflows CRUD & Execution ---
        if (pathname === '/api/workflows' && method === 'GET') {
          return sendJson(res, 200, { workflows: memory.listWorkflows() });
        }

        if (pathname === '/api/workflows' && method === 'POST') {
          const body = await readJsonBody(req);
          const persistToRepo = body.persistToRepo !== false;
          const definition = body.definition || body;
          const saved = engine.saveWorkflow(definition, { persistToRepo });
          return sendJson(res, 201, { workflow: saved });
        }

        if (pathname === '/api/workflows/sync' && method === 'POST') {
          const loaded = engine.syncFromDirectory();
          return sendJson(res, 200, { synced: loaded.length, workflows: loaded });
        }

        if (pathname === '/api/workflows/validate' && method === 'POST') {
          const body = await readJsonBody(req);
          return sendJson(res, 200, validateWorkflow(body.definition || body));
        }

        const wfRunMatch = pathname.match(/^\/api\/workflows\/([a-zA-Z0-9_-]+)\/run$/);
        if (wfRunMatch && method === 'POST') {
          const workflowId = wfRunMatch[1];
          const body = await readJsonBody(req);
          const run = await engine.runWorkflow(workflowId, {
            triggerType: body.triggerType || 'manual',
            payload: body.payload ?? {},
          });
          return sendJson(res, 200, { run });
        }

        const wfToggleMatch = pathname.match(/^\/api\/workflows\/([a-zA-Z0-9_-]+)\/toggle$/);
        if (wfToggleMatch && method === 'POST') {
          const wf = memory.getWorkflow(wfToggleMatch[1]);
          if (!wf) return sendJson(res, 404, { error: 'Workflow not found' });
          const nextDef = { ...wf.definition, enabled: !wf.enabled };
          const saved = engine.saveWorkflow(nextDef, { persistToRepo: wf.source.startsWith('workflows/') });
          return sendJson(res, 200, { workflow: saved });
        }

        const wfIdMatch = pathname.match(/^\/api\/workflows\/([a-zA-Z0-9_-]+)$/);
        if (wfIdMatch) {
          const id = wfIdMatch[1];
          if (method === 'GET') {
            const wf = memory.getWorkflow(id);
            if (!wf) return sendJson(res, 404, { error: 'Workflow not found' });
            return sendJson(res, 200, { workflow: wf });
          }
          if (method === 'PUT') {
            const body = await readJsonBody(req);
            const definition = { ...(body.definition || body), id };
            const saved = engine.saveWorkflow(definition, { persistToRepo: body.persistToRepo !== false });
            return sendJson(res, 200, { workflow: saved });
          }
          if (method === 'DELETE') {
            const deleted = memory.deleteWorkflow(id);
            return sendJson(res, deleted ? 200 : 404, { deleted });
          }
        }

        // --- Executions / Run History ---
        if (pathname === '/api/executions' && method === 'GET') {
          const workflowId = url.searchParams.get('workflowId') || '';
          const limit = Number(url.searchParams.get('limit') || 40);
          return sendJson(res, 200, { executions: memory.listExecutions({ workflowId, limit }) });
        }

        const execIdMatch = pathname.match(/^\/api\/executions\/([a-zA-Z0-9_-]+)$/);
        if (execIdMatch && method === 'GET') {
          const run = memory.getExecution(execIdMatch[1]);
          if (!run) return sendJson(res, 404, { error: 'Execution not found' });
          return sendJson(res, 200, { execution: run });
        }

        // --- Core Memory (Hostinger) ---
        if (pathname === '/api/memory' && method === 'GET') {
          const namespace = url.searchParams.get('namespace') || '';
          const tag = url.searchParams.get('tag') || '';
          const query = url.searchParams.get('query') || '';
          return sendJson(res, 200, {
            namespaces: memory.getNamespaces(),
            entries: memory.listMemory({ namespace, tag, query }),
          });
        }

        if (pathname === '/api/memory' && method === 'POST') {
          const body = await readJsonBody(req);
          if (!body.key) return sendJson(res, 400, { error: '"key" is required' });
          const entry = memory.setMemory(body.namespace || 'default', String(body.key), body.value, {
            tags: Array.isArray(body.tags) ? body.tags : [],
            summary: body.summary || '',
          });
          memory.logActivity('memory', `Stored ${entry.namespace}/${entry.key}`);
          return sendJson(res, 200, { entry });
        }

        if (pathname === '/api/memory/snapshot' && method === 'GET') {
          return sendJson(res, 200, memory.exportSnapshot());
        }

        const memDelMatch = pathname.match(/^\/api\/memory\/([^/]+)\/([^/]+)$/);
        if (memDelMatch && method === 'DELETE') {
          const ns = decodeURIComponent(memDelMatch[1]);
          const key = decodeURIComponent(memDelMatch[2]);
          const deleted = memory.deleteMemory(ns, key);
          if (deleted) memory.logActivity('memory', `Deleted ${ns}/${key}`);
          return sendJson(res, deleted ? 200 : 404, { deleted });
        }

        // --- Storage Drive (Google Drive / Local Sandbox) ---
        if (pathname === '/api/drive/files' && method === 'GET') {
          const prefix = url.searchParams.get('prefix') || '';
          const files = await drive.list({ prefix });
          return sendJson(res, 200, { info: drive.getInfo(), files });
        }

        if (pathname === '/api/drive/files' && method === 'POST') {
          const body = await readJsonBody(req);
          if (!body.name) return sendJson(res, 400, { error: '"name" is required' });
          const uploaded = await drive.upload({
            name: body.name,
            content: body.content ?? '',
            mimeType: body.mimeType || 'text/plain',
            overwrite: body.overwrite !== false,
          });
          memory.logActivity('drive', `Uploaded "${uploaded.name}" (${uploaded.size} bytes)`);
          return sendJson(res, 201, { file: uploaded });
        }

        const driveFileMatch = pathname.match(/^\/api\/drive\/files\/([^/]+)$/);
        if (driveFileMatch) {
          const fileId = decodeURIComponent(driveFileMatch[1]);
          if (method === 'GET') {
            const file = await drive.download({ fileId });
            return sendJson(res, 200, { file });
          }
          if (method === 'DELETE') {
            const result = await drive.delete({ fileId });
            if (result.deleted) memory.logActivity('drive', `Deleted drive file ${fileId}`);
            return sendJson(res, result.deleted ? 200 : 404, result);
          }
        }

        return sendJson(res, 404, { error: `API route not found: ${method} ${pathname}` });
      }

      // -----------------------------------------------------------------------
      // Static Visual Studio UI
      // -----------------------------------------------------------------------
      let relPath = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
      const fullPath = path.resolve(publicDir, relPath);
      if (!fullPath.startsWith(publicDir + path.sep) && fullPath !== publicDir) {
        res.writeHead(403);
        res.end('Forbidden');
        return;
      }

      if (fs.existsSync(fullPath) && fs.statSync(fullPath).isFile()) {
        const ext = path.extname(fullPath).toLowerCase();
        res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] || 'application/octet-stream' });
        fs.createReadStream(fullPath).pipe(res);
        return;
      }

      // SPA fallback
      const indexFile = path.join(publicDir, 'index.html');
      if (fs.existsSync(indexFile)) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        fs.createReadStream(indexFile).pipe(res);
        return;
      }

      res.writeHead(404);
      res.end('Not found');
    } catch (err) {
      const status = err.validationErrors ? 400 : 500;
      sendJson(res, status, {
        error: err.message || 'Internal Server Error',
        validationErrors: err.validationErrors || undefined,
      });
    }
  });

  return {
    config,
    memory,
    drive,
    engine,
    scheduler,
    server,
    start(port = config.port, host = config.host) {
      return new Promise((resolve) => {
        server.listen(port, host, () => {
          const addr = server.address();
          resolve({ port: addr.port, host: addr.address });
        });
      });
    },
    async stop() {
      scheduler.stop();
      await new Promise((resolve) => server.close(resolve));
      memory.close();
    },
  };
}

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
      if (raw.length > 5 * 1024 * 1024) {
        reject(new Error('Request payload exceeds 5MB limit'));
        req.destroy();
      }
    });
    req.on('end', () => {
      if (!raw.trim()) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new Error('Invalid JSON request body'));
      }
    });
    req.on('error', reject);
  });
}

function safeEqual(a, b) {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// Boot server when executed directly (`node src/server.mjs`)
const isDirect = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname);
if (isDirect) {
  const app = createApp();
  const { port, host } = await app.start();
  console.log(`Antigravity Flow Gen-1 running on http://${host}:${port}`);
  console.log(`Core Memory SQLite: ${app.config.dbPath}`);
  console.log(`Storage Drive Mode: ${app.drive.mode}`);

  const shutdown = async () => {
    console.log('\nShutting down Antigravity Flow Gen-1...');
    await app.stop();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
