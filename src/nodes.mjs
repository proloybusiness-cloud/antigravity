import { evaluateCondition } from './template.mjs';

/**
 * Metadata catalog describing all built-in nodes for the Visual Workflow Studio
 * and validation engine.
 */
export const NODE_CATALOG = [
  // --- Triggers ---
  {
    type: 'trigger.manual',
    category: 'trigger',
    label: 'Manual Trigger',
    description: 'Start workflow on demand from Antigravity, UI, or CLI.',
    defaultConfig: { samplePayload: {} },
  },
  {
    type: 'trigger.cron',
    category: 'trigger',
    label: 'Cron Schedule',
    description: 'Runs automatically 24/7 on a 5-field cron schedule.',
    defaultConfig: { schedule: '0 */6 * * *' },
  },
  {
    type: 'trigger.webhook',
    category: 'trigger',
    label: 'Webhook Listener',
    description: 'Receives live HTTP POST payloads at /api/webhooks/:workflowId.',
    defaultConfig: { requireSecret: false },
  },
  {
    type: 'trigger.github',
    category: 'trigger',
    label: 'GitHub Event',
    description: 'Triggered by GitHub Actions workflows or repository events.',
    defaultConfig: { event: 'workflow_dispatch' },
  },

  // --- Core Memory (Hostinger) ---
  {
    type: 'memory.read',
    category: 'memory',
    label: 'Memory Read',
    description: 'Read a structured key from Hostinger Core Memory.',
    defaultConfig: { namespace: 'default', key: '', defaultValue: null },
  },
  {
    type: 'memory.write',
    category: 'memory',
    label: 'Memory Write',
    description: 'Write, increment, or append to Hostinger Core Memory.',
    defaultConfig: { namespace: 'default', key: '', mode: 'set', value: '', tags: [], summary: '' },
  },
  {
    type: 'memory.search',
    category: 'memory',
    label: 'Memory Search',
    description: 'Query Hostinger Core Memory by namespace, tag, or text.',
    defaultConfig: { namespace: '', tag: '', query: '', limit: 25 },
  },
  {
    type: 'memory.snapshot',
    category: 'memory',
    label: 'Memory Snapshot',
    description: 'Export a complete snapshot of Core Memory for backup or audit.',
    defaultConfig: {},
  },

  // --- Storage Drive (Google Drive) ---
  {
    type: 'gdrive.upload',
    category: 'drive',
    label: 'Drive Upload',
    description: 'Upload or overwrite a file in Google Drive (or local sandbox).',
    defaultConfig: { name: 'output.json', mimeType: 'application/json', content: '', overwrite: true },
  },
  {
    type: 'gdrive.download',
    category: 'drive',
    label: 'Drive Download',
    description: 'Read file content from Google Drive by fileId or filename.',
    defaultConfig: { fileId: '', name: '' },
  },
  {
    type: 'gdrive.list',
    category: 'drive',
    label: 'Drive List',
    description: 'List files currently stored on Google Drive.',
    defaultConfig: { prefix: '', limit: 50 },
  },
  {
    type: 'gdrive.delete',
    category: 'drive',
    label: 'Drive Delete',
    description: 'Delete a file from Google Drive by fileId or filename.',
    defaultConfig: { fileId: '', name: '' },
  },

  // --- Logic, HTTP, GitHub & Brain ---
  {
    type: 'logic.condition',
    category: 'logic',
    label: 'IF Condition',
    description: 'Branch execution down true or false paths based on a rule.',
    defaultConfig: { left: '', operator: 'eq', right: '' },
  },
  {
    type: 'logic.transform',
    category: 'logic',
    label: 'Transform Data',
    description: 'Shape objects, build reports, or map fields between nodes.',
    defaultConfig: { output: {} },
  },
  {
    type: 'logic.delay',
    category: 'logic',
    label: 'Delay',
    description: 'Pause execution for a bounded number of milliseconds.',
    defaultConfig: { ms: 250 },
  },
  {
    type: 'http.request',
    category: 'integration',
    label: 'HTTP Request',
    description: 'Call any external REST API or webhook endpoint.',
    defaultConfig: { url: '', method: 'GET', headers: {}, body: null, timeoutMs: 10000 },
  },
  {
    type: 'github.api',
    category: 'integration',
    label: 'GitHub API',
    description: 'Read repo info, list commits/issues, or create issues on GitHub.',
    defaultConfig: { action: 'repo_summary', repository: '' },
  },
  {
    type: 'brain.summarize',
    category: 'brain',
    label: 'Brain Summarize',
    description: 'Synthesize structured briefs using configured LLM or local deterministic formatter.',
    defaultConfig: { title: 'Brief', prompt: 'Summarize the input clearly.', input: '' },
  },
];

export const NODE_CATALOG_MAP = new Map(NODE_CATALOG.map((n) => [n.type, n]));

/**
 * Executes a single node given its resolved configuration and runtime services.
 */
export async function executeNode(node, resolvedConfig, { memory, drive, config, trigger, executionId }) {
  switch (node.type) {
    // -------------------------------------------------------------------------
    // Triggers
    // -------------------------------------------------------------------------
    case 'trigger.manual':
    case 'trigger.cron':
    case 'trigger.webhook':
    case 'trigger.github':
      return {
        triggeredBy: trigger.type,
        timestamp: trigger.timestamp,
        payload: trigger.payload ?? resolvedConfig.samplePayload ?? {},
        schedule: resolvedConfig.schedule || null,
      };

    // -------------------------------------------------------------------------
    // Hostinger Core Memory
    // -------------------------------------------------------------------------
    case 'memory.read': {
      const ns = resolvedConfig.namespace || 'default';
      const key = String(resolvedConfig.key || '');
      if (!key) throw new Error('memory.read requires "key"');
      const entry = memory.getMemory(ns, key);
      return {
        found: Boolean(entry),
        namespace: ns,
        key,
        value: entry ? entry.value : resolvedConfig.defaultValue ?? null,
        updatedAt: entry?.updatedAt || null,
      };
    }

    case 'memory.write': {
      const ns = resolvedConfig.namespace || 'default';
      const key = String(resolvedConfig.key || '');
      if (!key) throw new Error('memory.write requires "key"');
      const mode = resolvedConfig.mode || 'set';
      let nextValue = resolvedConfig.value;

      if (mode === 'increment') {
        const existing = memory.getMemory(ns, key);
        const currentNum = Number(existing?.value ?? 0);
        const delta = Number(resolvedConfig.delta ?? resolvedConfig.value ?? 1);
        nextValue = (Number.isFinite(currentNum) ? currentNum : 0) + (Number.isFinite(delta) ? delta : 1);
      } else if (mode === 'append') {
        const existing = memory.getMemory(ns, key);
        const arr = Array.isArray(existing?.value) ? [...existing.value] : [];
        arr.push(resolvedConfig.value);
        const maxItems = Number(resolvedConfig.maxItems || 100);
        nextValue = arr.slice(-maxItems);
      }

      const saved = memory.setMemory(ns, key, nextValue, {
        tags: resolvedConfig.tags || [],
        summary: resolvedConfig.summary || '',
      });
      return {
        saved: true,
        mode,
        namespace: saved.namespace,
        key: saved.key,
        value: saved.value,
        updatedAt: saved.updatedAt,
      };
    }

    case 'memory.search': {
      const items = memory.listMemory({
        namespace: resolvedConfig.namespace || '',
        tag: resolvedConfig.tag || '',
        query: resolvedConfig.query || '',
        limit: Number(resolvedConfig.limit || 25),
      });
      return { count: items.length, items };
    }

    case 'memory.snapshot': {
      return memory.exportSnapshot();
    }

    // -------------------------------------------------------------------------
    // Google Drive Storage Layer
    // -------------------------------------------------------------------------
    case 'gdrive.upload': {
      const name = resolvedConfig.name;
      if (!name) throw new Error('gdrive.upload requires "name"');
      const uploaded = await drive.upload({
        name,
        content: resolvedConfig.content,
        mimeType: resolvedConfig.mimeType || inferMimeType(name),
        overwrite: resolvedConfig.overwrite !== false,
        metadata: { executionId, workflowNode: node.id },
      });
      return uploaded;
    }

    case 'gdrive.download': {
      return await drive.download({
        fileId: resolvedConfig.fileId || '',
        name: resolvedConfig.name || '',
      });
    }

    case 'gdrive.list': {
      const files = await drive.list({
        prefix: resolvedConfig.prefix || '',
        limit: Number(resolvedConfig.limit || 50),
      });
      return { mode: drive.mode, count: files.length, files };
    }

    case 'gdrive.delete': {
      return await drive.delete({
        fileId: resolvedConfig.fileId || '',
        name: resolvedConfig.name || '',
      });
    }

    // -------------------------------------------------------------------------
    // Logic & Transforms
    // -------------------------------------------------------------------------
    case 'logic.condition': {
      const passed = evaluateCondition({
        left: resolvedConfig.left,
        operator: resolvedConfig.operator || 'eq',
        right: resolvedConfig.right,
      });
      return {
        passed,
        branch: passed ? 'true' : 'false',
        left: resolvedConfig.left,
        operator: resolvedConfig.operator || 'eq',
        right: resolvedConfig.right,
      };
    }

    case 'logic.transform': {
      return resolvedConfig.output ?? resolvedConfig;
    }

    case 'logic.delay': {
      const ms = Math.min(Math.max(Number(resolvedConfig.ms || 100), 0), 15_000);
      await new Promise((resolve) => setTimeout(resolve, ms));
      return { delayedMs: ms };
    }

    // -------------------------------------------------------------------------
    // HTTP & GitHub Integrations
    // -------------------------------------------------------------------------
    case 'http.request': {
      const url = resolvedConfig.url;
      if (!url) throw new Error('http.request requires "url"');
      const method = String(resolvedConfig.method || 'GET').toUpperCase();
      const timeoutMs = Math.min(Number(resolvedConfig.timeoutMs || 10000), 30000);
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);

      try {
        const headers = { ...(resolvedConfig.headers || {}) };
        let body;
        if (resolvedConfig.body !== null && resolvedConfig.body !== undefined && method !== 'GET') {
          if (typeof resolvedConfig.body === 'object') {
            headers['Content-Type'] = headers['Content-Type'] || 'application/json';
            body = JSON.stringify(resolvedConfig.body);
          } else {
            body = String(resolvedConfig.body);
          }
        }
        const res = await fetch(url, { method, headers, body, signal: controller.signal });
        const rawText = await res.text();
        let parsed = rawText;
        try {
          parsed = JSON.parse(rawText);
        } catch {
          // keep text
        }
        return { ok: res.ok, status: res.status, data: parsed };
      } finally {
        clearTimeout(timer);
      }
    }

    case 'github.api': {
      const repo = resolvedConfig.repository || config.github.repository;
      const action = resolvedConfig.action || 'repo_summary';
      const token = config.github.token;
      const headers = {
        Accept: 'application/vnd.github+json',
        'User-Agent': 'antigravity-flow-gen1',
      };
      if (token) headers.Authorization = `Bearer ${token}`;

      try {
        if (action === 'repo_summary') {
          const [repoRes, commitsRes, issuesRes] = await Promise.all([
            fetch(`https://api.github.com/repos/${repo}`, { headers }),
            fetch(`https://api.github.com/repos/${repo}/commits?per_page=5`, { headers }),
            fetch(`https://api.github.com/repos/${repo}/issues?state=open&per_page=5`, { headers }),
          ]);
          const repoData = repoRes.ok ? await repoRes.json() : null;
          const commitsData = commitsRes.ok ? await commitsRes.json() : [];
          const issuesData = issuesRes.ok ? await issuesRes.json() : [];

          return {
            live: repoRes.ok,
            repository: repo,
            defaultBranch: repoData?.default_branch || 'main',
            private: repoData?.private ?? null,
            stars: repoData?.stargazers_count ?? 0,
            openIssuesCount: repoData?.open_issues_count ?? 0,
            recentCommits: Array.isArray(commitsData)
              ? commitsData.map((c) => ({
                  sha: c.sha?.slice(0, 7),
                  message: c.commit?.message?.split('\n')[0] || '',
                  author: c.commit?.author?.name || '',
                  date: c.commit?.author?.date || '',
                }))
              : [],
            openIssues: Array.isArray(issuesData)
              ? issuesData.map((i) => ({ number: i.number, title: i.title, state: i.state }))
              : [],
            fetchedAt: new Date().toISOString(),
          };
        }

        if (action === 'create_issue') {
          if (!token) {
            return {
              live: false,
              dryRun: true,
              repository: repo,
              title: resolvedConfig.title || 'Automated Issue',
              note: 'Set GITHUB_TOKEN to create live issues on GitHub.',
            };
          }
          const res = await fetch(`https://api.github.com/repos/${repo}/issues`, {
            method: 'POST',
            headers: { ...headers, 'Content-Type': 'application/json' },
            body: JSON.stringify({
              title: resolvedConfig.title || 'Antigravity Automated Issue',
              body: resolvedConfig.body || '',
              labels: resolvedConfig.labels || [],
            }),
          });
          const data = await res.json();
          if (!res.ok) throw new Error(`GitHub create_issue failed (${res.status}): ${data.message}`);
          return { live: true, number: data.number, url: data.html_url, title: data.title };
        }

        throw new Error(`Unknown github.api action: ${action}`);
      } catch (err) {
        if (resolvedConfig.allowOfflineFallback !== false) {
          return {
            live: false,
            repository: repo,
            fallbackReason: err.message,
            recentCommits: [],
            openIssues: [],
            fetchedAt: new Date().toISOString(),
          };
        }
        throw err;
      }
    }

    // -------------------------------------------------------------------------
    // Brain / AI Summarizer Node (Live LLM when key set, deterministic fallback)
    // -------------------------------------------------------------------------
    case 'brain.summarize': {
      const title = resolvedConfig.title || 'Antigravity Brief';
      const prompt = resolvedConfig.prompt || 'Summarize the following structured data clearly.';
      const inputData = resolvedConfig.input;
      const serialized =
        typeof inputData === 'string' ? inputData : JSON.stringify(inputData ?? {}, null, 2);

      if (config.brain.apiKey) {
        const res = await fetch(config.brain.apiUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${config.brain.apiKey}`,
          },
          body: JSON.stringify({
            model: config.brain.model,
            messages: [
              { role: 'system', content: 'You are Antigravity Brain, a concise operations analyst.' },
              { role: 'user', content: `${prompt}\n\nData:\n${serialized}` },
            ],
            temperature: 0.2,
          }),
        });
        if (res.ok) {
          const json = await res.json();
          const text = json.choices?.[0]?.message?.content?.trim() || '';
          return {
            mode: 'llm',
            model: config.brain.model,
            title,
            markdown: `# ${title}\n\n${text}\n`,
            generatedAt: new Date().toISOString(),
          };
        }
      }

      // Deterministic structured fallback so Gen-1 testing works offline/free
      const bullets = buildDeterministicBullets(inputData);
      const markdown = [
        `# ${title}`,
        '',
        `- **Generated:** ${new Date().toISOString()}`,
        `- **Engine:** Antigravity Brain (Gen-1 Deterministic Mode)`,
        `- **Prompt:** ${prompt}`,
        '',
        '## Key Details',
        ...bullets,
        '',
        '## Raw Payload',
        '```json',
        serialized.slice(0, 4000),
        '```',
        '',
      ].join('\n');

      return {
        mode: 'deterministic-local',
        title,
        bulletCount: bullets.length,
        markdown,
        generatedAt: new Date().toISOString(),
      };
    }

    default:
      throw new Error(`Unsupported node type: ${node.type}`);
  }
}

function inferMimeType(name) {
  const lower = String(name).toLowerCase();
  if (lower.endsWith('.json')) return 'application/json';
  if (lower.endsWith('.md')) return 'text/markdown';
  if (lower.endsWith('.csv')) return 'text/csv';
  if (lower.endsWith('.html')) return 'text/html';
  return 'text/plain';
}

function buildDeterministicBullets(data) {
  if (data === null || data === undefined) return ['- No input payload supplied.'];
  if (typeof data !== 'object') return [`- Value: ${String(data)}`];
  if (Array.isArray(data)) {
    return [
      `- Total items: ${data.length}`,
      ...data.slice(0, 5).map((item, idx) => `- Item ${idx + 1}: ${shortVal(item)}`),
    ];
  }
  const entries = Object.entries(data);
  if (!entries.length) return ['- Empty object payload.'];
  return entries.slice(0, 12).map(([k, v]) => `- **${k}:** ${shortVal(v)}`);
}

function shortVal(v) {
  if (v === null || v === undefined) return 'null';
  if (typeof v === 'object') {
    if (Array.isArray(v)) return `[${v.length} items]`;
    const str = JSON.stringify(v);
    return str.length > 100 ? `${str.slice(0, 97)}...` : str;
  }
  const str = String(v);
  return str.length > 120 ? `${str.slice(0, 117)}...` : str;
}
