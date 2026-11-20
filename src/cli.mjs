#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { getConfig } from './config.mjs';
import { CoreMemory } from './memory.mjs';
import { StorageDrive } from './drive.mjs';
import { WorkflowEngine, validateWorkflow } from './engine.mjs';

/**
 * Antigravity Brain CLI — lets Antigravity (or you) inspect, plan, validate,
 * and execute workflows locally, inside GitHub Actions, or remotely against
 * a deployed Hostinger instance via ANTIGRAVITY_REMOTE_URL.
 */
const args = process.argv.slice(2);
const [group, action, ...rest] = args;

const config = getConfig();

function parseFlags(tokens) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.startsWith('--')) {
      const key = t.slice(2);
      const next = tokens[i + 1];
      if (!next || next.startsWith('--')) {
        flags[key] = true;
      } else {
        flags[key] = next;
        i++;
      }
    } else {
      positional.push(t);
    }
  }
  return { flags, positional };
}

async function remoteFetch(apiPath, { method = 'GET', body } = {}) {
  const url = `${config.remoteUrl.replace(/\/+$/, '')}${apiPath}`;
  const headers = { 'Content-Type': 'application/json' };
  if (config.apiKey) headers.Authorization = `Bearer ${config.apiKey}`;
  const res = await fetch(url, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

async function main() {
  if (!group || group === 'help' || group === '--help') {
    console.log(`Antigravity Brain CLI (Gen-1)

Usage:
  node src/cli.mjs status
  node src/cli.mjs workflows list
  node src/cli.mjs workflows validate
  node src/cli.mjs workflows run <workflowId> [--input '{"key":"val"}']
  node src/cli.mjs workflows run-scheduled [--runner github|hostinger|both]
  node src/cli.mjs memory list [--namespace <ns>]
  node src/cli.mjs memory set <namespace> <key> <jsonOrString>
  node src/cli.mjs memory get <namespace> <key>
  node src/cli.mjs drive list
  node src/cli.mjs drive upload <name> <content>
  node src/cli.mjs runs list

Set ANTIGRAVITY_REMOTE_URL + ANTIGRAVITY_API_KEY to control your live Hostinger engine remotely.`);
    return;
  }

  const { flags, positional } = parseFlags(rest);

  // Remote Hostinger mode when ANTIGRAVITY_REMOTE_URL is set (except local validate)
  if (config.remoteUrl && !(group === 'workflows' && action === 'validate')) {
    if (group === 'status') {
      console.log(JSON.stringify(await remoteFetch('/api/status'), null, 2));
      return;
    }
    if (group === 'workflows' && action === 'list') {
      console.log(JSON.stringify(await remoteFetch('/api/workflows'), null, 2));
      return;
    }
    if (group === 'workflows' && action === 'run') {
      const id = positional[0];
      const payload = flags.input ? JSON.parse(flags.input) : {};
      console.log(
        JSON.stringify(
          await remoteFetch(`/api/workflows/${encodeURIComponent(id)}/run`, {
            method: 'POST',
            body: { triggerType: 'brain-cli', payload },
          }),
          null,
          2
        )
      );
      return;
    }
    if (group === 'memory' && action === 'list') {
      const qs = flags.namespace ? `?namespace=${encodeURIComponent(flags.namespace)}` : '';
      console.log(JSON.stringify(await remoteFetch(`/api/memory${qs}`), null, 2));
      return;
    }
    if (group === 'memory' && action === 'set') {
      const [ns, key, rawVal] = positional;
      let value = rawVal;
      try {
        value = JSON.parse(rawVal);
      } catch {
        // keep string
      }
      console.log(
        JSON.stringify(
          await remoteFetch('/api/memory', { method: 'POST', body: { namespace: ns, key, value } }),
          null,
          2
        )
      );
      return;
    }
    if (group === 'drive' && action === 'list') {
      console.log(JSON.stringify(await remoteFetch('/api/drive/files'), null, 2));
      return;
    }
    if (group === 'runs' && action === 'list') {
      console.log(JSON.stringify(await remoteFetch('/api/executions'), null, 2));
      return;
    }
  }

  // Local / GitHub Actions execution mode
  if (group === 'workflows' && action === 'validate') {
    const dir = config.workflowsDir;
    const files = fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith('.json')).sort() : [];
    let allValid = true;
    for (const file of files) {
      const def = JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8'));
      const res = validateWorkflow(def);
      if (res.valid) {
        console.log(`PASS  ${file} (${def.id}: ${def.nodes.length} nodes, ${def.edges.length} edges)`);
      } else {
        allValid = false;
        console.error(`FAIL  ${file}: ${res.errors.join('; ')}`);
      }
    }
    if (!allValid) process.exit(1);
    console.log(`Validated ${files.length} workflow file(s) successfully.`);
    return;
  }

  const memory = new CoreMemory(config.dbPath);
  const drive = new StorageDrive(config);
  const engine = new WorkflowEngine({ config, memory, drive });
  engine.syncFromDirectory();

  try {
    if (group === 'status') {
      console.log(
        JSON.stringify(
          {
            generation: 'Gen-1',
            memory: memory.getStats(),
            drive: await drive.getStats(),
            workflows: memory.listWorkflows().map((w) => ({
              id: w.id,
              name: w.name,
              runner: w.runner,
              enabled: w.enabled,
            })),
          },
          null,
          2
        )
      );
      return;
    }

    if (group === 'workflows' && action === 'list') {
      for (const wf of memory.listWorkflows()) {
        console.log(
          `${wf.enabled ? '[ON ]' : '[OFF]'} ${wf.id.padEnd(28)} runner=${wf.runner.padEnd(10)} "${wf.name}"`
        );
      }
      return;
    }

    if (group === 'workflows' && action === 'run') {
      const id = positional[0];
      if (!id) throw new Error('Specify a workflow ID to run');
      const payload = flags.input ? JSON.parse(flags.input) : {};
      const run = await engine.runWorkflow(id, { triggerType: 'cli', payload });
      console.log(JSON.stringify(run, null, 2));
      if (run.status !== 'success') process.exit(1);
      return;
    }

    if (group === 'workflows' && action === 'run-scheduled') {
      const runnerFilter = flags.runner || 'github';
      const matching = memory.listWorkflows().filter((wf) => {
        if (!wf.enabled) return false;
        if (runnerFilter === 'all') return true;
        return wf.runner === runnerFilter || wf.runner === 'both';
      });
      console.log(`Running ${matching.length} scheduled workflow(s) for runner="${runnerFilter}"...`);
      let failed = 0;
      for (const wf of matching) {
        const run = await engine.runWorkflow(wf.id, {
          triggerType: 'github-actions-cron',
          payload: { runner: runnerFilter, triggeredAt: new Date().toISOString() },
        });
        console.log(`- ${wf.id}: ${run.status} (${run.durationMs}ms)`);
        if (run.status !== 'success') failed++;
      }
      if (failed > 0) process.exit(1);
      return;
    }

    if (group === 'memory' && action === 'list') {
      console.log(JSON.stringify(memory.listMemory({ namespace: flags.namespace || '' }), null, 2));
      return;
    }

    if (group === 'memory' && action === 'get') {
      const [ns, key] = positional;
      console.log(JSON.stringify(memory.getMemory(ns, key), null, 2));
      return;
    }

    if (group === 'memory' && action === 'set') {
      const [ns, key, rawVal] = positional;
      let value = rawVal;
      try {
        value = JSON.parse(rawVal);
      } catch {
        // keep string
      }
      console.log(JSON.stringify(memory.setMemory(ns, key, value), null, 2));
      return;
    }

    if (group === 'drive' && action === 'list') {
      console.log(JSON.stringify(await drive.list(), null, 2));
      return;
    }

    if (group === 'drive' && action === 'upload') {
      const [name, content] = positional;
      console.log(JSON.stringify(await drive.upload({ name, content: content ?? '' }), null, 2));
      return;
    }

    if (group === 'runs' && action === 'list') {
      console.log(JSON.stringify(memory.listExecutions({ limit: 20 }), null, 2));
      return;
    }

    throw new Error(`Unknown command: ${args.join(' ')}`);
  } finally {
    memory.close();
  }
}

main().catch((err) => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});
