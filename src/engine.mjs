import fs from 'node:fs';
import path from 'node:path';
import { resolveTemplates } from './template.mjs';
import { executeNode, NODE_CATALOG_MAP } from './nodes.mjs';

/**
 * Validates a workflow JSON DAG definition and returns a topological node order.
 */
export function validateWorkflow(definition) {
  const errors = [];
  if (!definition || typeof definition !== 'object') {
    return { valid: false, errors: ['Workflow must be an object'], order: [] };
  }
  if (!definition.id || !/^[a-zA-Z0-9_-]+$/.test(definition.id)) {
    errors.push('Workflow "id" is required and must use letters, digits, "_" or "-"');
  }
  if (!definition.name || typeof definition.name !== 'string') {
    errors.push('Workflow "name" is required');
  }
  if (!Array.isArray(definition.nodes) || definition.nodes.length === 0) {
    errors.push('Workflow must define at least one node in "nodes"');
  }
  if (!Array.isArray(definition.edges)) {
    errors.push('Workflow must define an "edges" array');
  }
  if (errors.length > 0) {
    return { valid: false, errors, order: [] };
  }

  const nodeMap = new Map();
  for (const node of definition.nodes) {
    if (!node.id) {
      errors.push('Every node requires an "id"');
      continue;
    }
    if (nodeMap.has(node.id)) {
      errors.push(`Duplicate node id: "${node.id}"`);
    }
    if (!NODE_CATALOG_MAP.has(node.type)) {
      errors.push(`Unknown node type "${node.type}" on node "${node.id}"`);
    }
    nodeMap.set(node.id, node);
  }

  const inDegree = new Map();
  const adj = new Map();
  for (const id of nodeMap.keys()) {
    inDegree.set(id, 0);
    adj.set(id, []);
  }

  for (const edge of definition.edges) {
    if (!nodeMap.has(edge.from) || !nodeMap.has(edge.to)) {
      errors.push(`Edge references missing node: ${edge.from} -> ${edge.to}`);
      continue;
    }
    if (edge.from === edge.to) {
      errors.push(`Self-loop edge not allowed on node "${edge.from}"`);
      continue;
    }
    adj.get(edge.from).push(edge.to);
    inDegree.set(edge.to, (inDegree.get(edge.to) || 0) + 1);
  }

  // Kahn's topological sort for DAG verification
  const queue = [];
  for (const [id, deg] of inDegree.entries()) {
    if (deg === 0) queue.push(id);
  }
  const order = [];
  while (queue.length > 0) {
    const id = queue.shift();
    order.push(id);
    for (const next of adj.get(id) || []) {
      const nextDeg = inDegree.get(next) - 1;
      inDegree.set(next, nextDeg);
      if (nextDeg === 0) queue.push(next);
    }
  }

  if (order.length !== nodeMap.size) {
    errors.push('Workflow graph contains a cycle (must be a DAG)');
  }

  return { valid: errors.length === 0, errors, order };
}

/**
 * WorkflowEngine loads GitOps workflow definitions, persists them in Hostinger
 * Core Memory, and executes DAG graphs with full step tracing and branching.
 */
export class WorkflowEngine {
  constructor({ config, memory, drive }) {
    this.config = config;
    this.memory = memory;
    this.drive = drive;
  }

  /**
   * Syncs workflow JSON files from `workflows/` directory into Core Memory.
   */
  syncFromDirectory(dir = this.config.workflowsDir) {
    if (!fs.existsSync(dir)) return [];
    const files = fs
      .readdirSync(dir)
      .filter((f) => f.endsWith('.json'))
      .sort();

    const loaded = [];
    for (const file of files) {
      const fullPath = path.join(dir, file);
      const raw = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
      const check = validateWorkflow(raw);
      if (!check.valid) {
        this.memory.logActivity('engine', `Skipped invalid workflow file ${file}`, {
          level: 'warn',
          meta: { errors: check.errors },
        });
        continue;
      }
      const saved = this.memory.upsertWorkflow(raw, { source: `workflows/${file}` });
      loaded.push(saved);
    }
    return loaded;
  }

  /**
   * Saves a workflow both to Core Memory and (optionally) back to `workflows/<id>.json`
   * so changes made in the UI or via API stay GitOps-friendly.
   */
  saveWorkflow(definition, { persistToRepo = true } = {}) {
    const check = validateWorkflow(definition);
    if (!check.valid) {
      const err = new Error(`Invalid workflow: ${check.errors.join('; ')}`);
      err.validationErrors = check.errors;
      throw err;
    }

    let source = 'api';
    if (persistToRepo && this.config.workflowsDir) {
      fs.mkdirSync(this.config.workflowsDir, { recursive: true });
      const filePath = path.join(this.config.workflowsDir, `${definition.id}.json`);
      fs.writeFileSync(filePath, JSON.stringify(definition, null, 2) + '\n', 'utf8');
      source = `workflows/${definition.id}.json`;
    }

    const saved = this.memory.upsertWorkflow(definition, { source });
    this.memory.logActivity('brain', `Saved workflow "${saved.name}" (${saved.id})`, {
      meta: { source, nodeCount: definition.nodes.length },
    });
    return saved;
  }

  /**
   * Executes a workflow DAG end-to-end, storing run & step traces in Core Memory.
   */
  async runWorkflow(workflowId, { triggerType = 'manual', payload = {} } = {}) {
    const record = this.memory.getWorkflow(workflowId);
    if (!record) {
      throw new Error(`Workflow not found: ${workflowId}`);
    }
    const def = record.definition;
    const validation = validateWorkflow(def);
    if (!validation.valid) {
      throw new Error(`Workflow "${workflowId}" failed validation: ${validation.errors.join('; ')}`);
    }

    const runStartedMs = Date.now();
    const triggerTimestamp = new Date().toISOString();
    const executionId = this.memory.createExecution({
      workflowId: record.id,
      workflowName: record.name,
      triggerType,
      input: payload,
    });

    this.memory.logActivity('engine', `Started workflow "${record.name}" (${triggerType})`, {
      meta: { executionId, workflowId: record.id },
    });

    const nodeMap = new Map(def.nodes.map((n) => [n.id, n]));
    const incomingEdges = new Map(def.nodes.map((n) => [n.id, []]));
    for (const edge of def.edges) {
      incomingEdges.get(edge.to).push(edge);
    }

    const nodeOutputs = {};
    const nodeStatus = {};
    let lastOutput = null;

    try {
      for (const nodeId of validation.order) {
        const node = nodeMap.get(nodeId);
        const incoming = incomingEdges.get(nodeId) || [];

        // Determine whether this node is activated by its incoming edges
        if (incoming.length > 0) {
          const activeIncoming = incoming.some((edge) => {
            if (nodeStatus[edge.from] !== 'success') return false;
            if (!edge.when) return true;
            const parentOut = nodeOutputs[edge.from];
            return String(parentOut?.branch ?? '') === String(edge.when);
          });

          if (!activeIncoming) {
            nodeStatus[nodeId] = 'skipped';
            const now = new Date().toISOString();
            this.memory.recordStep({
              executionId,
              nodeId: node.id,
              nodeName: node.name || node.id,
              nodeType: node.type,
              status: 'skipped',
              startedAt: now,
              finishedAt: now,
              durationMs: 0,
            });
            continue;
          }
        }

        const stepStartMs = Date.now();
        const stepStartedAt = new Date().toISOString();

        // Build fresh template context with latest Core Memory snapshot
        const templateCtx = {
          $runId: executionId,
          $now: new Date().toISOString(),
          $date: new Date().toISOString().slice(0, 10),
          $workflow: { id: record.id, name: record.name },
          $trigger: { type: triggerType, timestamp: triggerTimestamp, payload },
          $nodes: Object.fromEntries(
            Object.entries(nodeOutputs).map(([id, out]) => [id, { output: out }])
          ),
          $memory: this.memory.getMemoryMap(),
        };

        const resolvedConfig = resolveTemplates(node.config || {}, templateCtx);

        try {
          const output = await executeNode(node, resolvedConfig, {
            memory: this.memory,
            drive: this.drive,
            config: this.config,
            trigger: { type: triggerType, timestamp: triggerTimestamp, payload },
            executionId,
          });

          nodeOutputs[nodeId] = output;
          nodeStatus[nodeId] = 'success';
          lastOutput = output;

          this.memory.recordStep({
            executionId,
            nodeId: node.id,
            nodeName: node.name || node.id,
            nodeType: node.type,
            status: 'success',
            input: resolvedConfig,
            output,
            startedAt: stepStartedAt,
            finishedAt: new Date().toISOString(),
            durationMs: Date.now() - stepStartMs,
          });
        } catch (stepErr) {
          nodeStatus[nodeId] = 'failed';
          this.memory.recordStep({
            executionId,
            nodeId: node.id,
            nodeName: node.name || node.id,
            nodeType: node.type,
            status: 'failed',
            input: resolvedConfig,
            error: stepErr.message,
            startedAt: stepStartedAt,
            finishedAt: new Date().toISOString(),
            durationMs: Date.now() - stepStartMs,
          });
          throw new Error(`Node "${node.name || node.id}" (${node.type}) failed: ${stepErr.message}`);
        }
      }

      const finalRun = this.memory.finishExecution(executionId, {
        status: 'success',
        output: lastOutput,
        durationMs: Date.now() - runStartedMs,
      });

      this.memory.logActivity('engine', `Completed workflow "${record.name}" in ${finalRun.durationMs}ms`, {
        meta: { executionId, workflowId: record.id },
      });
      return finalRun;
    } catch (runErr) {
      const failedRun = this.memory.finishExecution(executionId, {
        status: 'failed',
        error: runErr.message,
        durationMs: Date.now() - runStartedMs,
      });

      this.memory.logActivity('engine', `Failed workflow "${record.name}": ${runErr.message}`, {
        level: 'error',
        meta: { executionId, workflowId: record.id },
      });
      return failedRun;
    }
  }
}
