/**
 * Safe deterministic expression resolver & condition evaluator for n8n-style
 * `{{ ... }}` workflow templates. Never uses eval() or new Function().
 */

const EXACT_EXPR_RE = /^\{\{\s*([^}]+?)\s*\}\}$/;
const INTERPOLATE_RE = /\{\{\s*([^}]+?)\s*\}\}/g;

/**
 * Resolves a dot/bracket path like `$nodes.fetch.output.items[0].title`
 * against the execution context object.
 */
export function resolvePath(expr, ctx) {
  const trimmed = String(expr).trim();
  if (!trimmed) return undefined;

  // Support string, number, boolean, null literals inside templates
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1);
  }
  if (trimmed === 'true') return true;
  if (trimmed === 'false') return false;
  if (trimmed === 'null') return null;
  if (/^-?\d+(\.\d+)?$/.test(trimmed)) return Number(trimmed);

  // Support fallback operator: `expr ?? fallback`
  if (trimmed.includes('??')) {
    const parts = trimmed.split('??');
    for (const part of parts) {
      const val = resolvePath(part, ctx);
      if (val !== undefined && val !== null && val !== '') {
        return val;
      }
    }
    return undefined;
  }

  // Support `| json` or `| upper` or `| lower` or `| length` filters
  const pipeIdx = trimmed.indexOf('|');
  if (pipeIdx > 0) {
    const left = resolvePath(trimmed.slice(0, pipeIdx), ctx);
    const filter = trimmed.slice(pipeIdx + 1).trim();
    if (filter === 'json') return JSON.stringify(left, null, 2);
    if (filter === 'compactJson') return JSON.stringify(left);
    if (filter === 'upper') return String(left ?? '').toUpperCase();
    if (filter === 'lower') return String(left ?? '').toLowerCase();
    if (filter === 'length') {
      if (Array.isArray(left) || typeof left === 'string') return left.length;
      if (left && typeof left === 'object') return Object.keys(left).length;
      return 0;
    }
    return left;
  }

  // Parse path segments supporting dot notation and array indices
  const segments = trimmed
    .replace(/\[(\d+)\]/g, '.$1')
    .replace(/\[["']([^"']+)["']\]/g, '.$1')
    .split('.')
    .filter(Boolean);

  let current = ctx;
  for (const seg of segments) {
    if (current === null || current === undefined) return undefined;
    if (seg === '__proto__' || seg === 'constructor' || seg === 'prototype') {
      return undefined;
    }
    current = current[seg];
  }
  return current;
}

/**
 * Recursively resolves all `{{ ... }}` templates inside strings, arrays, and objects.
 */
export function resolveTemplates(value, ctx) {
  if (typeof value === 'string') {
    const exactMatch = value.match(EXACT_EXPR_RE);
    if (exactMatch) {
      const resolved = resolvePath(exactMatch[1], ctx);
      return resolved === undefined ? '' : resolved;
    }
    if (!value.includes('{{')) return value;
    return value.replace(INTERPOLATE_RE, (_m, expr) => {
      const resolved = resolvePath(expr, ctx);
      if (resolved === undefined || resolved === null) return '';
      if (typeof resolved === 'object') return JSON.stringify(resolved);
      return String(resolved);
    });
  }

  if (Array.isArray(value)) {
    return value.map((item) => resolveTemplates(item, ctx));
  }

  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = resolveTemplates(v, ctx);
    }
    return out;
  }

  return value;
}

/**
 * Evaluates a declarative condition rule safely.
 */
export function evaluateCondition({ left, operator = 'eq', right }) {
  switch (operator) {
    case 'eq':
    case 'equals':
      return left === right || String(left) === String(right);
    case 'neq':
    case 'not_equals':
      return left !== right && String(left) !== String(right);
    case 'gt':
      return Number(left) > Number(right);
    case 'gte':
      return Number(left) >= Number(right);
    case 'lt':
      return Number(left) < Number(right);
    case 'lte':
      return Number(left) <= Number(right);
    case 'contains':
      if (Array.isArray(left)) return left.includes(right);
      return String(left ?? '').toLowerCase().includes(String(right ?? '').toLowerCase());
    case 'not_contains':
      if (Array.isArray(left)) return !left.includes(right);
      return !String(left ?? '').toLowerCase().includes(String(right ?? '').toLowerCase());
    case 'exists':
      return left !== undefined && left !== null && left !== '';
    case 'empty':
      return (
        left === undefined ||
        left === null ||
        left === '' ||
        (Array.isArray(left) && left.length === 0)
      );
    case 'truthy':
      return Boolean(left) && left !== 'false' && left !== '0';
    case 'regex':
      try {
        return new RegExp(String(right), 'i').test(String(left ?? ''));
      } catch {
        return false;
      }
    default:
      throw new Error(`Unsupported condition operator: ${operator}`);
  }
}
