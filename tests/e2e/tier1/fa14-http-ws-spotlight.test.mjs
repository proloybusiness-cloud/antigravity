/**
 * OmniOS Tier 1 E2E Suite — FA-14: Unified Bootstrapper, HTTP REST v1, RFC 6455 WS & Spotlight Search
 * Covers PROJECT.md Features: F-061, F-062, F-063, F-064.
 *
 * STRICT INVARIANTS:
 * - Opaque-box only: imports ONLY Node 24 built-ins and ../lib/*.mjs.
 * - Zero skips, zero stubs, zero hardcoded app outputs.
 * - Clean try/finally teardown on every test.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { loadPublicOmniOS, startOmniServer } from '../lib/env.mjs';
import { buildCustomUapp } from '../lib/fixtures-apple-wasm.mjs';

function makeNonce() {
  return crypto.randomBytes(4).toString('hex');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitUntil(fn, { timeoutMs = 5000, intervalMs = 40, label = 'condition' } = {}) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const value = await fn();
      if (value) return value;
    } catch (err) {
      lastError = err;
    }
    const remaining = deadline - Date.now();
    if (remaining > 0) await sleep(Math.min(intervalMs, remaining));
  }
  throw new Error(
    `Timed out after ${timeoutMs}ms waiting for ${label}` +
    (lastError ? ` (last error: ${lastError.message})` : '')
  );
}

function asArray(payload, keys = ['items', 'data', 'processes', 'services', 'users', 'packages', 'results', 'windows', 'entries']) {
  if (Array.isArray(payload)) return payload;
  if (payload && typeof payload === 'object') {
    for (const k of keys) {
      if (Array.isArray(payload[k])) return payload[k];
    }
  }
  return [];
}

async function writeWithMethodFallback(api, methods, urlPath, body, opts = {}) {
  let lastRes = null;
  for (const method of methods) {
    const res = await api.request(method, urlPath, { ...opts, body });
    lastRes = res;
    if (res.ok) return res;
    if (res.status !== 404 && res.status !== 405) return res;
  }
  return lastRes;
}

async function installPackageHttp(api, bytes, filename) {
  let res = await api.post('/api/v1/packages/install', bytes, {
    query: { filename, grantAll: 'true' },
    headers: {
      'content-type': 'application/octet-stream',
      'x-filename': filename,
    },
  });
  if (res.status === 400 || res.status === 415 || res.status === 422) {
    const b64 = Buffer.from(bytes).toString('base64');
    res = await api.post('/api/v1/packages/install', {
      base64: b64,
      data: b64,
      filename,
      grantAll: true,
    });
  }
  assert.ok(res.ok, `Expected HTTP 2xx installing ${filename}, got ${res.status}: ${res.text}`);
  return res.json;
}

const SYSTEM_APP_ROLES = [
  { role: 'terminal', preferredId: 'sys.terminal', pattern: /omniterm|terminal/i },
  { role: 'files', preferredId: 'sys.files', pattern: /omnifiles|files/i },
  { role: 'monitor', preferredId: 'sys.monitor', pattern: /monitor|task/i },
  { role: 'apphub', preferredId: 'sys.apphub', pattern: /apphub|app[\s_-]*hub/i },
  { role: 'settings', preferredId: 'sys.settings', pattern: /settings|privacy/i },
  { role: 'inspector', preferredId: 'sys.inspector', pattern: /inspector/i },
  { role: 'notes', preferredId: 'sys.notes', pattern: /omninotes|notes/i },
];

function normalizeAppEntries(source, { markBuiltin = false, fromInstalled = false } = {}) {
  const out = [];
  if (!source) return out;
  const add = (item, keyHint = '') => {
    if (typeof item === 'string') {
      const id = item.trim();
      if (id) out.push({ appId: id, name: id, platform: '', isBuiltin: markBuiltin, fromInstalled });
      return;
    }
    if (!item || typeof item !== 'object') return;
    const appId = String(item.appId ?? item.id ?? keyHint ?? '').trim();
    if (!appId) return;
    const name = String(item.name ?? item.title ?? item.displayName ?? item.label ?? '').trim();
    const platform = String(item.platform ?? '').toLowerCase();
    const isBuiltin = Boolean(
      markBuiltin ||
      item.builtin ||
      item.builtIn ||
      item.isSystem ||
      item.system ||
      item.kind === 'system' ||
      item.type === 'system' ||
      platform === 'system' ||
      /^(?:sys|system|builtin)\./i.test(appId)
    );
    out.push({ appId, name, platform, isBuiltin, fromInstalled });
  };

  if (Array.isArray(source)) {
    for (const item of source) add(item);
  } else if (source instanceof Map) {
    for (const [k, v] of source.entries()) add(v, String(k));
  } else if (typeof source === 'object') {
    const arr = asArray(source, ['packages', 'apps', 'catalog', 'items', 'data', 'entries']);
    if (arr.length > 0) {
      for (const item of arr) add(item);
    } else {
      for (const [k, v] of Object.entries(source)) add(v, k);
    }
  }
  return out;
}

function resolveBuiltInSystemApps(candidates, contextLabel = 'packages') {
  const byId = new Map();
  for (const c of candidates) {
    if (!c?.appId) continue;
    const prev = byId.get(c.appId);
    if (!prev) {
      byId.set(c.appId, { ...c });
    } else {
      byId.set(c.appId, {
        appId: c.appId,
        name: prev.name || c.name,
        platform: prev.platform || c.platform,
        isBuiltin: prev.isBuiltin || c.isBuiltin,
        fromInstalled: prev.fromInstalled || c.fromInstalled,
      });
    }
  }

  const list = Array.from(byId.values());
  const resolved = {};
  const used = new Set();

  for (const { role, preferredId, pattern } of SYSTEM_APP_ROLES) {
    const matches = list
      .filter((c) => !used.has(c.appId) && (c.appId === preferredId || pattern.test(c.appId) || pattern.test(c.name)))
      .map((c) => {
        let score = 0;
        if (c.fromInstalled) score += 200;
        if (c.appId === preferredId) score += 50;
        if (c.isBuiltin) score += 40;
        if (!c.platform || c.platform === 'system' || c.platform === 'universal' || c.platform === 'omnios') score += 10;
        if (/sharer/i.test(`${c.appId} ${c.name}`)) score -= 25;
        return { c, score };
      })
      .sort((a, b) => b.score - a.score);

    assert.ok(
      matches.length > 0,
      `Expected built-in system app for role "${role}" in ${contextLabel}, discovered candidates: ${JSON.stringify(list)}`
    );
    resolved[role] = matches[0].c.appId;
    used.add(matches[0].c.appId);
  }

  assert.equal(
    new Set(Object.values(resolved)).size,
    SYSTEM_APP_ROLES.length,
    `Expected 7 distinct built-in system apps in ${contextLabel}, resolved: ${JSON.stringify(resolved)}`
  );
  return resolved;
}

async function discoverSystemAppsHttp(api) {
  const candidates = [];
  const pkgRes = await api.get('/api/v1/packages', { expectOk: true });
  candidates.push(...normalizeAppEntries(pkgRes.json, { fromInstalled: true }));
  const catRes = await api.get('/api/v1/packages/catalog');
  if (catRes.ok && catRes.json !== null) {
    candidates.push(...normalizeAppEntries(catRes.json, { fromInstalled: false }));
  }
  return resolveBuiltInSystemApps(candidates, 'GET /api/v1/packages (+catalog)');
}

async function setSystemConfigHttp(api, key, value) {
  const shortKey = key.startsWith('system.') ? key.slice('system.'.length) : key;
  const fullKey = key.startsWith('system.') ? key : `system.${key}`;
  const candidates = [
    { [shortKey]: value },
    { [fullKey]: value },
    { key: fullKey, value },
    { key: shortKey, value },
  ];

  for (const body of candidates) {
    const res = await writeWithMethodFallback(api, ['PUT', 'PATCH', 'POST'], '/api/v1/config/system', body);
    if (!res.ok) continue;
    const verify = await api.get('/api/v1/config/system', { expectOk: true });
    const cfg = verify.json?.system ?? verify.json?.config ?? verify.json ?? {};
    const cur = cfg[shortKey] ?? cfg[fullKey];
    if (cur === value) return verify.json;
  }
  throw new Error(`Failed to update /api/v1/config/system ${key}=${JSON.stringify(value)}`);
}

describe('Tier 1 — FA-14: Unified Bootstrapper, HTTP REST v1, RFC 6455 WS & Spotlight Search', () => {
  it('T1-FA14-01 [F-061]: createOmniOS(config) unified bootstrapper wiring all subsystems, 6 core services, 4 CPU engines, 5 platforms & 7 system apps', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();

      const diag = osHandle.require('kernel').getDiagnostics();
      assert.equal(diag.state, 'RUNNING', `Expected RUNNING kernel state, got: ${JSON.stringify(diag)}`);

      // Contract 1–6 subsystems
      for (const name of [
        'serviceManager',
        'processManager',
        'scheduler',
        'vfs',
        'pathTranslator',
        'configStore',
        'ipc',
        'intentRouter',
        'clipboard',
        'notifications',
        'security',
        'compositor',
        'cpuRegistry',
        'formatDetector',
        'pkgManager',
        'search',
        'shell',
      ]) {
        assert.ok(osHandle.require(name), `Expected public subsystem "${name}" wired by createOmniOS()`);
      }

      // All 6 core services healthy/running
      const svcStatus = osHandle.require('serviceManager').getStatus();
      const svcJson = JSON.stringify(svcStatus);
      for (const svcName of ['vfsd', 'configd', 'ipc-brokerd', 'securityd', 'pkgd', 'compositord']) {
        assert.ok(svcJson.includes(svcName), `Expected core service "${svcName}" in serviceManager.getStatus(): ${svcJson}`);
      }

      // All 4 CPU engines registered
      const cpuRegistry = osHandle.require('cpuRegistry');
      for (const arch of ['dalvik', 'x86_64', 'arm64', 'wasm']) {
        assert.ok(cpuRegistry.get(arch), `Expected CPU engine "${arch}" registered in cpuRegistry`);
      }

      // All 5 platforms wired
      if (osHandle.runtimes) {
        const rtKeys = osHandle.runtimes instanceof Map
          ? Array.from(osHandle.runtimes.keys())
          : Object.keys(osHandle.runtimes);
        for (const plat of ['android', 'windows', 'ios', 'macos', 'universal']) {
          assert.ok(
            rtKeys.includes(plat) || JSON.stringify(osHandle.runtimes).includes(plat),
            `Expected platform runtime "${plat}" wired in os.runtimes`
          );
        }
      }

      // All 7 built-in system apps dynamically discovered and distinct
      const candidates = [];
      const installed = await osHandle.require('pkgManager').list();
      candidates.push(...normalizeAppEntries(installed, { fromInstalled: true }));
      if (osHandle.apps) {
        const rawApps = typeof osHandle.apps.list === 'function'
          ? await osHandle.apps.list()
          : (typeof osHandle.apps.getAll === 'function' ? await osHandle.apps.getAll() : osHandle.apps);
        candidates.push(...normalizeAppEntries(rawApps, { markBuiltin: true }));
      }
      const sysApps = resolveBuiltInSystemApps(candidates, 'pkgManager.list() + os.apps');
      assert.equal(Object.keys(sysApps).length, 7);
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T1-FA14-02 [F-062]: HTTP REST v1 health, kernel, processes, security, packages & compositor read endpoints', async () => {
    let srv = null;
    try {
      srv = await startOmniServer();

      const health = await srv.api.get('/api/health', { expectOk: true });
      assert.equal(health.status, 200);
      assert.equal(health.json?.ok, true);
      assert.equal(health.json?.os, 'OmniOS');
      assert.ok(health.json?.status, `Expected status field in /api/health, got: ${health.text}`);

      const v1Health = await srv.api.get('/api/v1/health', { expectOk: true });
      assert.equal(v1Health.status, 200);
      assert.equal(v1Health.json?.ok, true);

      const kStatus = await srv.api.get('/api/v1/kernel/status', { expectOk: true });
      assert.ok(kStatus.json && typeof kStatus.json === 'object');

      const dmesg = await srv.api.get('/api/v1/kernel/dmesg', { expectOk: true });
      assert.ok(dmesg.json !== null);

      const services = await srv.api.get('/api/v1/kernel/services', { expectOk: true });
      const servicesJson = JSON.stringify(services.json);
      for (const svcName of ['vfsd', 'configd', 'ipc-brokerd', 'securityd', 'pkgd', 'compositord']) {
        assert.ok(servicesJson.includes(svcName), `Expected ${svcName} in /api/v1/kernel/services`);
      }

      const procs = await srv.api.get('/api/v1/processes', { expectOk: true });
      const procList = asArray(procs.json, ['processes', 'items', 'data']);
      assert.ok(procList.some((p) => p.pid === 1 || p.pid === 0), `Expected PID 0/1 in /api/v1/processes: ${procs.text}`);

      const tree = await srv.api.get('/api/v1/processes/tree', { expectOk: true });
      assert.ok(tree.json !== null);

      const perms = await srv.api.get('/api/v1/security/permissions', { expectOk: true });
      assert.ok(perms.json !== null);

      const audit = await srv.api.get('/api/v1/security/audit', { expectOk: true });
      assert.ok(audit.json !== null);

      const users = await srv.api.get('/api/v1/security/users', { expectOk: true });
      const usersJson = JSON.stringify(users.json);
      assert.ok(usersJson.includes('root') && usersJson.includes('user'), `Expected root & user in /api/v1/security/users: ${users.text}`);

      const pkgs = await srv.api.get('/api/v1/packages', { expectOk: true });
      assert.ok(pkgs.json !== null);

      const catalog = await srv.api.get('/api/v1/packages/catalog', { expectOk: true });
      assert.ok(catalog.json !== null);

      const snap = await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true });
      assert.ok(typeof snap.json?.shellMode === 'string', `Expected shellMode string in snapshot: ${snap.text}`);
      assert.ok(Array.isArray(snap.json?.windows), `Expected windows array in snapshot: ${snap.text}`);
    } finally {
      if (srv) await srv.stop().catch(() => {});
    }
  });

  it('T1-FA14-03 [F-062]: HTTP REST v1 VFS, Unified Config, IPC Clipboard & Shell Exec round-trip', async () => {
    let srv = null;
    try {
      srv = await startOmniServer();
      const nonce = makeNonce();
      const dirPath = `/home/user/Documents/http-${nonce}`;
      const filePath = `${dirPath}/note.txt`;
      const content = `HTTP_VFS_${nonce}`;

      const mkRes = await srv.api.post('/api/v1/vfs/mkdir', { path: dirPath, recursive: true });
      assert.ok(mkRes.ok, `Expected 2xx on /api/v1/vfs/mkdir, got ${mkRes.status}: ${mkRes.text}`);

      const writeRes = await writeWithMethodFallback(
        srv.api,
        ['PUT', 'POST'],
        '/api/v1/vfs/file',
        { path: filePath, content, data: content, encoding: 'utf8' }
      );
      assert.ok(writeRes.ok, `Expected 2xx writing /api/v1/vfs/file, got ${writeRes.status}: ${writeRes.text}`);

      const readRes = await srv.api.get('/api/v1/vfs/file', { query: { path: filePath }, expectOk: true });
      const readContent = typeof readRes.json?.content === 'string'
        ? readRes.json.content
        : (typeof readRes.json?.data === 'string' ? readRes.json.data : readRes.text);
      assert.ok(readContent.includes(content), `Expected VFS file read to contain ${content}, got: ${readContent}`);

      const statRes = await srv.api.get('/api/v1/vfs/stat', { query: { path: filePath }, expectOk: true });
      assert.ok(statRes.json !== null);

      const lsRes = await srv.api.get('/api/v1/vfs/ls', { query: { path: dirPath }, expectOk: true });
      assert.ok(JSON.stringify(lsRes.json).includes('note.txt'), `Expected note.txt in /api/v1/vfs/ls: ${lsRes.text}`);

      const mountsRes = await srv.api.get('/api/v1/vfs/mounts', { expectOk: true });
      assert.ok(mountsRes.json !== null);

      const resolveRes = await srv.api.get('/api/v1/vfs/resolve', {
        query: { path: 'C:\\Users\\user\\Documents', platform: 'windows' },
        expectOk: true,
      });
      assert.equal(
        resolveRes.json?.canonicalPath ?? resolveRes.json?.path,
        '/home/user/Documents',
        `Expected Windows Documents path resolution, got: ${resolveRes.text}`
      );

      // Config read endpoints
      for (const cfgEp of ['/api/v1/config/system', '/api/v1/config/registry', '/api/v1/config/defaults', '/api/v1/config/prefs']) {
        const res = await srv.api.get(cfgEp, { expectOk: true });
        assert.equal(res.status, 200);
      }

      // Clipboard round-trip
      const clipText = `CLIP_${nonce}`;
      const clipWrite = await writeWithMethodFallback(
        srv.api,
        ['POST', 'PUT'],
        '/api/v1/ipc/clipboard',
        { text: clipText, mime: 'text/plain', sourceAppId: 'sys.test' }
      );
      assert.ok(clipWrite.ok, `Expected 2xx setting clipboard, got ${clipWrite.status}: ${clipWrite.text}`);
      const clipRead = await srv.api.get('/api/v1/ipc/clipboard', { expectOk: true });
      assert.ok(
        JSON.stringify(clipRead.json).includes(clipText),
        `Expected clipboard read to include ${clipText}, got: ${clipRead.text}`
      );

      // Shell exec
      const shRes = await srv.api.post('/api/v1/shell/exec', { command: `echo SHELL_HTTP_${nonce}` }, { expectOk: true });
      assert.ok(
        JSON.stringify(shRes.json ?? shRes.text).includes(`SHELL_HTTP_${nonce}`),
        `Expected shell exec stdout to include SHELL_HTTP_${nonce}, got: ${shRes.text}`
      );
    } finally {
      if (srv) await srv.stop().catch(() => {});
    }
  });

  it('T1-FA14-04 [F-062]: Static ui/ HTML/CSS/JS asset serving & zero external CDN URLs', async () => {
    let srv = null;
    try {
      srv = await startOmniServer();
      const rootRes = await srv.api.get('/', { expectOk: true });
      assert.equal(rootRes.status, 200);
      assert.ok(
        String(rootRes.headers['content-type'] ?? '').toLowerCase().includes('text/html'),
        `Expected text/html content-type on /, got: ${rootRes.headers['content-type']}`
      );
      assert.ok(/<html|<!doctype html/i.test(rootRes.text), 'Expected valid HTML document at GET /');

      const assetUrls = [];
      const attrRegex = /<(?:script\b[^>]*\bsrc|link\b[^>]*\bhref)=["']([^"']+)["']/gi;
      let match;
      while ((match = attrRegex.exec(rootRes.text)) !== null) {
        assetUrls.push(match[1]);
      }

      assert.ok(assetUrls.length >= 2, `Expected local CSS & JS assets referenced in ui/index.html, found: ${JSON.stringify(assetUrls)}`);

      let cssCount = 0;
      let jsCount = 0;
      for (const rawUrl of assetUrls) {
        if (rawUrl.startsWith('data:') || rawUrl.startsWith('blob:')) continue;
        if (/^https?:\/\//i.test(rawUrl)) {
          assert.ok(
            rawUrl.startsWith(srv.baseUrl),
            `Offline-safe invariant violated: external CDN URL "${rawUrl}" found in ui/index.html`
          );
        }
        const resolved = new URL(rawUrl, `${srv.baseUrl}/`).toString();
        const assetRes = await srv.api.get(resolved, { expectOk: true });
        assert.equal(assetRes.status, 200, `Expected HTTP 200 for local asset ${rawUrl}`);
        assert.ok(assetRes.buffer.length > 0, `Expected non-empty body for local asset ${rawUrl}`);
        if (/\.css(\?|$)/i.test(rawUrl)) cssCount++;
        if (/\.m?js(\?|$)/i.test(rawUrl)) jsCount++;
      }

      assert.ok(cssCount >= 1, `Expected at least 1 local CSS stylesheet in ui/index.html, found ${cssCount}`);
      assert.ok(jsCount >= 1, `Expected at least 1 local JS module in ui/index.html, found ${jsCount}`);
    } finally {
      if (srv) await srv.stop().catch(() => {});
    }
  });

  it('T1-FA14-05 [F-063]: RFC 6455 WebSocket (/ws) initial compositor:snapshot, ping->pong & shell:mode command', async () => {
    let srv = null;
    let ws = null;
    try {
      srv = await startOmniServer();
      ws = await srv.connectWs();

      const snapEv = await ws.waitForType('compositor:snapshot', { timeoutMs: 5000 });
      assert.ok(typeof snapEv.payload?.shellMode === 'string', `Expected shellMode in WS snapshot: ${JSON.stringify(snapEv)}`);
      assert.ok(Array.isArray(snapEv.payload?.windows), `Expected windows array in WS snapshot: ${JSON.stringify(snapEv)}`);

      const c1 = ws.mark();
      ws.send({ type: 'ping' });
      const pongEv = await ws.waitForType('pong', { since: c1, timeoutMs: 5000 });
      assert.equal(pongEv.type, 'pong');

      const c2 = ws.mark();
      ws.send({ type: 'shell:mode', payload: { mode: 'macos', shellMode: 'macos' } });

      await waitUntil(async () => {
        const res = await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        return res.json?.shellMode === 'macos';
      }, { timeoutMs: 5000, label: 'compositor shellMode to switch to macos via WS' });

      const modeEv = await ws.waitForMessage(
        (m) => m?.type === 'config:changed' || m?.type === 'compositor:snapshot',
        { since: c2, timeoutMs: 5000 }
      );
      assert.ok(modeEv, 'Expected WS broadcast after shell:mode command');

      // Restore unified mode cleanly
      ws.send({ type: 'shell:mode', payload: { mode: 'unified', shellMode: 'unified' } });
      await waitUntil(async () => {
        const res = await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        return res.json?.shellMode === 'unified';
      }, { timeoutMs: 5000, label: 'compositor shellMode restored to unified' });
    } finally {
      if (ws) await ws.close().catch(() => {});
      if (srv) await srv.stop().catch(() => {});
    }
  });

  it('T1-FA14-06 [F-063]: RFC 6455 WebSocket (/ws) live server push for config:changed, notification:posted & window lifecycle', async () => {
    let srv = null;
    let ws = null;
    try {
      srv = await startOmniServer();
      ws = await srv.connectWs();
      await ws.waitForType('compositor:snapshot', { timeoutMs: 5000 });

      const nonce = makeNonce();

      // 1. config:changed push on system.theme mutation
      const initialCfg = await srv.api.get('/api/v1/config/system', { expectOk: true });
      const curTheme = initialCfg.json?.theme ?? initialCfg.json?.system?.theme ?? initialCfg.json?.['system.theme'] ?? 'dark';
      const nextTheme = curTheme === 'dark' ? 'light' : 'dark';
      const c1 = ws.mark();
      await setSystemConfigHttp(srv.api, 'theme', nextTheme);
      const cfgEv = await ws.waitForType('config:changed', { since: c1, timeoutMs: 5000 });
      assert.equal(cfgEv.type, 'config:changed');

      // 2. notification:posted push
      const c2 = ws.mark();
      const nRes = await srv.api.post('/api/v1/ipc/notifications', {
        appId: 'sys.test',
        platform: 'universal',
        title: `NotifTitle_${nonce}`,
        body: `NotifBody_${nonce}`,
        priority: 'normal',
        category: 'system',
      }, { expectOk: true });
      assert.ok(nRes.ok);
      const nEv = await ws.waitForMessage(
        (m) => m?.type === 'notification:posted' && JSON.stringify(m.payload ?? {}).includes(`NotifTitle_${nonce}`),
        { since: c2, timeoutMs: 5000 }
      );
      assert.ok(nEv);

      // 3. compositor:window_created & compositor:window_closed push
      const sysApps = await discoverSystemAppsHttp(srv.api);
      const notesAppId = sysApps.notes;
      const c3 = ws.mark();
      const launchRes = await srv.api.post(`/api/v1/packages/${encodeURIComponent(notesAppId)}/launch`, {}, { expectOk: true });
      assert.ok((launchRes.json?.pid ?? launchRes.json?.process?.pid) > 1);
      const createdEv = await ws.waitForType('compositor:window_created', { since: c3, timeoutMs: 5000 });
      assert.equal(createdEv.type, 'compositor:window_created');

      const c4 = ws.mark();
      await srv.api.post(`/api/v1/packages/${encodeURIComponent(notesAppId)}/stop`, {}, { expectOk: true });
      const closedEv = await ws.waitForType('compositor:window_closed', { since: c4, timeoutMs: 5000 });
      assert.equal(closedEv.type, 'compositor:window_closed');
    } finally {
      if (ws) await ws.close().catch(() => {});
      if (srv) await srv.stop().catch(() => {});
    }
  });

  it('T1-FA14-07 [F-064]: Spotlight Universal Search (GET /api/v1/search?q=...) across apps, VFS files, active processes & settings', async () => {
    let srv = null;
    try {
      srv = await startOmniServer();
      const nonce = makeNonce();

      // 1. Dynamically install a uniquely named .uapp
      const appId = `com.omnios.spot.${nonce}`;
      const appName = `SpotApp_${nonce}`;
      const uappBuf = buildCustomUapp({ appId, name: appName, message: `SPOT_${nonce}\n` });
      await installPackageHttp(srv.api, uappBuf, `spot-${nonce}.uapp`);

      // 2. Write a uniquely named VFS file
      const filePath = `/home/user/Documents/spotdoc-${nonce}.txt`;
      const writeRes = await writeWithMethodFallback(
        srv.api,
        ['PUT', 'POST'],
        '/api/v1/vfs/file',
        { path: filePath, content: `SPOT_CONTENT_${nonce}`, data: `SPOT_CONTENT_${nonce}`, encoding: 'utf8' }
      );
      assert.ok(writeRes.ok, `Expected 2xx writing Spotlight doc, got ${writeRes.status}`);

      // 3. Launch a dynamically discovered built-in system app process (Notes)
      const sysApps = await discoverSystemAppsHttp(srv.api);
      const notesAppId = sysApps.notes;
      await srv.api.post(`/api/v1/packages/${encodeURIComponent(notesAppId)}/launch`, {}, { expectOk: true });

      // Assert Spotlight finds installed app
      const appSearch = await srv.api.get('/api/v1/search', { query: { q: appName }, expectOk: true });
      assert.ok(
        JSON.stringify(appSearch.json).includes(appName) || JSON.stringify(appSearch.json).includes(appId),
        `Expected Spotlight to find installed app ${appName}, got: ${appSearch.text}`
      );

      // Assert Spotlight finds VFS file
      const fileSearch = await srv.api.get('/api/v1/search', { query: { q: `spotdoc-${nonce}` }, expectOk: true });
      assert.ok(
        JSON.stringify(fileSearch.json).includes(`spotdoc-${nonce}`),
        `Expected Spotlight to find VFS file spotdoc-${nonce}, got: ${fileSearch.text}`
      );

      // Assert Spotlight finds active process / app
      const procSearch = await srv.api.get('/api/v1/search', { query: { q: 'notes' }, expectOk: true });
      const procSearchBlob = JSON.stringify(procSearch.json);
      assert.ok(
        /notes/i.test(procSearchBlob) || procSearchBlob.includes(notesAppId),
        `Expected Spotlight to find active notes process/app (${notesAppId}), got: ${procSearch.text}`
      );

      // Assert Spotlight finds settings
      const settingSearch = await srv.api.get('/api/v1/search', { query: { q: 'theme' }, expectOk: true });
      assert.ok(
        /theme/i.test(JSON.stringify(settingSearch.json)),
        `Expected Spotlight to find theme setting, got: ${settingSearch.text}`
      );

      await srv.api.post(`/api/v1/packages/${encodeURIComponent(notesAppId)}/stop`, {}).catch(() => {});
    } finally {
      if (srv) await srv.stop().catch(() => {});
    }
  });
});
