/**
 * OmniOS Tier 1 E2E Suite — FA-15: Headless/Remote CLI, Multi-Syntax Shell & 7 Built-in System Apps
 * Covers PROJECT.md Features: F-065, F-066, F-067, F-068, F-069, F-070, F-071, F-072.
 *
 * STRICT INVARIANTS:
 * - Opaque-box only: imports ONLY Node 24 built-ins and ../lib/*.mjs.
 * - Zero skips, zero stubs, zero hardcoded app outputs.
 * - Clean try/finally teardown on every test.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import {
  createTempDataDir,
  runCli,
  startOmniServer,
} from '../lib/env.mjs';
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

function asArray(payload, keys = ['items', 'data', 'processes', 'windows', 'notifications', 'packages', 'services']) {
  if (Array.isArray(payload)) return payload;
  if (payload && typeof payload === 'object') {
    for (const k of keys) {
      if (Array.isArray(payload[k])) return payload[k];
    }
  }
  return [];
}

function collectTreeNodes(node, out = []) {
  if (!node || typeof node !== 'object') return out;
  if (Array.isArray(node)) {
    for (const item of node) collectTreeNodes(item, out);
    return out;
  }
  out.push(node);
  for (const key of ['children', 'items', 'tabs', 'panels', 'actions', 'buttons', 'rows']) {
    if (Array.isArray(node[key])) {
      for (const child of node[key]) collectTreeNodes(child, out);
    }
  }
  for (const key of ['body', 'content', 'header', 'footer', 'sidebar', 'main']) {
    if (node[key] && typeof node[key] === 'object') {
      collectTreeNodes(node[key], out);
    }
  }
  return out;
}

function findClickableNode(uiTree) {
  const nodes = collectTreeNodes(uiTree);
  const interactiveTypes = new Set(['button', 'tab', 'menuitem', 'action', 'toggle', 'switch', 'checkbox', 'list-item', 'card', 'link']);
  return (
    nodes.find((n) => n.id && interactiveTypes.has(String(n.type ?? '').toLowerCase())) ??
    nodes.find((n) => n.id && (n.action || n.onClick || n.clickable)) ??
    nodes.find((n) => typeof n.id === 'string' && n.id.length > 0 && n.id !== 'root') ??
    null
  );
}

function findInputNode(uiTree) {
  const nodes = collectTreeNodes(uiTree);
  const inputTypes = new Set(['input', 'textarea', 'textfield', 'terminal-input', 'command-input', 'editor', 'search']);
  return (
    nodes.find((n) => n.id && inputTypes.has(String(n.type ?? '').toLowerCase())) ??
    nodes.find((n) => n.id && /input|editor|command|term|note|text/i.test(String(n.id))) ??
    null
  );
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

function normalizeAppEntries(source, { fromInstalled = false } = {}) {
  const out = [];
  if (!source) return out;
  const add = (item, keyHint = '') => {
    if (typeof item === 'string') {
      const id = item.trim();
      if (id) out.push({ appId: id, name: id, platform: '', isBuiltin: false, fromInstalled });
      return;
    }
    if (!item || typeof item !== 'object') return;
    const appId = String(item.appId ?? item.id ?? keyHint ?? '').trim();
    if (!appId) return;
    const name = String(item.name ?? item.title ?? item.displayName ?? item.label ?? '').trim();
    const platform = String(item.platform ?? '').toLowerCase();
    const isBuiltin = Boolean(
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
  } else if (typeof source === 'object') {
    const arr = asArray(source, ['packages', 'apps', 'catalog', 'items', 'data', 'entries']);
    const sysArr = asArray(source, ['systemApps']);
    if (arr.length > 0 || sysArr.length > 0) {
      for (const item of arr) add(item);
      for (const item of sysArr) add(item);
    } else {
      for (const [k, v] of Object.entries(source)) add(v, k);
    }
  }
  return out;
}

async function discoverSystemAppsHttp(api) {
  const candidates = [];
  const pkgRes = await api.get('/api/v1/packages', { expectOk: true });
  candidates.push(...normalizeAppEntries(pkgRes.json, { fromInstalled: true }));
  const catRes = await api.get('/api/v1/packages/catalog');
  if (catRes.ok && catRes.json !== null) {
    candidates.push(...normalizeAppEntries(catRes.json, { fromInstalled: false }));
  }

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
      `Expected built-in system app for role "${role}" in /api/v1/packages, candidates: ${JSON.stringify(list)}`
    );
    resolved[role] = matches[0].c.appId;
    used.add(matches[0].c.appId);
  }

  assert.equal(
    new Set(Object.values(resolved)).size,
    SYSTEM_APP_ROLES.length,
    `Expected 7 distinct built-in system apps, resolved: ${JSON.stringify(resolved)}`
  );
  return resolved;
}

function assertProcessAlive(procRes, label, pid) {
  const state = procRes.json?.state ?? procRes.json?.process?.state ?? procRes.json?.pcb?.state ?? procRes.json?.data?.state ?? null;
  assert.ok(
    typeof state === 'string' && state.length > 0 && state !== 'TERMINATED' && state !== 'ZOMBIE',
    `Expected live non-terminated process state for ${label} (PID ${pid}), got state=${JSON.stringify(state)} payload=${procRes.text}`
  );
}

function hasExecutedTerminalOutput(uiTree, needle, typedCmd) {
  if (!uiTree) return false;
  const blob = JSON.stringify(uiTree);
  if (!blob.includes(needle)) return false;

  const inputTypes = new Set(['input', 'textarea', 'textfield', 'terminal-input', 'command-input', 'editor', 'search']);
  const nodes = collectTreeNodes(uiTree);
  for (const n of nodes) {
    const t = String(n.type ?? '').toLowerCase();
    if (inputTypes.has(t)) continue;
    for (const [k, v] of Object.entries(n)) {
      if (k === 'children' || k === 'items' || k === 'tabs' || k === 'panels' || k === 'actions' || k === 'buttons' || k === 'rows') continue;
      if (typeof v === 'string' && v.replaceAll(typedCmd, '').includes(needle)) return true;
      if (Array.isArray(v) && v.some((x) => typeof x === 'string' && x.replaceAll(typedCmd, '').includes(needle))) return true;
    }
  }
  // Fallback (e.g. readonly textarea terminal log): needle must still appear outside the raw typed command string
  return blob.replaceAll(typedCmd, '').includes(needle);
}

async function execShell(api, command) {
  const res = await api.post('/api/v1/shell/exec', { command }, { expectOk: true });
  const text = typeof res.json?.stdout === 'string'
    ? res.json.stdout
    : (typeof res.json?.output === 'string' ? res.json.output : JSON.stringify(res.json ?? res.text));
  return { res, stdout: text };
}

async function launchSystemAppAndWaitWindow(api, appId) {
  const launchRes = await api.post(`/api/v1/packages/${encodeURIComponent(appId)}/launch`, {}, { expectOk: true });
  const pid = launchRes.json?.pid ?? launchRes.json?.process?.pid;
  assert.ok(typeof pid === 'number' && pid > 1, `Expected PID > 1 launching ${appId}, got: ${launchRes.text}`);

  const win = await waitUntil(async () => {
    const snap = await api.get('/api/v1/compositor/snapshot', { expectOk: true });
    const wins = asArray(snap.json, ['windows']);
    return wins.find((w) => w.pid === pid || w.appId === appId) ?? null;
  }, { timeoutMs: 6000, label: `Compositor window for ${appId}` });

  const procRes = await api.get('/api/v1/processes', { expectOk: true });
  const procs = asArray(procRes.json, ['processes', 'items', 'data']);
  assert.ok(procs.some((p) => p.pid === pid), `Expected live PID ${pid} (${appId}) in /api/v1/processes`);
  assert.ok(typeof win.title === 'string' && win.title.length > 0, `Expected non-empty window title for ${appId}`);
  const uiTree = win.uiTree ?? win.surface?.uiTree;
  assert.ok(uiTree && Object.keys(uiTree).length > 0, `Expected populated uiTree for ${appId}`);

  return { pid, win, winId: win.windowId ?? win.id };
}

describe('Tier 1 — FA-15: Headless/Remote CLI, Multi-Syntax Shell & 7 Built-in System Apps', () => {
  it('T1-FA15-01 [F-065]: Headless local CLI (--data-dir --json) across status, dmesg, services, ps, vfs, reg, defaults & prefs', async () => {
    let tmp = null;
    try {
      tmp = await createTempDataDir('omnios-fa15-cli-');
      const nonce = makeNonce();

      const status = await runCli(['status'], { dataDir: tmp.dir, json: true, expectZero: true });
      assert.ok(status.json && /running/i.test(JSON.stringify(status.json)), `Expected RUNNING status JSON: ${status.stdout}`);

      const dmesg = await runCli(['dmesg'], { dataDir: tmp.dir, json: true, expectZero: true });
      assert.ok(dmesg.json !== null, `Expected JSON output from CLI dmesg: ${dmesg.stdout}`);

      const services = await runCli(['services'], { dataDir: tmp.dir, json: true, expectZero: true });
      const svcText = JSON.stringify(services.json ?? services.stdout);
      assert.ok(svcText.includes('vfsd') && svcText.includes('compositord'), `Expected core services in CLI services: ${svcText}`);

      const ps = await runCli(['ps'], { dataDir: tmp.dir, json: true, expectZero: true });
      const psList = asArray(ps.json, ['processes', 'items', 'data']);
      assert.ok(psList.some((p) => p.pid === 1 || p.pid === 0), `Expected PID 0/1 in CLI ps: ${ps.stdout}`);

      // VFS round-trip via headless CLI
      const vfsDir = `/home/user/Documents/cli-${nonce}`;
      const vfsFile = `${vfsDir}/f.txt`;
      await runCli(['vfs', 'mkdir', vfsDir], { dataDir: tmp.dir, json: true, expectZero: true });
      await runCli(['vfs', 'write', vfsFile, `CLI_VFS_${nonce}`], { dataDir: tmp.dir, json: true, expectZero: true });
      const cat = await runCli(['vfs', 'cat', vfsFile], { dataDir: tmp.dir, json: true, expectZero: true });
      assert.ok(cat.stdout.includes(`CLI_VFS_${nonce}`), `Expected vfs cat to return CLI_VFS_${nonce}, got: ${cat.stdout}`);

      const ls = await runCli(['vfs', 'ls', vfsDir], { dataDir: tmp.dir, json: true, expectZero: true });
      assert.ok(ls.stdout.includes('f.txt'), `Expected f.txt in vfs ls: ${ls.stdout}`);

      const resolved = await runCli(['vfs', 'resolve', 'C:\\Users\\user\\Documents', '--platform', 'windows'], {
        dataDir: tmp.dir,
        json: true,
        expectZero: true,
      });
      assert.ok(resolved.stdout.includes('/home/user/Documents'), `Expected canonical /home/user/Documents: ${resolved.stdout}`);

      // Windows Registry via CLI
      const regKey = `Software\\OmniCli_${nonce}`;
      await runCli(['reg', 'set', 'HKCU', regKey, `Val_${nonce}`, 'REG_SZ', `REG_CLI_${nonce}`], {
        dataDir: tmp.dir,
        json: true,
        expectZero: true,
      });
      const regGet = await runCli(['reg', 'get', 'HKCU', regKey, `Val_${nonce}`], {
        dataDir: tmp.dir,
        json: true,
        expectZero: true,
      });
      assert.ok(regGet.stdout.includes(`REG_CLI_${nonce}`), `Expected REG_CLI_${nonce} from reg get: ${regGet.stdout}`);
      const regList = await runCli(['reg', 'list', 'HKCU', regKey], {
        dataDir: tmp.dir,
        json: true,
        expectZero: true,
      });
      assert.ok(regList.stdout.includes(`Val_${nonce}`), `Expected Val_${nonce} in reg list: ${regList.stdout}`);

      // Apple Defaults via CLI
      const defDomain = `com.omnios.cli.${nonce}`;
      await runCli(['defaults', 'write', defDomain, `Key_${nonce}`, `DEF_CLI_${nonce}`], {
        dataDir: tmp.dir,
        json: true,
        expectZero: true,
      });
      const defRead = await runCli(['defaults', 'read', defDomain, `Key_${nonce}`], {
        dataDir: tmp.dir,
        json: true,
        expectZero: true,
      });
      assert.ok(defRead.stdout.includes(`DEF_CLI_${nonce}`), `Expected DEF_CLI_${nonce} from defaults read: ${defRead.stdout}`);

      // Android SharedPreferences via CLI
      await runCli(['prefs', 'set', defDomain, 'main', `Pref_${nonce}`, `PREF_CLI_${nonce}`], {
        dataDir: tmp.dir,
        json: true,
        expectZero: true,
      });
      const prefGet = await runCli(['prefs', 'get', defDomain, 'main', `Pref_${nonce}`], {
        dataDir: tmp.dir,
        json: true,
        expectZero: true,
      });
      assert.ok(prefGet.stdout.includes(`PREF_CLI_${nonce}`), `Expected PREF_CLI_${nonce} from prefs get: ${prefGet.stdout}`);
    } finally {
      if (tmp) await tmp.cleanup().catch(() => {});
    }
  });

  it('T1-FA15-02 [F-065]: Remote daemon CLI (--remote --json) across clipboard, notify, ospm & intent synced with live HTTP server', async () => {
    let srv = null;
    let tmp = null;
    try {
      srv = await startOmniServer();
      tmp = await createTempDataDir('omnios-fa15-rcli-');
      const nonce = makeNonce();

      // Clipboard via remote CLI + HTTP REST check
      await srv.runCli(['clipboard', 'set', `RCLIP_${nonce}`], { json: true, expectZero: true });
      const cliClip = await srv.runCli(['clipboard', 'get'], { json: true, expectZero: true });
      assert.ok(cliClip.stdout.includes(`RCLIP_${nonce}`), `Expected RCLIP_${nonce} from remote clipboard get: ${cliClip.stdout}`);
      const restClip = await srv.api.get('/api/v1/ipc/clipboard', { expectOk: true });
      assert.ok(JSON.stringify(restClip.json).includes(`RCLIP_${nonce}`), `Expected REST clipboard sync: ${restClip.text}`);

      // Notifications via remote CLI
      const sentNotif = await srv.runCli(['notify', 'send', `RNotif_${nonce}`, `RBody_${nonce}`], {
        json: true,
        expectZero: true,
      });
      const listNotif = await srv.runCli(['notify', 'list'], { json: true, expectZero: true });
      assert.ok(listNotif.stdout.includes(`RNotif_${nonce}`), `Expected RNotif_${nonce} in notify list: ${listNotif.stdout}`);
      const notifId = sentNotif.json?.id ??
        asArray(listNotif.json, ['notifications', 'items', 'data']).find((n) => String(n.title ?? '').includes(`RNotif_${nonce}`))?.id;
      assert.ok(notifId, `Expected notification ID to dismiss, got: ${sentNotif.stdout}`);
      await srv.runCli(['notify', 'dismiss', String(notifId)], { json: true, expectZero: true });

      // ospm + intent lifecycle via remote CLI
      const appId = `com.omnios.rcli.${nonce}`;
      const scheme = `rcli${nonce}`;
      const uappBuf = buildCustomUapp({
        appId,
        name: `RCliApp_${nonce}`,
        urlSchemes: [scheme],
        message: `RCLI_OUT_${nonce}\n`,
      });
      const hostPkgPath = path.join(tmp.dir, `rcli-${nonce}.uapp`);
      await fs.writeFile(hostPkgPath, uappBuf);

      const insp = await srv.runCli(['ospm', 'inspect', hostPkgPath], { json: true, expectZero: true });
      assert.equal(insp.json?.appId, appId);

      await srv.runCli(['ospm', 'install', hostPkgPath], { json: true, expectZero: true });
      const pkgList = await srv.runCli(['ospm', 'list'], { json: true, expectZero: true });
      assert.ok(pkgList.stdout.includes(appId), `Expected ${appId} in remote ospm list: ${pkgList.stdout}`);

      // Intent resolve for registered scheme
      let intentRes = await srv.runCli(['intent', 'resolve', `${scheme}://open`], { json: true });
      if (!intentRes.ok || !intentRes.stdout.includes(appId)) {
        intentRes = await srv.runCli(['intent', 'resolve', '--scheme', scheme], { json: true, expectZero: true });
      }
      assert.ok(intentRes.stdout.includes(appId), `Expected remote intent resolve to match ${appId}, got: ${intentRes.stdout}`);

      const launched = await srv.runCli(['ospm', 'launch', appId], { json: true, expectZero: true });
      assert.ok((launched.json?.pid ?? launched.json?.process?.pid) > 1, `Expected PID > 1: ${launched.stdout}`);

      await srv.runCli(['ospm', 'stop', appId], { json: true, expectZero: true });
      await srv.runCli(['ospm', 'uninstall', appId], { json: true, expectZero: true });
      const afterUninst = await srv.runCli(['ospm', 'list'], { json: true, expectZero: true });
      assert.ok(!afterUninst.stdout.includes(appId), `Expected ${appId} removed after remote uninstall`);
    } finally {
      if (srv) await srv.stop().catch(() => {});
      if (tmp) await tmp.cleanup().catch(() => {});
    }
  });

  it('T1-FA15-03 [F-066]: Multi-Syntax Shell Interpreter (REST & CLI exec): POSIX commands, pipes (|) & redirects (>)', async () => {
    let srv = null;
    try {
      srv = await startOmniServer();
      const nonce = makeNonce();
      const dir = `/home/user/Documents/sh-${nonce}`;
      const file = `${dir}/a.txt`;

      await execShell(srv.api, `mkdir -p ${dir}`);
      await execShell(srv.api, `echo PIPE_ALPHA_${nonce} > ${file}`);

      const catOut = await execShell(srv.api, `cat ${file}`);
      assert.ok(catOut.stdout.includes(`PIPE_ALPHA_${nonce}`), `Expected cat output PIPE_ALPHA_${nonce}, got: ${catOut.stdout}`);

      const lsOut = await execShell(srv.api, `ls ${dir}`);
      assert.ok(lsOut.stdout.includes('a.txt'), `Expected ls to show a.txt, got: ${lsOut.stdout}`);

      const pipeOut = await execShell(srv.api, `cat ${file} | grep PIPE_ALPHA_${nonce}`);
      assert.ok(pipeOut.stdout.includes(`PIPE_ALPHA_${nonce}`), `Expected piped grep match, got: ${pipeOut.stdout}`);

      const psOut = await execShell(srv.api, 'ps');
      assert.ok(/\b1\b|omnid|kernel/i.test(psOut.stdout), `Expected ps output listing PID 1 / active processes: ${psOut.stdout}`);

      const dmesgOut = await execShell(srv.api, 'dmesg');
      assert.ok(dmesgOut.stdout.trim().length > 0, 'Expected non-empty dmesg output from shell');

      const cliExec = await srv.runCli(['exec', `cat ${file}`], { json: true, expectZero: true });
      assert.ok(cliExec.stdout.includes(`PIPE_ALPHA_${nonce}`), `Expected CLI exec cat to match: ${cliExec.stdout}`);
    } finally {
      if (srv) await srv.stop().catch(() => {});
    }
  });

  it('T1-FA15-04 [F-066]: Multi-Syntax Shell Interpreter: Windows (dir/type/tasklist/reg), macOS (defaults), Android (pm/prefs) & ospm', async () => {
    let srv = null;
    try {
      srv = await startOmniServer();
      const nonce = makeNonce();
      const fileName = `winsh-${nonce}.txt`;

      // Seed file via shell redirect
      await execShell(srv.api, `echo MULTI_SYN_${nonce} > /home/user/Documents/${fileName}`);

      // Windows syntax
      const dirOut = await execShell(srv.api, 'dir C:\\Users\\user\\Documents');
      assert.ok(dirOut.stdout.includes(fileName), `Expected Windows dir to list ${fileName}: ${dirOut.stdout}`);

      const typeOut = await execShell(srv.api, `type C:\\Users\\user\\Documents\\${fileName}`);
      assert.ok(typeOut.stdout.includes(`MULTI_SYN_${nonce}`), `Expected Windows type to output MULTI_SYN_${nonce}: ${typeOut.stdout}`);

      const tlOut = await execShell(srv.api, 'tasklist');
      assert.ok(tlOut.stdout.trim().length > 0, `Expected non-empty Windows tasklist output`);

      await execShell(srv.api, `reg set HKCU Software\\Sh_${nonce} K REG_SZ V_${nonce}`);
      const regOut = await execShell(srv.api, `reg get HKCU Software\\Sh_${nonce} K`);
      assert.ok(regOut.stdout.includes(`V_${nonce}`), `Expected reg get to return V_${nonce}: ${regOut.stdout}`);

      // macOS syntax
      const dom = `com.omnios.sh.${nonce}`;
      await execShell(srv.api, `defaults write ${dom} MKey MVal_${nonce}`);
      const defOut = await execShell(srv.api, `defaults read ${dom} MKey`);
      assert.ok(defOut.stdout.includes(`MVal_${nonce}`), `Expected defaults read to return MVal_${nonce}: ${defOut.stdout}`);

      // Android syntax
      const pmOut = await execShell(srv.api, 'pm list');
      assert.ok(pmOut.stdout.trim().length > 0, 'Expected non-empty Android pm list output');

      await execShell(srv.api, `prefs set ${dom} p AKey AVal_${nonce}`);
      const prefsOut = await execShell(srv.api, `prefs get ${dom} p AKey`);
      assert.ok(prefsOut.stdout.includes(`AVal_${nonce}`), `Expected prefs get to return AVal_${nonce}: ${prefsOut.stdout}`);

      // Cross-platform ospm
      const sysApps = await discoverSystemAppsHttp(srv.api);
      const ospmOut = await execShell(srv.api, 'ospm list');
      assert.ok(
        ospmOut.stdout.includes(sysApps.terminal) || /terminal|omniterm|notes|files/i.test(ospmOut.stdout),
        `Expected ospm list output to include built-in apps (${sysApps.terminal}): ${ospmOut.stdout}`
      );
    } finally {
      if (srv) await srv.stop().catch(() => {});
    }
  });

  it('T1-FA15-05 [F-067/F-068/F-069]: Built-in System Apps Wave 1 (OmniTerm, OmniFiles, Activity Monitor) real PIDs, windows & live input', async () => {
    let srv = null;
    try {
      srv = await startOmniServer();
      const nonce = makeNonce();
      const sysApps = await discoverSystemAppsHttp(srv.api);

      const term = await launchSystemAppAndWaitWindow(srv.api, sysApps.terminal);
      const files = await launchSystemAppAndWaitWindow(srv.api, sysApps.files);
      const monitor = await launchSystemAppAndWaitWindow(srv.api, sysApps.monitor);

      assert.equal(new Set([term.pid, files.pid, monitor.pid]).size, 3, 'Expected 3 distinct PIDs for Wave 1 system apps');

      // Live input to OmniTerm executing a real command
      const termInputNode = findInputNode(term.win.uiTree ?? term.win.surface?.uiTree);
      const expectedOut = `TERM_OK_${nonce}`;
      const cmd = `echo ${expectedOut}`;

      const checkTermExecuted = async () => {
        const snap = await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        const w = asArray(snap.json, ['windows']).find((x) => (x.windowId ?? x.id) === term.winId);
        if (!w) return false;
        const tree = w.uiTree ?? w.surface?.uiTree ?? null;
        return JSON.stringify(tree ?? '').includes(expectedOut) && hasExecutedTerminalOutput(tree, expectedOut, cmd);
      };

      if (termInputNode) {
        await srv.api.post(`/api/v1/compositor/windows/${encodeURIComponent(term.winId)}/input`, {
          type: 'input',
          nodeId: termInputNode.id,
          value: cmd,
        }, { expectOk: true });
        await srv.api.post(`/api/v1/compositor/windows/${encodeURIComponent(term.winId)}/input`, {
          type: 'action',
          nodeId: termInputNode.id,
          value: cmd,
          command: cmd,
        }, { expectOk: true });
        // Always dispatch Enter keydown if action did not execute the command
        await sleep(150);
        if (!(await checkTermExecuted())) {
          await srv.api.post(`/api/v1/compositor/windows/${encodeURIComponent(term.winId)}/input`, {
            type: 'keydown',
            key: 'Enter',
            nodeId: termInputNode.id,
            value: cmd,
            command: cmd,
          }, { expectOk: true });
        }
      } else {
        await srv.api.post(`/api/v1/compositor/windows/${encodeURIComponent(term.winId)}/input`, {
          type: 'keydown',
          key: 'Enter',
          value: cmd,
          command: cmd,
        }, { expectOk: true });
      }

      const termUpdated = await waitUntil(checkTermExecuted, {
        timeoutMs: 5000,
        label: `OmniTerm uiTree output containing ${expectedOut}`,
      });
      assert.ok(termUpdated);

      // Interactive click on OmniFiles & Activity Monitor
      for (const app of [files, monitor]) {
        const btn = findClickableNode(app.win.uiTree ?? app.win.surface?.uiTree);
        assert.ok(btn, `Expected at least one interactive node in ${app.win.appId} uiTree`);
        const clickRes = await srv.api.post(`/api/v1/compositor/windows/${encodeURIComponent(app.winId)}/input`, {
          type: 'click',
          nodeId: btn.id,
        }, { expectOk: true });
        assert.equal(clickRes.status, 200);
        const procRes = await srv.api.get(`/api/v1/processes/${app.pid}`, { expectOk: true });
        assertProcessAlive(procRes, app.win.appId, app.pid);
      }

      // Clean stop & verify windows closed
      for (const id of [sysApps.terminal, sysApps.files, sysApps.monitor]) {
        await srv.api.post(`/api/v1/packages/${encodeURIComponent(id)}/stop`, {}, { expectOk: true });
      }
      await waitUntil(async () => {
        const snap = await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        const ids = new Set(asArray(snap.json, ['windows']).map((w) => w.windowId ?? w.id));
        return !ids.has(term.winId) && !ids.has(files.winId) && !ids.has(monitor.winId);
      }, { timeoutMs: 5000, label: 'Wave 1 system app windows closed' });
    } finally {
      if (srv) await srv.stop().catch(() => {});
    }
  });

  it('T1-FA15-06 [F-070/F-071]: Built-in System Apps Wave 2 (App Hub, Settings) real PIDs, windows & live input', async () => {
    let srv = null;
    try {
      srv = await startOmniServer();
      const sysApps = await discoverSystemAppsHttp(srv.api);

      const apphub = await launchSystemAppAndWaitWindow(srv.api, sysApps.apphub);
      const settings = await launchSystemAppAndWaitWindow(srv.api, sysApps.settings);
      assert.notEqual(apphub.pid, settings.pid);

      for (const app of [apphub, settings]) {
        const btn = findClickableNode(app.win.uiTree ?? app.win.surface?.uiTree);
        assert.ok(btn, `Expected interactive node in ${app.win.appId} uiTree`);
        const res = await srv.api.post(`/api/v1/compositor/windows/${encodeURIComponent(app.winId)}/input`, {
          type: 'click',
          nodeId: btn.id,
        }, { expectOk: true });
        assert.equal(res.status, 200);

        const procRes = await srv.api.get(`/api/v1/processes/${app.pid}`, { expectOk: true });
        assertProcessAlive(procRes, app.win.appId, app.pid);
      }

      await srv.api.post(`/api/v1/packages/${encodeURIComponent(sysApps.apphub)}/stop`, {}, { expectOk: true });
      await srv.api.post(`/api/v1/packages/${encodeURIComponent(sysApps.settings)}/stop`, {}, { expectOk: true });
    } finally {
      if (srv) await srv.stop().catch(() => {});
    }
  });

  it('T1-FA15-07 [F-072]: Built-in System Apps Wave 3 (Binary Inspector, OmniNotes) real PIDs, windows & interactive input', async () => {
    let srv = null;
    try {
      srv = await startOmniServer();
      const nonce = makeNonce();
      const sysApps = await discoverSystemAppsHttp(srv.api);

      const inspector = await launchSystemAppAndWaitWindow(srv.api, sysApps.inspector);
      const notes = await launchSystemAppAndWaitWindow(srv.api, sysApps.notes);
      assert.notEqual(inspector.pid, notes.pid);

      const notesRev0 = Number(notes.win.surfaceRevision ?? 0);
      const notesTree = notes.win.uiTree ?? notes.win.surface?.uiTree;
      const notesInput = findInputNode(notesTree) ?? findClickableNode(notesTree);
      assert.ok(notesInput, `Expected interactive/editor node in ${sysApps.notes} uiTree`);
      const noteRes = await srv.api.post(`/api/v1/compositor/windows/${encodeURIComponent(notes.winId)}/input`, {
        type: findInputNode(notesTree) ? 'input' : 'click',
        nodeId: notesInput.id,
        value: `NOTE_${nonce}`,
      }, { expectOk: true });
      assert.equal(noteRes.status, 200);

      await waitUntil(async () => {
        const snap = await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        const w = asArray(snap.json, ['windows']).find((x) => (x.windowId ?? x.id) === notes.winId);
        const tree = w?.uiTree ?? w?.surface?.uiTree;
        return Boolean(w && (Number(w.surfaceRevision ?? 0) > notesRev0 || JSON.stringify(tree ?? '').includes(`NOTE_${nonce}`)));
      }, { timeoutMs: 5000, label: `${sysApps.notes} surface update after input` });

      const inspBtn = findClickableNode(inspector.win.uiTree ?? inspector.win.surface?.uiTree);
      assert.ok(inspBtn, `Expected interactive node in ${sysApps.inspector} uiTree`);
      const inspRes = await srv.api.post(`/api/v1/compositor/windows/${encodeURIComponent(inspector.winId)}/input`, {
        type: 'click',
        nodeId: inspBtn.id,
      }, { expectOk: true });
      assert.equal(inspRes.status, 200);

      const inspProc = await srv.api.get(`/api/v1/processes/${inspector.pid}`, { expectOk: true });
      assertProcessAlive(inspProc, sysApps.inspector, inspector.pid);
      const notesProc = await srv.api.get(`/api/v1/processes/${notes.pid}`, { expectOk: true });
      assertProcessAlive(notesProc, sysApps.notes, notes.pid);

      await srv.api.post(`/api/v1/packages/${encodeURIComponent(sysApps.inspector)}/stop`, {}, { expectOk: true });
      await srv.api.post(`/api/v1/packages/${encodeURIComponent(sysApps.notes)}/stop`, {}, { expectOk: true });

      await waitUntil(async () => {
        const snap = await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        const ids = new Set(asArray(snap.json, ['windows']).map((w) => w.windowId ?? w.id));
        return !ids.has(inspector.winId) && !ids.has(notes.winId);
      }, { timeoutMs: 5000, label: 'Wave 3 windows closed with zero leaks' });
    } finally {
      if (srv) await srv.stop().catch(() => {});
    }
  });
});
