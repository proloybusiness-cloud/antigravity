/**
 * OmniOS Tier 4 E2E Suite — S03: Cross-Platform Productivity Handoff & Built-in System Apps Admin Session
 * Covers PROJECT.md Features: F-004, F-016–F-026, F-034, F-040–F-047, F-054–F-072, F-085.
 *
 * Scenarios:
 * - T4-S03-01 (Scenario 5): Authoring & Handoff Pipeline over live HTTP REST:
 *   Windows PE32+ .exe writes report to C:\Users\user\Documents\ + Win32 Clipboard ->
 *   Android .apk reads /sdcard/Documents/, executes runtime arithmetic, emits Notification & Intent ->
 *   macOS Universal .app.zip writes follow-up to /Users/user/Documents/ + updates NSUserDefaults ->
 *   Spotlight GET /api/v1/search strictly finds documents & installed apps (anti-vacuous result unwrapping).
 * - T4-S03-02 (Scenario 6): Full Admin Session across all 7 dynamically discovered built-in system apps
 *   (OmniTerm, OmniFiles, Activity Monitor, App Hub, Settings, Binary Inspector, OmniNotes — zero hardcoded
 *   app IDs), multi-syntax shell, live /proc & process inspection, controlled Kernel Panic + safe-mode
 *   recovery + cold restart zero-data-loss SQLite durability verification.
 *
 * STRICT INVARIANTS:
 * - Opaque-box only: imports ONLY Node 24 built-ins and ../lib/*.mjs.
 * - Zero external npm dependencies, zero hardcoded system app IDs, zero undocumented capability strings.
 * - Zero skips, zero stubs, zero swallowed AssertionErrors inside try/catch.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import {
  PUBLIC_PATHS,
  assertPublicEntryExists,
  createTempDataDir,
  loadPublicOmniOS,
  startOmniServer,
} from '../lib/env.mjs';
import {
  buildCustomApk,
  buildCustomPe64Exe,
} from '../lib/fixtures-android-win.mjs';
import {
  buildCustomMacAppZip,
  buildCustomUapp,
} from '../lib/fixtures-apple-wasm.mjs';

function makeNonce(bytes = 4) {
  return crypto.randomBytes(bytes).toString('hex');
}

function makeSafeAddOperands() {
  const b = crypto.randomBytes(2);
  return [19 + (b[0] % 55), 23 + (b[1] % 55)];
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitUntil(fn, { timeoutMs = 8000, intervalMs = 60, label = 'condition' } = {}) {
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

function asArray(payload, keys = ['items', 'data', 'windows', 'processes', 'packages', 'notifications', 'entries', 'handlers', 'candidates']) {
  if (Array.isArray(payload)) return payload;
  if (payload && typeof payload === 'object') {
    for (const k of keys) {
      if (Array.isArray(payload[k])) return payload[k];
    }
  }
  return [];
}

function unwrapExplicitArray(payload, keys = ['handlers', 'candidates', 'results', 'items', 'data', 'entries']) {
  if (Array.isArray(payload)) return payload;
  if (payload && typeof payload === 'object') {
    for (const k of keys) {
      if (Array.isArray(payload[k])) return payload[k];
    }
  }
  return null;
}

/**
 * Strictly extracts search result items without ever matching echoed `query` strings.
 */
function extractSearchItems(json) {
  if (!json) return [];
  if (Array.isArray(json)) return json;
  if (typeof json !== 'object') return [];
  for (const key of ['results', 'items', 'hits', 'matches', 'entries', 'data']) {
    if (Array.isArray(json[key])) return json[key];
  }
  const grouped = [];
  for (const cat of ['apps', 'packages', 'files', 'processes', 'settings', 'actions']) {
    if (Array.isArray(json[cat])) grouped.push(...json[cat]);
  }
  if (json.results && typeof json.results === 'object' && !Array.isArray(json.results)) {
    for (const cat of ['apps', 'packages', 'files', 'processes', 'settings', 'actions']) {
      if (Array.isArray(json.results[cat])) grouped.push(...json.results[cat]);
    }
  }
  return grouped;
}

function getWinId(w) {
  return w?.windowId ?? w?.id ?? null;
}

function getWinBounds(w) {
  const b = w?.bounds ?? w ?? {};
  return {
    x: Number(b.x),
    y: Number(b.y),
    width: Number(b.width),
    height: Number(b.height),
  };
}

function getUiTree(w) {
  return w?.uiTree ?? w?.surface?.uiTree ?? null;
}

function getSurfaceRev(w) {
  return Number(w?.surfaceRevision ?? w?.surface?.surfaceRevision ?? w?.surface?.revision ?? 0);
}

function extractFileText(res) {
  if (!res || !res.ok) return null;
  if (typeof res.json?.content === 'string') return res.json.content;
  if (typeof res.json?.data === 'string') return res.json.data;
  if (typeof res.text === 'string') return res.text;
  return '';
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

async function installPackageHttp(api, bytes, filename, { grantAll = true } = {}) {
  let res = await api.post('/api/v1/packages/install', bytes, {
    query: { filename, grantAll: grantAll ? 'true' : 'false' },
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
      grantAll,
    });
  }
  assert.ok(res.ok, `Expected HTTP 2xx installing ${filename}, got ${res.status}: ${res.text}`);
  return res.json;
}

const SYSTEM_APP_ROLES = [
  { role: 'terminal', pattern: /omniterm|terminal/i },
  { role: 'files', pattern: /omnifiles|\bfiles\b/i },
  { role: 'monitor', pattern: /activity[\s_-]*monitor|task[\s_-]*monitor|\bmonitor\b/i },
  { role: 'apphub', pattern: /apphub|app[\s_-]*hub/i },
  { role: 'settings', pattern: /settings|privacy/i },
  { role: 'inspector', pattern: /inspector/i },
  { role: 'notes', pattern: /omninotes|\bnotes\b/i },
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
      platform === 'omnios'
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
    if (!c.appId) continue;
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

  for (const { role, pattern } of SYSTEM_APP_ROLES) {
    const roleEndRe = new RegExp(`(?:^|[._-])${role}$`, 'i');
    const matches = list
      .filter((c) => !used.has(c.appId) && (pattern.test(c.appId) || pattern.test(c.name)))
      .map((c) => {
        let score = 0;
        if (c.fromInstalled) score += 200;
        if (c.isBuiltin) score += 60;
        if (roleEndRe.test(c.appId)) score += 30;
        if (!c.platform || c.platform === 'system' || c.platform === 'universal' || c.platform === 'omnios') score += 20;
        if (/sharer/i.test(`${c.appId} ${c.name}`)) score -= 40;
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
  const state =
    procRes.json?.state ??
    procRes.json?.process?.state ??
    procRes.json?.pcb?.state ??
    procRes.json?.data?.state ??
    null;
  assert.ok(
    typeof state === 'string' && state.length > 0 && state !== 'TERMINATED' && state !== 'ZOMBIE',
    `Expected live non-terminated process for ${label} (PID ${pid}), got state=${JSON.stringify(state)} body=${procRes.text}`
  );
}

function extractProcessDebugAndVmm(procJson) {
  const p = procJson?.process ?? procJson?.pcb ?? procJson?.data ?? procJson ?? {};
  const debug = p.debugState ?? p.debug ?? p.cpu ?? p.execution ?? p.execState ?? null;
  const vmm = p.memoryStats ?? p.memory ?? p.vmm ?? p.addressSpace ?? p.mem ?? null;
  const registers = debug?.registers ?? p.registers ?? null;
  const pc = debug?.pc ?? p.pc;
  const sp = debug?.sp ?? p.sp;
  const arch = debug?.arch ?? p.arch ?? null;
  const mappedPages = vmm?.mappedPages ?? p.mappedPages;
  const usedBytes = vmm?.usedBytes ?? p.usedBytes;
  const regions = vmm?.regions ?? p.regions ?? null;
  return { p, debug, vmm, registers, pc, sp, arch, mappedPages, usedBytes, regions };
}

function isFiniteNumeric(v) {
  return (
    (typeof v === 'number' && Number.isFinite(v)) ||
    (typeof v === 'string' && v.trim() !== '' && Number.isFinite(Number(v)))
  );
}

function collectTreeNodes(node, out = [], visited = new Set()) {
  if (!node || typeof node !== 'object') return out;
  if (visited.has(node)) return out;
  visited.add(node);
  if (Array.isArray(node)) {
    for (const item of node) collectTreeNodes(item, out, visited);
    return out;
  }
  out.push(node);
  for (const key of ['children', 'items', 'tabs', 'panels', 'actions', 'buttons', 'rows']) {
    if (Array.isArray(node[key])) {
      for (const child of node[key]) collectTreeNodes(child, out, visited);
    }
  }
  for (const key of ['body', 'content', 'header', 'footer', 'sidebar', 'main']) {
    if (node[key] && typeof node[key] === 'object') {
      collectTreeNodes(node[key], out, visited);
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
  const inputTypes = new Set([
    'input', 'textarea', 'textfield', 'textbox', 'text-input', 'textinput', 'edittext',
    'terminal-input', 'command-input', 'editor', 'search',
  ]);
  return (
    nodes.find((n) => n.id && inputTypes.has(String(n.type ?? '').toLowerCase())) ??
    nodes.find((n) => n.id && /input|editor|command|term|note|text/i.test(String(n.id))) ??
    null
  );
}

/**
 * Verifies terminal actually executed `typedCmd` producing `needle` OUTSIDE the echoed command string.
 */
function hasExecutedTerminalOutput(uiTree, needle, typedCmd) {
  if (!uiTree || typeof uiTree !== 'object') return false;

  const inputTypes = new Set([
    'input', 'textarea', 'textfield', 'textbox', 'text-input', 'textinput', 'edittext',
    'terminal-input', 'command-input', 'editor', 'search',
  ]);
  const childKeys = new Set([
    'children', 'items', 'tabs', 'panels', 'actions', 'buttons', 'rows',
    'body', 'content', 'header', 'footer', 'sidebar', 'main',
  ]);
  const hasNonEchoNeedle = (val, seen = new Set()) => {
    if (typeof val === 'string') return val.replaceAll(typedCmd, '').includes(needle);
    if (!val || typeof val !== 'object') return false;
    if (seen.has(val)) return false;
    seen.add(val);
    if (Array.isArray(val)) {
      return val.some((x) => {
        if (typeof x === 'string') return x.replaceAll(typedCmd, '').includes(needle);
        if (x && typeof x === 'object' && !inputTypes.has(String(x.type ?? '').toLowerCase())) {
          if (Array.isArray(x)) return hasNonEchoNeedle(x, seen);
          return Object.values(x).some((sv) => typeof sv === 'string' && sv.replaceAll(typedCmd, '').includes(needle));
        }
        return false;
      });
    }
    if (!inputTypes.has(String(val.type ?? '').toLowerCase())) {
      return Object.values(val).some((sv) => typeof sv === 'string' && sv.replaceAll(typedCmd, '').includes(needle));
    }
    return false;
  };

  const hasPrimitiveNonEchoNeedle = (val, seen = new Set()) => {
    if (typeof val === 'string') return val.replaceAll(typedCmd, '').includes(needle);
    if (!Array.isArray(val) || seen.has(val)) return false;
    seen.add(val);
    return val.some((x) => hasPrimitiveNonEchoNeedle(x, seen));
  };

  const nodes = collectTreeNodes(uiTree);
  for (const n of nodes) {
    const t = String(n.type ?? '').toLowerCase();
    if (inputTypes.has(t)) continue;
    for (const [k, v] of Object.entries(n)) {
      if (childKeys.has(k)) {
        if (hasPrimitiveNonEchoNeedle(v)) return true;
        continue;
      }
      if (hasNonEchoNeedle(v)) return true;
    }
  }
  return false;
}

async function execShell(api, command) {
  const res = await api.post('/api/v1/shell/exec', { command }, { expectOk: true });
  const stdout =
    typeof res.json?.stdout === 'string'
      ? res.json.stdout
      : (typeof res.json?.output === 'string' ? res.json.output : JSON.stringify(res.json ?? res.text));
  return { res, stdout };
}

describe('Tier 4 — S03: Cross-Platform Productivity Handoff & 7 Built-in System Apps Admin Session', () => {
  it('T4-S03-01 [Scenario 5]: Cross-platform handoff pipeline (Windows .exe -> Clipboard/VFS -> Android .apk -> Intent -> macOS .app.zip + NSUserDefaults -> Spotlight)', async () => {
    let srv = null;
    const stopAppIds = [];
    try {
      // Fail-fast on public HTTP entrypoint before allocating fixtures
      srv = await startOmniServer();

      const nonce = makeNonce(4);
      const [andA, andB] = makeSafeAddOperands();
      const expectedSum = andA + andB;

      // ----------------------------------------------------------------------
      // Stage 1: Windows PE32+ .exe writes report to C:\Users\user\Documents\ & summary to Clipboard
      // ----------------------------------------------------------------------
      const reportName = `report-${nonce}.txt`;
      const reportPath = `/home/user/Documents/${reportName}`;
      const winExe = buildCustomPe64Exe({
        subsystem: 3,
        message: `WIN_SUMMARY_${nonce}\n`,
        writeFilePath: `C:\\Users\\user\\Documents\\${reportName}`,
        writeFileContent: `WIN_REPORT_${nonce}\n`,
        regHive: 0x80000001,
        regSubKey: `Software\\OmniHandoff\\Run_${nonce}`,
        regValueName: 'Report',
        regValueData: reportName,
        exitCode: 0,
      });

      const instWin = await installPackageHttp(srv.api, winExe, `handoff-win-${nonce}.exe`);
      const winAppId = instWin?.appId ?? instWin?.package?.appId ?? instWin?.id;
      assert.ok(winAppId, `Expected appId installing Windows PE32+ app: ${JSON.stringify(instWin)}`);
      stopAppIds.push(winAppId);

      await srv.api.post(`/api/v1/packages/${encodeURIComponent(winAppId)}/launch`, {}, { expectOk: true });

      const winReportText = await waitUntil(async () => {
        const res = await srv.api.get('/api/v1/vfs/file', { query: { path: reportPath } });
        const txt = extractFileText(res);
        return txt && txt.includes(`WIN_REPORT_${nonce}`) ? txt : null;
      }, { timeoutMs: 8000, label: `Windows .exe report at ${reportPath}` });
      assert.ok(winReportText.includes(`WIN_REPORT_${nonce}`));

      const winResolve = await srv.api.get('/api/v1/vfs/resolve', {
        query: { path: `C:\\Users\\user\\Documents\\${reportName}`, platform: 'windows' },
        expectOk: true,
      });
      assert.equal(winResolve.json?.canonicalPath ?? winResolve.json?.path, reportPath);

      const clipWrite = await writeWithMethodFallback(
        srv.api,
        ['PUT', 'POST'],
        '/api/v1/ipc/clipboard',
        {
          text: `WIN_SUMMARY_${nonce}`,
          html: `<em>WIN_SUMMARY_${nonce}</em>`,
          json: { report: reportName, nonce },
          mime: 'text/plain',
          sourceAppId: winAppId,
        }
      );
      assert.ok(clipWrite.ok, `Expected 2xx updating shared clipboard: ${clipWrite.status} ${clipWrite.text}`);
      const clipRead = await srv.api.get('/api/v1/ipc/clipboard', { expectOk: true });
      assert.ok(JSON.stringify(clipRead.json).includes(`WIN_SUMMARY_${nonce}`), `Clipboard missing summary: ${clipRead.text}`);

      // ----------------------------------------------------------------------
      // Stage 2: Pre-install Stage 3 macOS .app.zip, verify Android /sdcard/ view & run Android .apk
      // ----------------------------------------------------------------------
      const andResolve = await srv.api.get('/api/v1/vfs/resolve', {
        query: { path: `/sdcard/Documents/${reportName}`, platform: 'android' },
        expectOk: true,
      });
      assert.equal(andResolve.json?.canonicalPath ?? andResolve.json?.path, reportPath);

      const readViaAnd = await srv.api.get('/api/v1/vfs/file', { query: { path: reportPath }, expectOk: true });
      assert.ok((extractFileText(readViaAnd) ?? '').includes(`WIN_REPORT_${nonce}`));

      const macBundle = `com.omnios.handoff.mac${nonce}`;
      const macAppName = `HandoffMac_${nonce}`;
      const macScheme = `handoff${nonce}`;
      const macExt = `hnd${nonce.slice(0, 4)}`;
      const followupName = `followup-${nonce}.txt`;
      const followupPath = `/home/user/Documents/${followupName}`;

      const macZip = buildCustomMacAppZip({
        bundleId: macBundle,
        appName: macAppName,
        executableName: macAppName,
        arch: 'universal',
        plistFormat: 'xml',
        urlScheme: macScheme,
        documentExtensions: [macExt],
        fileWrite: {
          path: `/Users/user/Documents/${followupName}`,
          content: `MAC_FOLLOWUP_${nonce}_SUM=${expectedSum}`,
        },
        exitCode: 0,
      });
      const instMac = await installPackageHttp(srv.api, macZip, `handoff-mac-${nonce}.app.zip`);
      const macAppId = instMac?.appId ?? instMac?.package?.appId ?? instMac?.id ?? macBundle;
      stopAppIds.push(macAppId);

      const andPkg = `com.omnios.handoff.and${nonce}`;
      const andAppLabel = `HandoffAnd_${nonce}`;
      const calcOutPath = `/home/user/Documents/report-${nonce}-calc.txt`;
      const apkBytes = buildCustomApk({
        packageName: andPkg,
        appLabel: andAppLabel,
        computeA: andA,
        computeB: andB,
        computeOp: 'add',
        outputFile: `/sdcard/Documents/report-${nonce}-calc.txt`,
        // Omit outputContent so Dalvik writes dynamically computed sum
        sharedPrefName: 'handoff_prefs',
        sharedPrefKey: 'report_name',
        sharedPrefVal: reportName,
        intentAction: 'android.intent.action.VIEW',
        intentUri: `${macScheme}://followup`,
        notificationTitle: andAppLabel,
        notificationBody: `Sum=${expectedSum}`,
        permissions: [
          'android.permission.READ_EXTERNAL_STORAGE',
          'android.permission.WRITE_EXTERNAL_STORAGE',
          'android.permission.POST_NOTIFICATIONS',
        ],
      });
      const instAnd = await installPackageHttp(srv.api, apkBytes, `handoff-and-${nonce}.apk`);
      const andAppId = instAnd?.appId ?? instAnd?.package?.appId ?? instAnd?.id ?? andPkg;
      stopAppIds.push(andAppId);

      await srv.api.post(`/api/v1/packages/${encodeURIComponent(andAppId)}/launch`, {}, { expectOk: true });

      await waitUntil(async () => {
        const fRes = await srv.api.get('/api/v1/vfs/file', { query: { path: calcOutPath } });
        const fTxt = extractFileText(fRes) ?? '';
        if (!fTxt.includes(String(expectedSum))) return false;

        const snapRes = await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        const wins = asArray(snapRes.json, ['windows']);
        const andWin = wins.find((w) => w.appId === andAppId);
        if (!andWin || !JSON.stringify(getUiTree(andWin)).includes(String(expectedSum))) return false;

        const notifRes = await srv.api.get('/api/v1/ipc/notifications', { expectOk: true });
        return JSON.stringify(notifRes.json).includes(andAppLabel);
      }, { timeoutMs: 8000, label: `Android .apk dynamic sum=${expectedSum} in VFS, uiTree & notifications` });

      // Append Android's dynamically computed sum onto Windows's report
      const combinedReport = `WIN_REPORT_${nonce}\nAND_CALC=${expectedSum}\n`;
      const appendRes = await writeWithMethodFallback(
        srv.api,
        ['PUT', 'POST'],
        '/api/v1/vfs/file',
        { path: reportPath, content: combinedReport, data: combinedReport, encoding: 'utf8' }
      );
      assert.ok(appendRes.ok, `Expected 2xx updating shared report: ${appendRes.status}`);
      const mergedRead = await srv.api.get('/api/v1/vfs/file', { query: { path: reportPath }, expectOk: true });
      const mergedText = extractFileText(mergedRead) ?? '';
      assert.ok(mergedText.includes(`WIN_REPORT_${nonce}`) && mergedText.includes(`AND_CALC=${expectedSum}`));

      // ----------------------------------------------------------------------
      // Stage 3: Cross-Platform Intent -> macOS .app.zip follow-up & NSUserDefaults
      // ----------------------------------------------------------------------
      let resolveRes = await srv.api.post('/api/v1/ipc/intents/resolve', {
        scheme: macScheme,
        uri: `${macScheme}://followup`,
      });
      if (!resolveRes.ok && (resolveRes.status === 404 || resolveRes.status === 405)) {
        resolveRes = await srv.api.get('/api/v1/ipc/intents/resolve', {
          query: { scheme: macScheme, uri: `${macScheme}://followup` },
        });
      }
      assert.ok(resolveRes.ok, `Expected 2xx resolving macOS intent scheme ${macScheme}: ${resolveRes.status} ${resolveRes.text}`);
      const resolvedArr = unwrapExplicitArray(resolveRes.json, ['handlers', 'candidates', 'results', 'items', 'data']);
      assert.ok(resolvedArr !== null, `Intent resolve must return explicit array: ${resolveRes.text}`);
      assert.ok(
        JSON.stringify(resolvedArr).includes(macAppId) || JSON.stringify(resolvedArr).includes(macBundle),
        `Expected ${macBundle} in intent resolve candidates: ${resolveRes.text}`
      );

      // Check briefly if Android's startActivity already triggered macOS follow-up; else dispatch explicitly
      let macAlreadyRan = false;
      const probeDeadline = Date.now() + 1200;
      while (Date.now() < probeDeadline) {
        const fCheck = await srv.api.get('/api/v1/vfs/file', { query: { path: followupPath } });
        if ((extractFileText(fCheck) ?? '').includes(`MAC_FOLLOWUP_${nonce}_SUM=${expectedSum}`)) {
          macAlreadyRan = true;
          break;
        }
        await sleep(80);
      }

      if (!macAlreadyRan) {
        const dispRes = await srv.api.post('/api/v1/ipc/intents/dispatch', {
          scheme: macScheme,
          uri: `${macScheme}://followup`,
          extras: { report: reportName, sum: expectedSum },
        }, { expectOk: true });
        assert.equal(dispRes.json?.status, 'DELIVERED', `Expected DELIVERED intent dispatch to macOS app: ${dispRes.text}`);
        assert.equal(dispRes.json?.targetAppId, macAppId);
      }

      const followupText = await waitUntil(async () => {
        const res = await srv.api.get('/api/v1/vfs/file', { query: { path: followupPath } });
        const txt = extractFileText(res) ?? '';
        return txt.includes(`MAC_FOLLOWUP_${nonce}_SUM=${expectedSum}`) ? txt : null;
      }, { timeoutMs: 8000, label: `macOS follow-up file at ${followupPath}` });
      assert.ok(followupText.includes(`MAC_FOLLOWUP_${nonce}_SUM=${expectedSum}`));

      const macResolve = await srv.api.get('/api/v1/vfs/resolve', {
        query: { path: `/Users/user/Documents/${followupName}`, platform: 'macos' },
        expectOk: true,
      });
      assert.equal(macResolve.json?.canonicalPath ?? macResolve.json?.path, followupPath);

      const defMut = await writeWithMethodFallback(
        srv.api,
        ['PUT', 'POST', 'PATCH'],
        '/api/v1/config/defaults',
        { domain: macBundle, key: 'LastFollowup', value: followupName }
      );
      assert.ok(defMut.ok, `Expected 2xx updating macOS NSUserDefaults: ${defMut.status} ${defMut.text}`);
      const defRead = await srv.api.get('/api/v1/config/defaults', {
        query: { domain: macBundle, key: 'LastFollowup' },
        expectOk: true,
      });
      assert.ok(defRead.text.includes(followupName), `Expected LastFollowup=${followupName}: ${defRead.text}`);

      // ----------------------------------------------------------------------
      // Stage 4: Spotlight Universal Search GET /api/v1/search (strict item unwrapping)
      // ----------------------------------------------------------------------
      const searchFollowup = await srv.api.get('/api/v1/search', {
        query: { q: `followup-${nonce}` },
        expectOk: true,
      });
      const followupItems = extractSearchItems(searchFollowup.json);
      assert.ok(followupItems.length >= 1, `Expected Spotlight results for followup-${nonce}: ${searchFollowup.text}`);
      assert.ok(
        followupItems.some((item) => JSON.stringify(item).includes(followupName)),
        `Expected Spotlight items to include full filename ${followupName}: ${JSON.stringify(followupItems)}`
      );

      const searchReport = await srv.api.get('/api/v1/search', {
        query: { q: `report-${nonce}` },
        expectOk: true,
      });
      const reportItems = extractSearchItems(searchReport.json);
      assert.ok(reportItems.length >= 1, `Expected Spotlight results for report-${nonce}: ${searchReport.text}`);
      assert.ok(
        reportItems.some((item) => JSON.stringify(item).includes(reportName)),
        `Expected Spotlight items to include full filename ${reportName}: ${JSON.stringify(reportItems)}`
      );

      const searchMac = await srv.api.get('/api/v1/search', {
        query: { q: macAppName },
        expectOk: true,
      });
      const macItems = extractSearchItems(searchMac.json);
      assert.ok(macItems.length >= 1, `Expected Spotlight results for ${macAppName}: ${searchMac.text}`);
      assert.ok(
        macItems.some((item) => JSON.stringify(item).includes(macAppName) || JSON.stringify(item).includes(macBundle)),
        `Expected Spotlight items to include macOS app ${macAppName}: ${JSON.stringify(macItems)}`
      );

      const searchAnd = await srv.api.get('/api/v1/search', {
        query: { q: andAppLabel },
        expectOk: true,
      });
      const andItems = extractSearchItems(searchAnd.json);
      assert.ok(andItems.length >= 1, `Expected Spotlight results for ${andAppLabel}: ${searchAnd.text}`);
      assert.ok(
        andItems.some((item) => JSON.stringify(item).includes(andAppLabel) || JSON.stringify(item).includes(andAppId)),
        `Expected Spotlight items to include Android app ${andAppLabel}: ${JSON.stringify(andItems)}`
      );
    } finally {
      if (srv) {
        for (const id of stopAppIds) {
          await srv.api.post(`/api/v1/packages/${encodeURIComponent(id)}/stop`, {}).catch(() => {});
        }
        await srv.stop().catch(() => {});
      }
    }
  });

  it('T4-S03-02 [Scenario 6]: Full 7 built-in system apps admin session + multi-syntax shell + Kernel Panic / Safe-Mode Recovery + Cold Restart zero-data-loss', async () => {
    let sharedTmp = null;
    let srv1 = null;
    let os2 = null;
    try {
      // Fail-fast on BOTH public entrypoints BEFORE creating temp dirs
      await assertPublicEntryExists(PUBLIC_PATHS.httpServerEntry, 'os/server/http-server.mjs');
      await assertPublicEntryExists(PUBLIC_PATHS.osEntry, 'os/os.mjs');

      sharedTmp = await createTempDataDir('omnios-s03-admin-');
      srv1 = await startOmniServer({ dataDir: sharedTmp.dir, keepDataDir: true });

      const nonce = makeNonce(4);

      // 1. Dynamically discover all 7 built-in system apps (ZERO hardcoded app IDs)
      const sysApps = await discoverSystemAppsHttp(srv1.api);

      // 2. Seed durable admin file & install a custom target .uapp
      const adminDocPath = `/home/user/Documents/admin-session-${nonce}.txt`;
      const adminDocContent = `ADMIN_DATA_${nonce}`;
      const seedRes = await writeWithMethodFallback(
        srv1.api,
        ['PUT', 'POST'],
        '/api/v1/vfs/file',
        { path: adminDocPath, content: adminDocContent, data: adminDocContent, encoding: 'utf8' }
      );
      assert.ok(seedRes.ok, `Expected 2xx seeding admin VFS doc: ${seedRes.status} ${seedRes.text}`);

      const targetAppId = `com.omnios.s06.target${nonce}`;
      await installPackageHttp(
        srv1.api,
        buildCustomUapp({ appId: targetAppId, name: `AdminTarget_${nonce}`, message: `TARGET_${nonce}\n` }),
        `admin-target-${nonce}.uapp`
      );

      // Install & launch a persistent live dynamic Android .apk for live PID register/VMM inspection & shell kill
      const liveBinPkg = `com.omnios.s06.livebin${nonce}`;
      const liveBinLabel = `AdminLiveBin_${nonce}`;
      const [binA, binB] = makeSafeAddOperands();
      const binSum = binA + binB;
      const liveBinOutPath = `/home/user/Documents/admin-livebin-${nonce}.txt`;
      const instLiveBin = await installPackageHttp(
        srv1.api,
        buildCustomApk({
          packageName: liveBinPkg,
          appLabel: liveBinLabel,
          computeA: binA,
          computeB: binB,
          computeOp: 'add',
          outputFile: `/sdcard/Documents/admin-livebin-${nonce}.txt`,
          permissions: ['android.permission.WRITE_EXTERNAL_STORAGE'],
        }),
        `admin-livebin-${nonce}.apk`,
        { grantAll: true }
      );
      const liveBinAppId = instLiveBin?.appId ?? instLiveBin?.package?.appId ?? instLiveBin?.id ?? liveBinPkg;

      const lLiveBin = await srv1.api.post(`/api/v1/packages/${encodeURIComponent(liveBinAppId)}/launch`, {}, { expectOk: true });
      const liveBinPid = lLiveBin.json?.pid ?? lLiveBin.json?.process?.pid;
      assert.ok(Number.isInteger(liveBinPid) && liveBinPid > 1, `Expected valid PID > 1 launching live binary APK: ${lLiveBin.text}`);

      await waitUntil(async () => {
        const fRes = await srv1.api.get('/api/v1/vfs/file', { query: { path: liveBinOutPath } });
        if ((extractFileText(fRes) ?? '').includes(String(binSum))) return true;
        const snap = await srv1.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        const w = asArray(snap.json, ['windows']).find((x) => x.pid === liveBinPid || x.appId === liveBinAppId);
        return Boolean(w && JSON.stringify(getUiTree(w)).includes(String(binSum)));
      }, { timeoutMs: 8000, label: `live binary APK PID ${liveBinPid} executed Dalvik sum=${binSum}` });

      // 3. Launch all 7 built-in system apps concurrently as real kernel processes + Compositor windows
      const roles = ['terminal', 'files', 'monitor', 'apphub', 'settings', 'inspector', 'notes'];
      const launched = {};
      for (const role of roles) {
        const appId = sysApps[role];
        const lRes = await srv1.api.post(`/api/v1/packages/${encodeURIComponent(appId)}/launch`, {}, { expectOk: true });
        const pid = lRes.json?.pid ?? lRes.json?.process?.pid;
        assert.ok(Number.isInteger(pid) && pid > 1, `Expected valid PID > 1 launching ${role} (${appId}): ${lRes.text}`);
        launched[role] = { appId, pid };
      }
      assert.equal(new Set(roles.map((r) => launched[r].pid)).size, 7, `Expected 7 distinct PIDs: ${JSON.stringify(launched)}`);

      // Wait for all 7 windows in Compositor snapshot & validate title, bounds, uiTree & live PID
      const roleWins = await waitUntil(async () => {
        const snap = await srv1.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        const wins = asArray(snap.json, ['windows']);
        const mapped = {};
        for (const role of roles) {
          const { appId, pid } = launched[role];
          const w = wins.find((x) => x.pid === pid || x.appId === appId);
          if (!w) return null;
          mapped[role] = w;
        }
        return mapped;
      }, { timeoutMs: 8000, label: 'all 7 built-in system app Compositor windows' });

      for (const role of roles) {
        const w = roleWins[role];
        const b = getWinBounds(w);
        assert.ok(typeof w.title === 'string' && w.title.length > 0, `Expected non-empty title for ${role}`);
        assert.ok(b.width > 0 && b.height > 0, `Expected positive bounds for ${role}, got ${JSON.stringify(b)}`);
        const tree = getUiTree(w);
        assert.ok(tree && Object.keys(tree).length > 0, `Expected populated uiTree for ${role}`);
        const pRes = await srv1.api.get(`/api/v1/processes/${launched[role].pid}`, { expectOk: true });
        assertProcessAlive(pRes, role, launched[role].pid);
      }

      // 4. Interactive OmniTerm command execution (strict non-echo verification)
      const termWinId = getWinId(roleWins.terminal);
      const termInputNode = findInputNode(getUiTree(roleWins.terminal));
      const typedCmd = `echo S06_TERM_${nonce}`;
      await srv1.api.post(`/api/v1/compositor/windows/${encodeURIComponent(termWinId)}/input`, {
        type: 'command',
        action: 'exec',
        nodeId: termInputNode?.id ?? 'terminal-input',
        value: typedCmd,
        text: typedCmd,
        command: typedCmd,
      }, { expectOk: true });
      await srv1.api.post(`/api/v1/compositor/windows/${encodeURIComponent(termWinId)}/input`, {
        type: 'keydown',
        key: 'Enter',
        nodeId: termInputNode?.id ?? 'terminal-input',
        value: typedCmd,
      });

      await waitUntil(async () => {
        const snap = await srv1.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        const w = asArray(snap.json, ['windows']).find((x) => getWinId(x) === termWinId);
        return hasExecutedTerminalOutput(getUiTree(w), `S06_TERM_${nonce}`, typedCmd);
      }, { timeoutMs: 6000, label: `OmniTerm executed output S06_TERM_${nonce}` });

      // 5. Multi-syntax Shell commands via POST /api/v1/shell/exec (ls, dir, reg, defaults, prefs, ps)
      const shLs = await execShell(srv1.api, 'ls /home/user/Documents');
      assert.ok(shLs.stdout.includes(`admin-session-${nonce}.txt`), `Shell ls missing admin doc: ${shLs.stdout}`);

      const shDir = await execShell(srv1.api, 'dir C:\\Users\\user\\Documents');
      assert.ok(shDir.stdout.includes(`admin-session-${nonce}.txt`), `Shell Windows dir missing admin doc: ${shDir.stdout}`);

      // Registry set/get via shell
      const regSubKey = `Software\\OmniAdmin_${nonce}`;
      const regVal = `REG_SURVIVE_${nonce}`;
      let regSetRes = await srv1.api.post('/api/v1/shell/exec', {
        command: `reg set HKCU ${regSubKey} AuditKey REG_SZ ${regVal}`,
      });
      let usedCombinedReg = false;
      if (!regSetRes.ok || /error|usage|invalid/i.test(String(regSetRes.json?.stderr ?? ''))) {
        regSetRes = await srv1.api.post('/api/v1/shell/exec', {
          command: `reg set HKCU\\${regSubKey} AuditKey ${regVal}`,
        }, { expectOk: true });
        usedCombinedReg = true;
      }
      const regGetCmd = usedCombinedReg
        ? `reg get HKCU\\${regSubKey} AuditKey`
        : `reg get HKCU ${regSubKey} AuditKey`;
      const shRegGet = await execShell(srv1.api, regGetCmd);
      assert.ok(shRegGet.stdout.includes(regVal), `Shell reg get missing ${regVal}: ${shRegGet.stdout}`);

      // Apple Defaults write/read via shell
      const defDomain = `com.omnios.admin.${nonce}`;
      const defVal = `DEF_SURVIVE_${nonce}`;
      await execShell(srv1.api, `defaults write ${defDomain} AdminFlag ${defVal}`);
      const shDefRead = await execShell(srv1.api, `defaults read ${defDomain} AdminFlag`);
      assert.ok(shDefRead.stdout.includes(defVal), `Shell defaults read missing ${defVal}: ${shDefRead.stdout}`);

      // Android SharedPreferences set/get via shell
      const prefVal = `PREF_SURVIVE_${nonce}`;
      let prefSetRes = await srv1.api.post('/api/v1/shell/exec', {
        command: `prefs set ${defDomain} admin PrefFlag ${prefVal}`,
      });
      let usedShortPref = false;
      if (!prefSetRes.ok || /error|usage|invalid/i.test(String(prefSetRes.json?.stderr ?? ''))) {
        prefSetRes = await srv1.api.post('/api/v1/shell/exec', {
          command: `prefs set ${defDomain} PrefFlag ${prefVal}`,
        }, { expectOk: true });
        usedShortPref = true;
      }
      const prefGetCmd = usedShortPref
        ? `prefs get ${defDomain} PrefFlag`
        : `prefs get ${defDomain} admin`;
      const shPrefGet = await execShell(srv1.api, prefGetCmd);
      assert.ok(shPrefGet.stdout.includes(prefVal), `Shell prefs get missing ${prefVal}: ${shPrefGet.stdout}`);

      const shPs = await execShell(srv1.api, 'ps');
      assert.ok(
        shPs.stdout.trim().length > 0 && /omnid|\b1\b/i.test(shPs.stdout) && shPs.stdout.includes(String(liveBinPid)),
        `Shell ps output must list init and live binary PID ${liveBinPid}: ${shPs.stdout}`
      );

      // 6. Live binary PID register/debug & VMM inspection (GET /api/v1/processes/:pid + /proc/<pid>/status) + shell `kill <pid>`
      const liveBinProcRes = await srv1.api.get(`/api/v1/processes/${liveBinPid}`, { expectOk: true });
      assertProcessAlive(liveBinProcRes, liveBinAppId, liveBinPid);
      const liveProcInfo = extractProcessDebugAndVmm(liveBinProcRes.json);
      const hasRegsOrDebug = Boolean(
        (liveProcInfo.registers && typeof liveProcInfo.registers === 'object' && Object.keys(liveProcInfo.registers).length > 0) ||
        (liveProcInfo.debug && typeof liveProcInfo.debug === 'object' && Object.keys(liveProcInfo.debug).length > 0) ||
        (liveProcInfo.pc !== undefined && liveProcInfo.pc !== null) ||
        (liveProcInfo.sp !== undefined && liveProcInfo.sp !== null)
      );
      assert.ok(
        hasRegsOrDebug,
        `Expected live binary PID ${liveBinPid} GET /api/v1/processes/:pid to expose registers/debug state: ${liveBinProcRes.text}`
      );

      const procPidStatusRes = await srv1.api.get('/api/v1/vfs/file', {
        query: { path: `/proc/${liveBinPid}/status` },
        expectOk: true,
      });
      const procPidStatusTxt = extractFileText(procPidStatusRes) ?? '';
      assert.ok(
        procPidStatusTxt.trim().length > 0 && procPidStatusTxt.includes(String(liveBinPid)),
        `Expected /proc/${liveBinPid}/status to contain live PID ${liveBinPid} status: ${procPidStatusRes.text}`
      );
      const hasVmmInRest = Boolean(
        (liveProcInfo.vmm && typeof liveProcInfo.vmm === 'object' && Object.keys(liveProcInfo.vmm).length > 0) ||
        isFiniteNumeric(liveProcInfo.mappedPages) ||
        isFiniteNumeric(liveProcInfo.usedBytes) ||
        Array.isArray(liveProcInfo.regions)
      );
      const hasVmmInProcStatus = /mem|page|vmm|ram|bytes|rss|vm/i.test(procPidStatusTxt);
      assert.ok(
        hasVmmInRest || hasVmmInProcStatus,
        `Expected VMM memory/page stats for live binary PID ${liveBinPid} in /api/v1/processes/:pid or /proc/${liveBinPid}/status: rest=${liveBinProcRes.text} proc=${procPidStatusTxt}`
      );

      // Terminate live binary test process via multi-syntax shell `kill <pid>`
      const shKill = await execShell(srv1.api, `kill ${liveBinPid}`);
      assert.ok(shKill.res.ok, `Expected HTTP 2xx executing shell kill ${liveBinPid}: ${shKill.res.text}`);
      await waitUntil(async () => {
        const pCheck = await srv1.api.get(`/api/v1/processes/${liveBinPid}`);
        if (pCheck.status === 404) return true;
        const st =
          pCheck.json?.state ??
          pCheck.json?.process?.state ??
          pCheck.json?.pcb?.state ??
          pCheck.json?.data?.state ??
          null;
        if (st === 'TERMINATED' || st === 'ZOMBIE') return true;
        const listRes = await srv1.api.get('/api/v1/processes', { expectOk: true });
        const procs = asArray(listRes.json, ['processes', 'items', 'data']);
        const hit = procs.find((x) => x.pid === liveBinPid);
        return !hit || hit.state === 'TERMINATED' || hit.state === 'ZOMBIE';
      }, { timeoutMs: 6000, label: `live binary PID ${liveBinPid} terminated via shell kill` });

      // Process tree, dynamic /proc/uptime mount & interactive controls across remaining 6 built-in apps
      const treeRes = await srv1.api.get('/api/v1/processes/tree', { expectOk: true });
      assert.ok(treeRes.json !== null, 'Expected non-null /api/v1/processes/tree');

      const procUptime = await srv1.api.get('/api/v1/vfs/file', { query: { path: '/proc/uptime' } });
      const procStat = procUptime.ok ? procUptime : await srv1.api.get('/api/v1/vfs/stat', { query: { path: '/proc/uptime' } });
      assert.ok(procStat.ok, `Expected dynamic /proc/uptime readable via VFS REST: ${procStat.status} ${procStat.text}`);

      // Drive interactive input into OmniNotes
      const notesWinId = getWinId(roleWins.notes);
      const notesRev0 = getSurfaceRev(roleWins.notes);
      const notesInputNode = findInputNode(getUiTree(roleWins.notes));
      await srv1.api.post(`/api/v1/compositor/windows/${encodeURIComponent(notesWinId)}/input`, {
        type: 'input',
        nodeId: notesInputNode?.id ?? 'notes-editor',
        value: `NOTE_S06_${nonce}`,
        text: `NOTE_S06_${nonce}`,
      }, { expectOk: true });
      await waitUntil(async () => {
        const snap = await srv1.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        const w = asArray(snap.json, ['windows']).find((x) => getWinId(x) === notesWinId);
        return Boolean(w && (getSurfaceRev(w) > notesRev0 || JSON.stringify(getUiTree(w)).includes(`NOTE_S06_${nonce}`)));
      }, { timeoutMs: 5000, label: 'OmniNotes surface update after input' });

      // Click a discovered interactive node in the other 5 system apps & verify live PIDs
      for (const role of ['files', 'monitor', 'apphub', 'settings', 'inspector']) {
        const winId = getWinId(roleWins[role]);
        const clickable = findClickableNode(getUiTree(roleWins[role]));
        const clickRes = await srv1.api.post(`/api/v1/compositor/windows/${encodeURIComponent(winId)}/input`, {
          type: 'click',
          nodeId: clickable?.id ?? 'root',
          action: clickable?.action ?? undefined,
        });
        assert.equal(clickRes.status, 200, `Expected HTTP 200 clicking interactive node in ${role}: ${clickRes.text}`);
        const pRes = await srv1.api.get(`/api/v1/processes/${launched[role].pid}`, { expectOk: true });
        assertProcessAlive(pRes, role, launched[role].pid);
      }

      // Stop all 7 system apps cleanly
      for (const role of roles) {
        await srv1.api.post(`/api/v1/packages/${encodeURIComponent(launched[role].appId)}/stop`, {}, { expectOk: true });
      }
      await waitUntil(async () => {
        const snap = await srv1.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        const wins = asArray(snap.json, ['windows']);
        const pidSet = new Set(roles.map((r) => launched[r].pid));
        return !wins.some((w) => pidSet.has(w.pid));
      }, { timeoutMs: 6000, label: 'all 7 system app windows closed after stop' });

      // 7. Controlled Kernel Panic + Safe-Mode Recovery (REST) + Cold Restart Zero-Data-Loss (Public API)
      const panicCode = `E_S06_PANIC_${nonce}`;
      const panicRes = await srv1.api.post('/api/v1/kernel/panic', {
        code: panicCode,
        reason: `Admin session crash ${nonce}`,
      }, { expectOk: true });
      assert.equal(panicRes.status, 200);

      const statusPanic = await srv1.api.get('/api/v1/kernel/status', { expectOk: true });
      assert.match(JSON.stringify(statusPanic.json), /PANIC/i, `Kernel status must report PANIC: ${statusPanic.text}`);
      assert.ok(JSON.stringify(statusPanic.json).includes(panicCode), `lastPanic must contain ${panicCode}: ${statusPanic.text}`);

      const recRes = await srv1.api.post('/api/v1/kernel/recover', { safeMode: true }, { expectOk: true });
      assert.equal(recRes.status, 200);
      const statusRecovered = await srv1.api.get('/api/v1/kernel/status', { expectOk: true });
      const recState = statusRecovered.json?.state ?? statusRecovered.json?.status;
      assert.ok(
        recState === 'RUNNING' || recState === 'SAFE_MODE',
        `Kernel status must return to RUNNING or SAFE_MODE: ${statusRecovered.text}`
      );

      // Shut down srv1 cleanly & Cold Restart directly on the SAME SQLite dataDir
      await srv1.stop();
      srv1 = null;

      os2 = await loadPublicOmniOS({ dataDir: sharedTmp.dir, keepDataDir: true });
      const diag2 = os2.require('kernel').getDiagnostics();
      assert.equal(diag2?.state, 'RUNNING');
      assert.ok(JSON.stringify(diag2?.lastPanic ?? {}).includes(panicCode), `Persisted lastPanic missing ${panicCode}: ${JSON.stringify(diag2)}`);

      const svc2Json = JSON.stringify(os2.require('serviceManager').getStatus());
      for (const svcName of ['vfsd', 'configd', 'ipc-brokerd', 'securityd', 'pkgd', 'compositord']) {
        assert.ok(svc2Json.includes(svcName), `Core service "${svcName}" missing after cold restart`);
      }

      const vfsRaw2 = await os2.require('vfs').readFile(adminDocPath, { encoding: 'utf8' });
      const vfsText2 = typeof vfsRaw2 === 'string' ? vfsRaw2 : Buffer.from(vfsRaw2).toString('utf8');
      assert.equal(vfsText2, adminDocContent, 'VFS file lost across panic + safeMode + cold restart');

      const reg2 = await os2.require('configStore').registry.getValue('HKCU', regSubKey, 'AuditKey', { uid: 0 });
      assert.equal(String(reg2?.data ?? '').replace(/\0+$/, ''), regVal, 'Registry value lost across cold restart');

      const def2 = await os2.require('configStore').defaults.get(defDomain, 'AdminFlag');
      assert.equal(def2, defVal, 'Apple Defaults value lost across cold restart');

      let spPersisted = null;
      for (const prefName of ['admin', 'default', 'main', 'prefs']) {
        try {
          const m = await os2.require('configStore').sharedPrefs.getAll(defDomain, prefName);
          if (m && m.PrefFlag === prefVal) {
            spPersisted = m.PrefFlag;
            break;
          }
        } catch {
          // try next prefName
        }
      }
      assert.equal(spPersisted, prefVal, 'Android SharedPreferences lost across cold restart');

      const pkgs2 = await os2.require('pkgManager').list();
      assert.ok(
        pkgs2.some((p) => (p?.appId ?? p?.id ?? p) === targetAppId),
        `Installed package ${targetAppId} lost across cold restart: ${JSON.stringify(pkgs2)}`
      );
      assert.ok(
        pkgs2.some((p) => (p?.appId ?? p?.id ?? p) === liveBinAppId),
        `Installed binary package ${liveBinAppId} lost across cold restart: ${JSON.stringify(pkgs2)}`
      );

      // Re-launch persisted binary on os2 and strictly verify live execCtx.getDebugState() & addressSpace.getStats()
      const scheduler2 = os2.require('scheduler');
      const pm2 = os2.require('processManager');
      scheduler2.stop?.();
      const lBin2 = await os2.require('pkgManager').launch(liveBinAppId, {});
      assert.ok(
        Number.isInteger(lBin2?.pid) && lBin2.pid > 1,
        `Expected valid PID launching persisted binary ${liveBinAppId} on os2: ${JSON.stringify(lBin2)}`
      );
      for (let stepIdx = 0; stepIdx < 40; stepIdx++) {
        await scheduler2.step(5);
      }
      const pcb2 = pm2.get(lBin2.pid);
      assert.ok(
        pcb2 && pcb2.state !== 'TERMINATED' && pcb2.state !== 'ZOMBIE',
        `Expected live PCB for PID ${lBin2.pid} on os2, got state=${pcb2?.state}`
      );

      const execCtx2 =
        pcb2.executionContext ??
        pcb2.execCtx ??
        (pcb2.threads instanceof Map ? Array.from(pcb2.threads.values())[0]?.executionContext : null) ??
        (Array.isArray(pcb2.threads) ? pcb2.threads[0]?.executionContext : null) ??
        null;
      assert.ok(
        execCtx2 && typeof execCtx2.getDebugState === 'function',
        `Expected live IExecutionContext.getDebugState() on PID ${lBin2.pid}`
      );
      const dbg2 = execCtx2.getDebugState();
      assert.ok(dbg2 && typeof dbg2 === 'object', `Expected non-null getDebugState(): ${JSON.stringify(dbg2)}`);
      assert.ok(typeof dbg2.arch === 'string' && dbg2.arch.length > 0, `Expected non-empty arch in getDebugState(): ${JSON.stringify(dbg2)}`);
      assert.ok(dbg2.pc !== undefined && dbg2.pc !== null, `Expected pc in getDebugState(): ${JSON.stringify(dbg2)}`);
      assert.ok(dbg2.sp !== undefined && dbg2.sp !== null, `Expected sp in getDebugState(): ${JSON.stringify(dbg2)}`);
      assert.ok(
        dbg2.registers && typeof dbg2.registers === 'object' && Object.keys(dbg2.registers).length > 0,
        `Expected non-empty registers in getDebugState(): ${JSON.stringify(dbg2)}`
      );

      const addrSpace2 = pcb2.addressSpace ?? pcb2.vmm ?? null;
      assert.ok(
        addrSpace2 && typeof addrSpace2.getStats === 'function',
        `Expected live addressSpace.getStats() on PID ${lBin2.pid}`
      );
      const vmmStats2 = addrSpace2.getStats();
      assert.ok(vmmStats2 && typeof vmmStats2 === 'object', `Expected non-null addressSpace.getStats(): ${JSON.stringify(vmmStats2)}`);
      assert.ok(
        isFiniteNumeric(vmmStats2.mappedPages) && Number(vmmStats2.mappedPages) >= 0,
        `Expected numeric mappedPages in addressSpace.getStats(): ${JSON.stringify(vmmStats2)}`
      );
      assert.ok(
        isFiniteNumeric(vmmStats2.usedBytes) && Number(vmmStats2.usedBytes) >= 0,
        `Expected numeric usedBytes in addressSpace.getStats(): ${JSON.stringify(vmmStats2)}`
      );
      assert.ok(
        Array.isArray(vmmStats2.regions),
        `Expected regions array in addressSpace.getStats(): ${JSON.stringify(vmmStats2)}`
      );

      await os2.require('pkgManager').stop(lBin2.pid);

      // Direct programmatic panic -> recover({ safeMode: true }) verification preserving VFS
      await os2.require('kernel').panic(`E_S06_DIRECT_${nonce}`, `Direct panic ${nonce}`, { nonce });
      await os2.require('kernel').recover({ safeMode: true });
      const directState = os2.require('kernel').getDiagnostics()?.state;
      assert.ok(
        directState === 'RUNNING' || directState === 'SAFE_MODE',
        `Kernel state must return to RUNNING or SAFE_MODE after safeMode recovery (got ${directState})`
      );
      const vfsAfterDirect = await os2.require('vfs').readFile(adminDocPath, { encoding: 'utf8' });
      const vfsAfterDirectTxt = typeof vfsAfterDirect === 'string' ? vfsAfterDirect : Buffer.from(vfsAfterDirect).toString('utf8');
      assert.equal(vfsAfterDirectTxt, adminDocContent, 'VFS data must survive programmatic panic + safeMode recovery');
    } finally {
      if (srv1) await srv1.stop().catch(() => {});
      if (os2) await os2.shutdown().catch(() => {});
      if (sharedTmp) await sharedTmp.cleanup().catch(() => {});
    }
  });
});
