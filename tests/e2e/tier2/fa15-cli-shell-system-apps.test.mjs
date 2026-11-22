/**
 * OmniOS Tier 2 E2E Suite — FA-15: Headless/Remote CLI, Multi-Syntax Shell & System Apps
 * Boundary, Corner & Negative Cases.
 * Covers PROJECT.md Features: F-009, F-034, F-065, F-066, F-067–F-072, Contracts 7 & 8.
 *
 * STRICT INVARIANTS:
 * - Opaque-box only: imports ONLY Node 24 built-ins and ../lib/*.mjs.
 * - Zero hardcoded system app identifiers; all built-in apps are discovered dynamically.
 * - Zero skips, zero stubs, zero vacuous assertions.
 * - Clean try/finally teardown on every test.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import {
  PUBLIC_PATHS,
  allocateEphemeralPort,
  assertPublicEntryExists,
  createTempDataDir,
  runCli,
  startOmniServer,
} from '../lib/env.mjs';

function makeNonce() {
  return crypto.randomBytes(4).toString('hex');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitUntil(fn, { timeoutMs = 5000, intervalMs = 50, label = 'condition' } = {}) {
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

function asArray(payload, keys = ['packages', 'apps', 'catalog', 'items', 'data', 'entries', 'processes', 'windows']) {
  if (Array.isArray(payload)) return payload;
  if (payload && typeof payload === 'object') {
    for (const k of keys) {
      if (Array.isArray(payload[k])) return payload[k];
    }
  }
  return [];
}

function tryParseJson(text) {
  const trimmed = String(text ?? '').trim();
  if (!trimmed) return null;
  try {
    return JSON.parse(trimmed);
  } catch {
    // Also check last non-empty JSON line if CLI printed a status prefix
    const lines = trimmed.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    for (let i = lines.length - 1; i >= 0; i--) {
      if (lines[i].startsWith('{') || lines[i].startsWith('[')) {
        try {
          return JSON.parse(lines[i]);
        } catch {
          // continue
        }
      }
    }
    return null;
  }
}

function extractCliJsonError(res) {
  if (res.json && typeof res.json === 'object') return res.json;
  const fromStderr = tryParseJson(res.stderr);
  if (fromStderr && typeof fromStderr === 'object') return fromStderr;
  const fromStdout = tryParseJson(res.stdout);
  if (fromStdout && typeof fromStdout === 'object') return fromStdout;
  return null;
}

function extractProcState(json) {
  return json?.state ?? json?.process?.state ?? json?.pcb?.state ?? json?.data?.state ?? null;
}

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
      platform === 'system'
    );
    out.push({ appId, name, platform, isBuiltin, fromInstalled, raw: item });
  };

  if (Array.isArray(source)) {
    for (const item of source) add(item);
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

async function discoverBuiltInApp(api, preferredPatterns) {
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
        raw: prev.raw ?? c.raw,
      });
    }
  }
  const all = Array.from(byId.values());

  for (const pattern of preferredPatterns) {
    const matches = all
      .filter((c) => pattern.test(c.appId) || pattern.test(c.name))
      .map((c) => {
        let score = 0;
        if (c.fromInstalled) score += 200;
        if (c.isBuiltin) score += 60;
        if (!c.platform || c.platform === 'system' || c.platform === 'universal' || c.platform === 'omnios') score += 20;
        if (/sharer/i.test(`${c.appId} ${c.name}`)) score -= 40;
        return { c, score };
      })
      .sort((a, b) => b.score - a.score);
    if (matches.length > 0) {
      return { appId: matches[0].c.appId, pkg: matches[0].c };
    }
  }

  assert.fail(`Could not dynamically discover any built-in system app matching ${preferredPatterns.join(', ')}; candidates=${JSON.stringify(all.map((x) => ({ appId: x.appId, name: x.name })))}`);
}

describe('Tier 2 — FA-15: Headless/Remote CLI, Multi-Syntax Shell & System Apps (Boundary & Negative)', () => {
  it('T2-FA15-01 [F-065]: CLI unknown subcommand & missing required arguments exit non-zero cleanly without hanging', async () => {
    let tmp = null;
    try {
      // Fail loudly with E_OMNIOS_NOT_IMPLEMENTED before allocating temp directories
      await assertPublicEntryExists(PUBLIC_PATHS.cliEntry, 'os/cli/omnios-cli.mjs');
      tmp = await createTempDataDir('omnios-t2-fa15-01-');

      const badInvocations = [
        ['nonexistent-subcmd-xyz'],
        ['kill'],
        ['vfs', 'cat'],
        ['ospm', 'install'],
        ['reg', 'get'],
      ];

      for (const args of badInvocations) {
        const res = await runCli(args, { dataDir: tmp.dir, json: true, timeoutMs: 10000 });
        assert.notEqual(
          res.code,
          0,
          `CLI "${args.join(' ')}" must exit non-zero, got code=0 stdout=${JSON.stringify(res.stdout)}`
        );
        assert.equal(res.signal, null, `CLI "${args.join(' ')}" should exit cleanly, not via signal=${res.signal}`);
        assert.ok(
          (res.stderr + res.stdout).trim().length > 0,
          `CLI "${args.join(' ')}" should emit an informative error/usage message`
        );
      }
    } finally {
      if (tmp) await tmp.cleanup().catch(() => {});
    }
  });

  it('T2-FA15-02 [F-065]: CLI invalid & unreachable --remote URLs exit non-zero promptly without hanging', async () => {
    await assertPublicEntryExists(PUBLIC_PATHS.cliEntry, 'os/cli/omnios-cli.mjs');
    const unusedPort = await allocateEphemeralPort('127.0.0.1');

    const badRemotes = [
      `http://127.0.0.1:${unusedPort}`,
      'not-a-valid-url://???',
    ];

    for (const remote of badRemotes) {
      const t0 = Date.now();
      const res = await runCli(['status'], { remote, json: true, timeoutMs: 10000 });
      const elapsed = Date.now() - t0;

      assert.notEqual(
        res.code,
        0,
        `CLI status --remote "${remote}" must exit non-zero, got code=0 stdout=${JSON.stringify(res.stdout)}`
      );
      assert.equal(res.signal, null, `CLI status --remote "${remote}" terminated by signal=${res.signal}`);
      assert.ok(
        (res.stderr + res.stdout).trim().length > 0,
        `CLI status --remote "${remote}" must output an error diagnostic`
      );
      assert.ok(elapsed < 9000, `CLI status --remote "${remote}" took ${elapsed}ms (expected prompt failure < 9000ms)`);
    }
  });

  it('T2-FA15-03 [F-065]: CLI kill 999999 & vfs cat /does/not/exist return non-zero with structured JSON errors (--json) in remote & local modes', async () => {
    let srv = null;
    let tmp = null;
    try {
      srv = await startOmniServer();
      tmp = await createTempDataDir('omnios-t2-fa15-03-');
      const nonce = makeNonce();
      const missingFile = `/does/not/exist/missing-${nonce}.txt`;

      const modes = [
        { label: 'remote', run: (args) => srv.runCli(args, { json: true, timeoutMs: 10000 }) },
        { label: 'local', run: (args) => runCli(args, { dataDir: tmp.dir, json: true, timeoutMs: 10000 }) },
      ];

      for (const mode of modes) {
        // 1. kill 999999
        const killRes = await mode.run(['kill', '999999']);
        assert.notEqual(killRes.code, 0, `[${mode.label}] kill 999999 must exit non-zero`);
        assert.equal(killRes.signal, null);
        const killErr = extractCliJsonError(killRes);
        assert.ok(
          killErr && (killErr.ok === false || Boolean(killErr.error) || Boolean(killErr.code) || Boolean(killErr.message)),
          `[${mode.label}] Expected structured JSON error for kill 999999 --json, got stdout=${JSON.stringify(killRes.stdout)} stderr=${JSON.stringify(killRes.stderr)}`
        );

        // 2. vfs cat /does/not/exist/...
        const catRes = await mode.run(['vfs', 'cat', missingFile]);
        assert.notEqual(catRes.code, 0, `[${mode.label}] vfs cat missing file must exit non-zero`);
        assert.equal(catRes.signal, null);
        const catErr = extractCliJsonError(catRes);
        assert.ok(
          catErr && (catErr.ok === false || Boolean(catErr.error) || Boolean(catErr.code) || Boolean(catErr.message)),
          `[${mode.label}] Expected structured JSON error for vfs cat missing --json, got stdout=${JSON.stringify(catRes.stdout)} stderr=${JSON.stringify(catRes.stderr)}`
        );
        assert.ok(
          /ENOENT|not found|no such|missing|error/i.test(JSON.stringify(catErr)),
          `[${mode.label}] Expected ENOENT/not-found detail in vfs cat JSON error, got: ${JSON.stringify(catErr)}`
        );
      }

      // Server remains healthy and subsequent remote status exits 0
      const health = await srv.api.get('/api/health', { expectOk: true });
      assert.equal(health.status, 200);
      assert.equal(health.json?.ok, true);

      const statusRes = await srv.runCli(['status'], { json: true, expectZero: true });
      assert.equal(statusRes.code, 0);
    } finally {
      if (srv) await srv.stop().catch(() => {});
      if (tmp) await tmp.cleanup().catch(() => {});
    }
  });

  it('T2-FA15-04 [F-066]: Multi-Syntax Shell syntax errors, unknown commands & bad pipes/files return non-zero + stderr without crashing OmniOS', async () => {
    let srv = null;
    try {
      srv = await startOmniServer();
      const nonce = makeNonce();

      const badCommands = [
        `nonexistent_cmd_${nonce} foo`,
        `echo "unclosed_${nonce}`,
        'echo hi |',
        '| grep x',
        'echo hi >',
        `echo hi | nonexistent_pipe_cmd_${nonce}`,
        `cat /does/not/exist/${nonce}.txt`,
        `type C:\\Users\\user\\Documents\\missing_${nonce}.txt`,
      ];

      for (const command of badCommands) {
        const res = await srv.api.post('/api/v1/shell/exec', { command });
        assert.ok(res.status < 500, `Shell command ${JSON.stringify(command)} triggered HTTP ${res.status} server error!`);

        if (res.status >= 400 && res.status < 500) {
          assert.ok(res.text.trim().length > 0, `Expected error details on HTTP ${res.status} for ${JSON.stringify(command)}`);
        } else {
          assert.equal(res.status, 200, `Expected HTTP 200 or 4xx for ${JSON.stringify(command)}, got ${res.status}`);
          const exitCode = Number(res.json?.exitCode ?? res.json?.code ?? 0);
          const errText = String(res.json?.stderr ?? res.json?.error ?? res.json?.message ?? '').trim();
          assert.notEqual(
            exitCode,
            0,
            `Shell command ${JSON.stringify(command)} returned exitCode=0; expected non-zero! payload=${res.text}`
          );
          assert.ok(
            errText.length > 0,
            `Shell command ${JSON.stringify(command)} returned empty stderr/error; payload=${res.text}`
          );
        }
      }

      // Also verify remote CLI `exec` fails cleanly on unknown command
      const cliExec = await srv.runCli(['exec', `nonexistent_cli_cmd_${nonce}`], { json: true });
      const cliFailed = cliExec.code !== 0 || (cliExec.json && Number(cliExec.json.exitCode ?? 0) !== 0);
      assert.ok(
        cliFailed,
        `Expected remote CLI exec on nonexistent command to report non-zero failure, got code=${cliExec.code} stdout=${cliExec.stdout}`
      );

      // Verify shell & server recover completely for subsequent valid command
      const okRes = await srv.api.post('/api/v1/shell/exec', { command: `echo SHELL_RECOVERED_${nonce}` }, { expectOk: true });
      const okExit = Number(okRes.json?.exitCode ?? okRes.json?.code ?? 0);
      assert.equal(okExit, 0, `Expected recovery echo exitCode 0, got ${okRes.text}`);
      const okOut = String(okRes.json?.stdout ?? okRes.json?.output ?? okRes.text);
      assert.ok(okOut.includes(`SHELL_RECOVERED_${nonce}`), `Expected SHELL_RECOVERED_${nonce}, got: ${okOut}`);
    } finally {
      if (srv) await srv.stop().catch(() => {});
    }
  });

  it('T2-FA15-05 [F-065/F-034]: Launching, stopping & uninstalling nonexistent appId via CLI ospm & HTTP REST fails cleanly', async () => {
    let srv = null;
    try {
      srv = await startOmniServer();
      const nonce = makeNonce();
      const fakeAppId = `com.omnios.nonexistent.${nonce}`;

      // REST checks
      const launchRes = await srv.api.post(`/api/v1/packages/${encodeURIComponent(fakeAppId)}/launch`, {});
      assert.ok(
        launchRes.status >= 400 && launchRes.status < 500,
        `Expected HTTP 4xx launching nonexistent ${fakeAppId}, got ${launchRes.status}: ${launchRes.text}`
      );

      const delRes = await srv.api.delete(`/api/v1/packages/${encodeURIComponent(fakeAppId)}`);
      assert.ok(
        delRes.status >= 400 && delRes.status < 500,
        `Expected HTTP 4xx deleting nonexistent ${fakeAppId}, got ${delRes.status}: ${delRes.text}`
      );

      const stopRes = await srv.api.post(`/api/v1/packages/${encodeURIComponent(fakeAppId)}/stop`, {});
      assert.ok(stopRes.status < 500, `Stopping nonexistent ${fakeAppId} caused HTTP ${stopRes.status}`);
      assert.ok(
        !stopRes.ok || stopRes.json?.ok === false,
        `Expected stop on nonexistent ${fakeAppId} to fail cleanly, got ${stopRes.status}: ${stopRes.text}`
      );

      // Remote CLI ospm checks
      for (const args of [
        ['ospm', 'launch', fakeAppId],
        ['ospm', 'uninstall', fakeAppId],
        ['ospm', 'inspect', `/nonexistent/path/fake-${nonce}.apk`],
      ]) {
        const res = await srv.runCli(args, { json: true });
        assert.notEqual(res.code, 0, `Remote CLI "${args.join(' ')}" must exit non-zero, got code=0 stdout=${res.stdout}`);
        assert.ok((res.stderr + res.stdout).trim().length > 0);
      }

      // Healthy ospm list & /api/health confirm system integrity
      const health = await srv.api.get('/api/health', { expectOk: true });
      assert.equal(health.status, 200);
      assert.equal(health.json?.ok, true);

      const listCli = await srv.runCli(['ospm', 'list'], { json: true, expectZero: true });
      assert.equal(listCli.code, 0);
    } finally {
      if (srv) await srv.stop().catch(() => {});
    }
  });

  it('T2-FA15-06 [F-067–F-072]: Malformed input events dispatched to a dynamically discovered running system app window do not crash process or compositor', async () => {
    let srv = null;
    let launchedAppId = null;
    try {
      srv = await startOmniServer();
      const nonce = makeNonce();

      // Dynamically discover a built-in system app (zero hardcoded identifiers)
      const { appId } = await discoverBuiltInApp(srv.api, [
        /omninotes|notes/i,
        /omnifiles|files/i,
        /omniterm|terminal/i,
        /settings|privacy/i,
      ]);
      launchedAppId = appId;

      const launchRes = await srv.api.post(`/api/v1/packages/${encodeURIComponent(appId)}/launch`, {}, { expectOk: true });
      const pid = launchRes.json?.pid ?? launchRes.json?.process?.pid;
      assert.ok(Number.isInteger(pid) && pid > 1, `Expected valid PID > 1 launching ${appId}, got: ${launchRes.text}`);

      const win = await waitUntil(async () => {
        const snapRes = await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true });
        const wins = asArray(snapRes.json?.windows ?? snapRes.json?.snapshot?.windows ?? snapRes.json);
        return wins.find((w) => w.pid === pid || w.appId === appId) ?? null;
      }, { timeoutMs: 6000, label: `window for ${appId} (pid=${pid})` });
      const winId = win.windowId ?? win.id;
      assert.ok(winId, `Expected non-empty windowId in snapshot entry: ${JSON.stringify(win)}`);

      // Dispatch 7 malformed / adversarial input events including __proto__ pollution probe
      const malformedInputs = [
        {},
        { type: 'bogus_op_xyz', nodeId: 'no-node' },
        { type: 'click', nodeId: `missing_${nonce}` },
        { type: 'input', nodeId: 'missing', value: null },
        { type: 'keydown', key: 12345, modifiers: 'bad' },
        { type: 'pointerdown', x: -99999, y: null },
        JSON.parse('{"type":"action","nodeId":"__proto__","__proto__":{"polluted":true}}'),
      ];

      for (const ev of malformedInputs) {
        const res = await srv.api.post(`/api/v1/compositor/windows/${encodeURIComponent(winId)}/input`, ev);
        assert.ok(
          res.status < 500,
          `Malformed input ${JSON.stringify(ev)} crashed compositor/app with HTTP ${res.status}: ${res.text}`
        );
      }

      // Owning process MUST STILL be alive (truthy non-terminated state)
      const procRes = await srv.api.get(`/api/v1/processes/${pid}`, { expectOk: true });
      const state = extractProcState(procRes.json);
      assert.ok(
        typeof state === 'string' && state.length > 0 && state !== 'TERMINATED' && state !== 'ZOMBIE',
        `Expected live non-terminated process state for ${appId} (PID ${pid}), got state=${JSON.stringify(state)} body=${procRes.text}`
      );

      // Window MUST still exist in compositor snapshot
      const afterSnap = await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true });
      const afterWins = asArray(afterSnap.json?.windows ?? afterSnap.json?.snapshot?.windows ?? afterSnap.json);
      assert.ok(
        afterWins.some((w) => (w.windowId ?? w.id) === winId),
        `Window ${winId} vanished unexpectedly after malformed input events`
      );

      // Input dispatched to nonexistent windowId MUST return 4xx (never 500)
      const ghostInputRes = await srv.api.post(`/api/v1/compositor/windows/win-missing-${nonce}/input`, {
        type: 'click',
        nodeId: 'btn',
      });
      assert.ok(
        ghostInputRes.status >= 400 && ghostInputRes.status < 500,
        `Expected HTTP 4xx dispatching input to nonexistent window, got ${ghostInputRes.status}: ${ghostInputRes.text}`
      );
    } finally {
      if (srv && launchedAppId) {
        await srv.api.post(`/api/v1/packages/${encodeURIComponent(launchedAppId)}/stop`, {}).catch(() => {});
      }
      if (srv) await srv.stop().catch(() => {});
    }
  });

  it('T2-FA15-07 [F-065/F-009]: CLI boundary protections (killing protected PID 1, invalid Registry hive, removing nonexistent VFS path)', async () => {
    let srv = null;
    try {
      srv = await startOmniServer();
      const nonce = makeNonce();

      // 1. Attempting to SIGKILL protected init process PID 1 MUST fail non-zero and keep PID 1 alive
      const killInit = await srv.runCli(['kill', '1', '--signal', 'SIGKILL'], { json: true });
      assert.notEqual(
        killInit.code,
        0,
        `CLI kill 1 --signal SIGKILL must refuse to terminate protected PID 1, got code=0 stdout=${killInit.stdout}`
      );

      const procsRes = await srv.api.get('/api/v1/processes', { expectOk: true });
      const procs = asArray(procsRes.json, ['processes', 'items', 'data']);
      const pid1 = procs.find((p) => Number(p?.pid) === 1);
      assert.ok(pid1, `Expected PID 1 to remain present in /api/v1/processes, got: ${procsRes.text}`);
      const pid1State = extractProcState(pid1);
      assert.ok(
        typeof pid1State === 'string' && pid1State !== 'TERMINATED' && pid1State !== 'ZOMBIE',
        `PID 1 must stay alive after kill 1 attempt, got state=${JSON.stringify(pid1State)}`
      );

      // 2. Invalid Registry hive
      const badHive = await srv.runCli(['reg', 'get', 'HKINVALID', 'Software\\Bad', 'Key'], { json: true });
      assert.notEqual(badHive.code, 0, `Expected non-zero exit for invalid registry hive HKINVALID, got code=0`);

      // 3. Removing nonexistent VFS path
      const rmMissing = await srv.runCli(['vfs', 'rm', `/does/not/exist/${nonce}`], { json: true });
      assert.notEqual(rmMissing.code, 0, `Expected non-zero exit for vfs rm on missing path, got code=0`);

      const health = await srv.api.get('/api/health', { expectOk: true });
      assert.equal(health.status, 200);
      assert.equal(health.json?.ok, true);
    } finally {
      if (srv) await srv.stop().catch(() => {});
    }
  });
});
