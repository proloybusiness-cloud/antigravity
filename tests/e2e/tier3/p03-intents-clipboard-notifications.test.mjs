/**
 * OmniOS Tier 3 Pairwise E2E Suite — P-03:
 * Universal Intent Router (Android Intent -> iOS URL Scheme, macOS DocumentTypes +
 * Universal fileTypes Share Sheet CHOOSER_REQUIRED) × Multi-MIME Shared Clipboard
 * × Notification Center, Dynamic Island Live Activities, DND & IPC/SHM.
 *
 * Feature Pairs Exercised:
 *   F-022, F-023, F-024, F-025, F-026, F-039, F-040, F-050, F-053, F-054, F-055, F-056, F-062, F-063, F-065
 *
 * STRICT INVARIANTS:
 * - Opaque-box only: imports ONLY Node 24 built-ins and ../lib/*.mjs.
 * - Zero skips, zero stubs, zero hardcoded system app IDs or capability names.
 * - Zero assertions inside try/catch blocks.
 * - Clean try/finally teardown on every test.
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { loadPublicOmniOS, startOmniServer } from '../lib/env.mjs';
import { buildCustomApk } from '../lib/fixtures-android-win.mjs';
import {
  buildCustomIpa,
  buildCustomMacAppZip,
  buildCustomUapp,
} from '../lib/fixtures-apple-wasm.mjs';

// Genuine valid 1x1 transparent PNG image (base64)
const PNG_1X1_B64 =
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
const PNG_1X1_BYTES = Buffer.from(PNG_1X1_B64, 'base64');

function hasPngPayload(rawText, obj) {
  if (typeof rawText === 'string' && rawText.includes(PNG_1X1_B64)) return true;
  if (!obj || typeof obj !== 'object') return false;
  const candidates = [obj.data, obj.image, obj.bytes, obj.buffer, obj.binary, obj.payload, obj.text];
  for (const c of candidates) {
    if (typeof c === 'string') {
      if (c.includes(PNG_1X1_B64)) return true;
      const stripped = c.replace(/^data:image\/png;base64,/i, '').trim();
      if (stripped.length >= 16) {
        const decoded = Buffer.from(stripped, 'base64');
        if (decoded.equals(PNG_1X1_BYTES)) return true;
      }
    } else {
      const byteArr = Array.isArray(c) ? c : (c && c.type === 'Buffer' && Array.isArray(c.data) ? c.data : null);
      if (byteArr && Buffer.from(byteArr).equals(PNG_1X1_BYTES)) return true;
    }
  }
  return false;
}

function makeNonce() {
  return crypto.randomBytes(4).toString('hex');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitUntil(fn, { timeoutMs = 8000, intervalMs = 50, label = 'condition' } = {}) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() < deadline) {
    let val = null;
    try {
      val = await fn();
    } catch (err) {
      lastError = err;
    }
    if (val) return val;
    const rem = deadline - Date.now();
    if (rem > 0) await sleep(Math.min(intervalMs, rem));
  }
  throw new Error(
    `Timed out after ${timeoutMs}ms waiting for ${label}` +
    (lastError ? ` (last error: ${lastError.message})` : '')
  );
}

function unwrapExplicitArray(payload, keys = ['notifications', 'items', 'candidates', 'handlers', 'history', 'data', 'list', 'results']) {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== 'object') return null;
  for (const key of keys) {
    if (Array.isArray(payload[key])) return payload[key];
  }
  if (payload.data && typeof payload.data === 'object') {
    for (const key of keys) {
      if (Array.isArray(payload.data[key])) return payload.data[key];
    }
  }
  return null;
}

function unwrapObject(payload, keys = ['notification', 'clipboard', 'result', 'data']) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return payload;
  for (const key of keys) {
    if (payload[key] && typeof payload[key] === 'object' && !Array.isArray(payload[key])) {
      return payload[key];
    }
  }
  return payload;
}

function extractHandlerId(entry) {
  if (typeof entry === 'string') return entry;
  return entry?.appId ?? entry?.id ?? entry?.packageName ?? entry?.bundleId ?? null;
}

async function registerIntentHandler(router, appId, spec) {
  let arrayOk = false;
  let arrayErr = null;
  try {
    await router.registerHandlers(appId, [spec]);
    arrayOk = true;
  } catch (err) {
    arrayErr = err;
  }

  if (arrayErr && !(arrayErr instanceof TypeError || /object|array|handler|iterable|invalid/i.test(String(arrayErr?.message ?? '')))) {
    throw arrayErr;
  }

  if (arrayOk) {
    const probeQuery = {};
    if (spec.actions?.[0]) probeQuery.action = spec.actions[0];
    else if (spec.action) probeQuery.action = spec.action;
    if (spec.schemes?.[0]) probeQuery.scheme = spec.schemes[0];
    else if (spec.scheme) probeQuery.scheme = spec.scheme;
    if (spec.mimeTypes?.[0]) probeQuery.mimeType = spec.mimeTypes[0];
    else if (spec.mimeType) probeQuery.mimeType = spec.mimeType;
    if (spec.extensions?.[0]) probeQuery.extension = spec.extensions[0];
    else if (spec.extension) probeQuery.extension = spec.extension;
    const resolved = await router.resolve(probeQuery);
    if (Array.isArray(resolved) && resolved.some((h) => extractHandlerId(h) === appId)) {
      return;
    }
  }

  await router.registerHandlers(appId, spec);
}

function extractAppId(rec, fallback = null) {
  return rec?.appId ?? rec?.id ?? rec?.packageName ?? rec?.bundleId ?? rec?.package?.appId ?? rec?.data?.appId ?? fallback;
}

async function installPackageHttp(api, bytes, filename) {
  const buf = bytes instanceof Uint8Array ? bytes : Buffer.from(String(bytes), 'utf8');
  let res = await api.post('/api/v1/packages/install', buf, {
    query: { filename, grantAll: 'true' },
    headers: { 'content-type': 'application/octet-stream', 'x-filename': filename },
  });
  if (!res.ok) {
    const b64 = Buffer.from(buf).toString('base64');
    res = await api.post('/api/v1/packages/install', {
      filename,
      grantAll: true,
      base64: b64,
      data: b64,
      buffer: b64,
    });
  }
  return res;
}

async function restMutate(api, urlPath, body, opts = {}) {
  let res = await api.put(urlPath, body, opts);
  if (res.status === 404 || res.status === 405) {
    res = await api.post(urlPath, body, opts);
  }
  if (res.status === 404 || res.status === 405) {
    res = await api.patch(urlPath, body, opts);
  }
  return res;
}

async function setSystemConfigHttp(api, key, value) {
  const fullKey = key.startsWith('system.') ? key : `system.${key}`;
  const shortKey = fullKey.replace(/^system\./, '');
  let res = await restMutate(api, '/api/v1/config/system', { key: fullKey, value });
  if (!res.ok) {
    res = await restMutate(api, '/api/v1/config/system', { [fullKey]: value, [shortKey]: value });
  }
  return res;
}

function readSystemDndFromJson(payload) {
  const roots = [payload, payload?.data, payload?.config, payload?.system].filter(
    (obj) => obj && typeof obj === 'object' && !Array.isArray(obj)
  );
  for (const obj of roots) {
    if (typeof obj['system.dnd'] === 'boolean') return obj['system.dnd'];
    if (typeof obj.dnd === 'boolean') return obj.dnd;
  }
  return undefined;
}

async function stepUntilCondition(osHandle, predicate, minTicks = 300) {
  const scheduler = osHandle.require('scheduler');
  const pm = osHandle.require('processManager');
  const limit = Math.max(minTicks, pm.list().length * 25);
  for (let i = 0; i < limit; i++) {
    let ok = false;
    try {
      ok = Boolean(await predicate());
    } catch {
      ok = false;
    }
    if (ok) return true;
    await scheduler.step(2);
  }
  let finalOk = false;
  try {
    finalOk = Boolean(await predicate());
  } catch {
    finalOk = false;
  }
  return finalOk;
}

async function runToCompletion(osHandle, pid, maxTicks = 2500) {
  const scheduler = osHandle.require('scheduler');
  const pm = osHandle.require('processManager');
  const scaled = Math.max(maxTicks, pm.list().length * 50);
  let summary = null;
  if (typeof scheduler.runUntilIdle === 'function') {
    summary = await scheduler.runUntilIdle(pid, scaled);
  } else {
    for (let i = 0; i < Math.ceil(scaled / 25); i++) {
      await scheduler.step(25);
      const cur = pm.get(pid);
      if (!cur || cur.state === 'TERMINATED' || cur.state === 'ZOMBIE') break;
    }
  }
  return { pcb: pm.get(pid), summary };
}

function makeYieldingContext() {
  const ctx = {
    steps: 0,
    disposed: false,
    step(budget) {
      ctx.steps += 1;
      return { status: 'YIELD', instructionsExecuted: Math.max(1, Number(budget) || 1) };
    },
    deliverEvent() {},
    getDebugState() {
      return { arch: 'wasm', pc: ctx.steps, sp: 0, registers: {}, instructionsExecuted: ctx.steps, lastSyscall: null, stackTop: 0 };
    },
    dispose() {
      ctx.disposed = true;
    },
  };
  return ctx;
}

describe('Tier 3 — P-03: Cross-Platform Intents, Share Sheet, Multi-MIME Clipboard, Notifications & IPC/SHM', () => {
  test('T3-P03-01 [F-024, F-039, F-040, F-050, F-053]: Executing Android .apk Firing ACTION_VIEW Intent -> Launches Real Installed iOS .ipa via CFBundleURLTypes + ACTION_SEND Dispatch', async () => {
    const os = await loadPublicOmniOS();
    const trackedPids = [];
    try {
      os.require('scheduler').stop?.();
      const vfs = os.require('vfs');
      const pm = os.require('processManager');
      const pkgManager = os.require('pkgManager');
      const router = os.require('intentRouter');
      const nonce = makeNonce();

      const scheme = `omnip03${nonce}`;
      const iosBundle = `com.p03.ios.${nonce}`;
      const iosMarkerPath = `/var/mobile/Documents/ios-launched-${nonce}.txt`;
      const canonMarkerPath = `/home/user/Documents/ios-launched-${nonce}.txt`;
      const iosMarkerBody = `IOS_FROM_ANDROID_${nonce}`;

      // 1. Install real iOS .ipa declaring CFBundleURLTypes scheme and writing a nonce file on launch
      const iosIpa = buildCustomIpa({
        bundleId: iosBundle,
        displayName: `P03Ios${nonce}`,
        executableName: `P03Ios${nonce}`,
        urlScheme: scheme,
        fileWrite: { path: iosMarkerPath, content: iosMarkerBody },
        exitCode: 0,
      });
      const iosRec = await pkgManager.install(iosIpa, { filename: `p03-ios-${nonce}.ipa`, grantAll: true });
      const iosAppId = extractAppId(iosRec, iosBundle);

      // Verify auto-indexing of CFBundleURLTypes in IntentRouter
      const resolvedScheme = await router.resolve({ scheme });
      assert.ok(Array.isArray(resolvedScheme), 'intentRouter.resolve({ scheme }) must return an array');
      assert.ok(
        resolvedScheme.some((h) => extractHandlerId(h) === iosAppId),
        `iOS CFBundleURLTypes scheme "${scheme}" must auto-index ${iosAppId} (got ${JSON.stringify(resolvedScheme)})`
      );

      // 2. Install & launch real Android .apk firing Activity.startActivity(ACTION_VIEW, omnip03<nonce>://trigger/<nonce>)
      const andPkg = `com.p03.and.${nonce}`;
      const andApk = buildCustomApk({
        packageName: andPkg,
        appLabel: `P03And${nonce}`,
        intentAction: 'android.intent.action.VIEW',
        intentUri: `${scheme}://trigger/${nonce}`,
      });
      const andRec = await pkgManager.install(andApk, { filename: `p03-and-${nonce}.apk`, grantAll: true });
      const andLaunch = await pkgManager.launch(extractAppId(andRec, andPkg), {});
      if (andLaunch?.pid) trackedPids.push(andLaunch.pid);

      // Step scheduler until Android's startActivity launches iOS .ipa and ARM64 Mach-O writes the VFS marker file
      const triggered = await stepUntilCondition(os, async () => {
        const txt = await vfs.readFile(canonMarkerPath, { platform: 'posix', encoding: 'utf8' });
        return txt === iosMarkerBody;
      }, 600);
      assert.equal(triggered, true, `Executing Android .apk ACTION_VIEW must launch iOS .ipa to write ${canonMarkerPath}`);
      assert.equal(
        await vfs.readFile(canonMarkerPath, { platform: 'posix', encoding: 'utf8' }),
        iosMarkerBody,
        'iOS .ipa launched by Android Intent must write exact runtime-nonce content'
      );

      // 3. Cross-platform ACTION_SEND (text/plain) dispatch to a registered Universal target
      const sendAppId = `com.p03.send.${nonce}`;
      await pkgManager.install(
        buildCustomUapp({ appId: sendAppId, name: `SendTgt${nonce}`, message: `SEND_OK_${nonce}\n` }),
        { filename: `p03-send-${nonce}.uapp`, grantAll: true }
      );
      await registerIntentHandler(router, sendAppId, {
        actions: ['android.intent.action.SEND'],
        mimeTypes: ['text/plain'],
        priority: 100,
      });

      const sendRes = await router.dispatch({
        action: 'android.intent.action.SEND',
        mimeType: 'text/plain',
        extras: { text: `SEND_${nonce}` },
        sourcePid: 1,
        preferredAppId: sendAppId,
      });
      assert.equal(sendRes?.status, 'DELIVERED', `ACTION_SEND dispatch must return DELIVERED (got ${JSON.stringify(sendRes)})`);
      assert.equal(sendRes?.targetAppId, sendAppId, 'ACTION_SEND must deliver to targetAppId');
      if (sendRes?.pid) trackedPids.push(sendRes.pid);

      // Record any extra spawned PIDs for clean teardown
      for (const p of pm.list()) {
        if (p?.appId === iosAppId && p.state !== 'TERMINATED' && p.state !== 'ZOMBIE') {
          trackedPids.push(p.pid);
        }
      }
    } finally {
      const pm = os.processManager;
      for (const pid of trackedPids) {
        try {
          const pcb = pm?.get?.(pid);
          if (pcb && pcb.state !== 'TERMINATED' && pcb.state !== 'ZOMBIE') await pm.kill(pid, 'SIGKILL');
        } catch {
          // ignore
        }
      }
      await os.shutdown();
    }
  });

  test('T3-P03-02 [F-024, F-054, F-055, F-056, F-062, F-063]: macOS CFBundleDocumentTypes x Universal .uapp fileTypes x Multi-Handler Share Sheet (CHOOSER_REQUIRED + WS intent:chooser)', async () => {
    const srv = await startOmniServer();
    let ws = null;
    try {
      ws = await srv.connectWs();
      const nonce = makeNonce();
      const ext = `ox${nonce.slice(0, 6)}`;
      const macId = `com.p03.macdoc.${nonce}`;
      const uappId = `com.p03.uappdoc.${nonce}`;

      // 1. Install macOS .app.zip declaring CFBundleDocumentTypes for ext
      const macZip = buildCustomMacAppZip({
        bundleId: macId,
        appName: `MacDoc${nonce}`,
        executableName: `MacDoc${nonce}`,
        arch: 'universal',
        documentExtensions: [ext],
        message: `MAC_ASSOC_${nonce}\n`,
      });
      const macInst = await installPackageHttp(srv.api, macZip, `p03-mac-${nonce}.app.zip`);
      assert.ok(macInst.ok, `Installing macOS .app.zip must succeed (got ${macInst.status}: ${macInst.text})`);

      // 2. Install Universal .uapp declaring fileTypes for ext
      const uappZip = buildCustomUapp({
        appId: uappId,
        name: `UappDoc${nonce}`,
        fileTypes: [ext, `.${ext}`],
        message: `UAPP_ASSOC_${nonce}\n`,
      });
      const uappInst = await installPackageHttp(srv.api, uappZip, `p03-uapp-${nonce}.uapp`);
      assert.ok(uappInst.ok, `Installing Universal .uapp must succeed (got ${uappInst.status}: ${uappInst.text})`);

      // 3. Resolve via REST /api/v1/ipc/intents/resolve (POST -> GET fallback on 404/405)
      const resolveQuery = { extension: ext, uri: `file:///home/user/Documents/doc.${ext}` };
      let resolveRes = await srv.api.post('/api/v1/ipc/intents/resolve', resolveQuery);
      if (resolveRes.status === 404 || resolveRes.status === 405) {
        resolveRes = await srv.api.get('/api/v1/ipc/intents/resolve', { query: resolveQuery });
      }
      assert.equal(resolveRes.status, 200, `Intent resolve must return 200 (got ${resolveRes.status}: ${resolveRes.text})`);
      const handlers = unwrapExplicitArray(resolveRes.json, ['handlers', 'candidates', 'items', 'data', 'results']);
      assert.ok(Array.isArray(handlers), `Intent resolve must return explicit array (got ${resolveRes.text})`);
      const resolvedIds = handlers.map(extractHandlerId);
      assert.ok(resolvedIds.includes(macId), `Resolved handlers must include macOS app ${macId} (got ${JSON.stringify(resolvedIds)})`);
      assert.ok(resolvedIds.includes(uappId), `Resolved handlers must include Universal app ${uappId} (got ${JSON.stringify(resolvedIds)})`);

      // 4. Ambiguous dispatch MUST trigger CHOOSER_REQUIRED + WS intent:chooser broadcast
      const cursor = ws.mark();
      const dispatchPayload = {
        action: 'android.intent.action.VIEW',
        extension: ext,
        uri: `file:///home/user/Documents/doc.${ext}`,
      };
      const dispRes = await srv.api.post('/api/v1/ipc/intents/dispatch', dispatchPayload, { expectOk: true });
      const dispBody = unwrapObject(dispRes.json, ['result', 'data']);
      assert.equal(
        dispBody?.status,
        'CHOOSER_REQUIRED',
        `Ambiguous multi-platform file extension must return CHOOSER_REQUIRED (got ${dispRes.text})`
      );
      const candidates = unwrapExplicitArray(dispBody?.candidates ?? dispBody, ['candidates', 'handlers', 'items']);
      assert.ok(Array.isArray(candidates) && candidates.length >= 2, `CHOOSER_REQUIRED must include >=2 candidates (got ${dispRes.text})`);
      const candIds = candidates.map(extractHandlerId);
      assert.ok(candIds.includes(macId) && candIds.includes(uappId), `Candidates must include both ${macId} and ${uappId}`);

      const wsChooser = await ws.waitForMessage(
        (m) => m?.type === 'intent:chooser' && JSON.stringify(m).includes(macId) && JSON.stringify(m).includes(uappId),
        { since: cursor, timeoutMs: 5000 }
      );
      assert.equal(wsChooser?.type, 'intent:chooser', 'WS must push intent:chooser referencing both platform candidates');

      // 5. Disambiguate with preferredAppId -> DELIVERED to macOS handler
      const chosenRes = await srv.api.post('/api/v1/ipc/intents/dispatch', {
        ...dispatchPayload,
        preferredAppId: macId,
      }, { expectOk: true });
      const chosenBody = unwrapObject(chosenRes.json, ['result', 'data']);
      assert.equal(chosenBody?.status, 'DELIVERED', `Disambiguated dispatch must return DELIVERED (got ${chosenRes.text})`);
      assert.equal(chosenBody?.targetAppId, macId, `Disambiguated dispatch must target ${macId}`);
    } finally {
      await ws?.close();
      await srv.stop();
    }
  });

  test('T3-P03-03 [F-024, F-026, F-053, F-062, F-063]: iOS URL Scheme (omniweather://) x Notification Center + Dynamic Island Live Activity x Action & Dismiss Lifecycle', async () => {
    const nonce = makeNonce();
    let os = null;
    let srv = null;
    let ws = null;
    try {
      // Part A: Programmatic iOS omniweather:// scheme + Dynamic Island liveActivity lifecycle
      os = await loadPublicOmniOS();
      os.require('scheduler').stop?.();
      const vfs = os.require('vfs');
      const pkgManager = os.require('pkgManager');
      const router = os.require('intentRouter');
      const notifications = os.require('notifications');

      const weatherBundle = `com.p03.weather.${nonce}`;
      const weatherFile = `/var/mobile/Documents/weather-${nonce}.txt`;
      const weatherCanon = `/home/user/Documents/weather-${nonce}.txt`;
      const weatherBody = `WEATHER_${nonce}`;

      const weatherIpa = buildCustomIpa({
        bundleId: weatherBundle,
        displayName: `OmniWeather${nonce}`,
        executableName: `OmniWeather${nonce}`,
        urlScheme: 'omniweather',
        fileWrite: { path: weatherFile, content: weatherBody },
        exitCode: 0,
      });
      const rec = await pkgManager.install(weatherIpa, { filename: `p03-weather-${nonce}.ipa`, grantAll: true });
      const weatherAppId = extractAppId(rec, weatherBundle);

      const resolved = await router.resolve({ scheme: 'omniweather' });
      assert.ok(
        Array.isArray(resolved) && resolved.some((h) => extractHandlerId(h) === weatherAppId),
        `omniweather:// scheme must resolve to ${weatherAppId}`
      );

      const disp = await router.dispatch({
        uri: `omniweather://city/${nonce}`,
        scheme: 'omniweather',
        sourcePid: 1,
        preferredAppId: weatherAppId,
      });
      assert.equal(disp?.status, 'DELIVERED', `omniweather:// dispatch must deliver (got ${JSON.stringify(disp)})`);
      assert.equal(disp?.targetAppId, weatherAppId);
      if (disp?.pid) {
        await runToCompletion(os, disp.pid, 2500);
      }
      assert.equal(await vfs.readFile(weatherCanon, { platform: 'posix', encoding: 'utf8' }), weatherBody);

      const laId = `la-${nonce}`;
      const posted = await notifications.post({
        appId: weatherAppId,
        platform: 'ios',
        title: `Weather ${nonce}`,
        body: `72F Clear ${nonce}`,
        priority: 'high',
        category: 'weather',
        actions: [{ id: 'refresh', label: 'Refresh' }],
        liveActivity: { id: laId, title: `Weather ${nonce}`, status: 'Sunny 72F', progress: 0.7 },
      });
      const notifId = posted?.id ?? posted?.notificationId;
      assert.ok(notifId, `notifications.post() must return notification ID (got ${JSON.stringify(posted)})`);

      const liveActs = await notifications.getLiveActivities();
      assert.ok(
        Array.isArray(liveActs) && JSON.stringify(liveActs).includes(laId),
        `getLiveActivities() must expose Dynamic Island payload "${laId}" (got ${JSON.stringify(liveActs)})`
      );

      const actRes = await notifications.invokeAction(notifId, 'refresh');
      assert.ok(actRes !== false, 'invokeAction("refresh") must succeed');

      await notifications.dismiss(notifId);
      const activeList = await notifications.list({ includeDismissed: false });
      const allList = await notifications.list({ includeDismissed: true });
      assert.equal(activeList.some((n) => (n?.id ?? n?.notificationId) === notifId), false, 'Dismissed notification must be absent from active list');
      assert.equal(allList.some((n) => (n?.id ?? n?.notificationId) === notifId), true, 'Dismissed notification must appear when includeDismissed=true');

      await os.shutdown();
      os = null;

      // Part B: Live HTTP REST + WS + Remote CLI Dynamic Island Notification lifecycle
      srv = await startOmniServer();
      ws = await srv.connectWs();
      const cursor = ws.mark();
      const srvLaId = `la-srv-${nonce}`;
      const postRes = await srv.api.post('/api/v1/ipc/notifications', {
        appId: weatherBundle,
        platform: 'ios',
        title: `LiveIsland ${nonce}`,
        body: `Forecast ${nonce}`,
        priority: 'high',
        actions: [{ id: 'refresh', label: 'Refresh' }],
        liveActivity: { id: srvLaId, title: `LiveIsland ${nonce}`, status: 'Active', progress: 0.5 },
      }, { expectOk: true });
      const srvNotif = unwrapObject(postRes.json, ['notification', 'data']);
      const srvNotifId = srvNotif?.id ?? srvNotif?.notificationId;
      assert.ok(srvNotifId, `POST /api/v1/ipc/notifications must return notification id (got ${postRes.text})`);

      const wsNotif = await ws.waitForMessage(
        (m) => m?.type === 'notification:posted' && JSON.stringify(m).includes(srvLaId),
        { since: cursor, timeoutMs: 5000 }
      );
      assert.equal(wsNotif?.type, 'notification:posted', 'WS notification:posted must carry liveActivity payload');

      const restAct = await srv.api.post(`/api/v1/ipc/notifications/${encodeURIComponent(srvNotifId)}/action`, { actionId: 'refresh' });
      assert.ok(restAct.ok, `POST /api/v1/ipc/notifications/:id/action must succeed (got ${restAct.status}: ${restAct.text})`);

      const cliListBefore = await srv.runCli(['notify', 'list'], { json: true, expectZero: true });
      assert.ok(cliListBefore.stdout.includes(`LiveIsland ${nonce}`), `Remote CLI notify list must show active notification (got ${cliListBefore.stdout})`);

      const restDismiss = await srv.api.post(`/api/v1/ipc/notifications/${encodeURIComponent(srvNotifId)}/dismiss`, {});
      assert.ok(restDismiss.ok, `POST /api/v1/ipc/notifications/:id/dismiss must succeed (got ${restDismiss.status}: ${restDismiss.text})`);

      const listAfterRes = await srv.api.get('/api/v1/ipc/notifications', { expectOk: true });
      const listAfter = unwrapExplicitArray(listAfterRes.json, ['notifications', 'items', 'data']);
      assert.ok(Array.isArray(listAfter), 'GET /api/v1/ipc/notifications must return explicit array');
      assert.equal(
        listAfter.some((n) => (n?.id ?? n?.notificationId) === srvNotifId && !n?.dismissed),
        false,
        'Dismissed notification must be excluded from active REST list'
      );
    } finally {
      await ws?.close();
      await srv?.stop();
      await os?.shutdown();
    }
  });

  test('T3-P03-04 [F-025, F-062, F-065]: Multi-MIME Shared Clipboard Across 4 Platforms (text/plain, text/html, application/json, image/png) x 20-Entry Bounded FIFO History x REST & Remote CLI Sync', async () => {
    const nonce = makeNonce();
    let srv = null;
    let os = null;
    try {
      // Part A: Live Server REST + Remote CLI Multi-MIME across all 4 platforms
      srv = await startOmniServer();

      const expectedHtml = `<b>MAC_HTML_${nonce}</b>`;
      const mimeSamples = [
        { mime: 'text/plain', text: `WIN_PLAIN_${nonce}`, sourceAppId: 'win.clipboard.app' },
        { mime: 'text/html', text: `MAC_HTML_${nonce}`, html: expectedHtml, sourceAppId: 'mac.clipboard.app' },
        { mime: 'application/json', text: `ANDROID_JSON_SUMMARY_${nonce}`, json: { nonce, plat: 'android', kind: 'json-payload' }, sourceAppId: 'and.clipboard.app' },
        { mime: 'image/png', text: PNG_1X1_B64, data: PNG_1X1_B64, image: PNG_1X1_B64, sourceAppId: 'ios.clipboard.app' },
      ];

      for (const sample of mimeSamples) {
        const setRes = await restMutate(srv.api, '/api/v1/ipc/clipboard', sample);
        assert.ok(setRes.ok, `Setting clipboard (${sample.mime}) via REST must succeed (got ${setRes.status}: ${setRes.text})`);

        const getRes = await srv.api.get('/api/v1/ipc/clipboard', { expectOk: true });
        const cur = unwrapObject(getRes.json, ['clipboard', 'current', 'data']);
        const actualMime = cur?.mime ?? cur?.mimeType ?? cur?.contentType;
        assert.equal(
          actualMime,
          sample.mime,
          `Clipboard MIME must explicitly equal ${sample.mime} (got ${JSON.stringify(actualMime)} in ${getRes.text})`
        );

        if (sample.mime === 'text/plain') {
          assert.ok(
            String(cur?.text ?? '').includes(`WIN_PLAIN_${nonce}`),
            `text/plain clipboard entry must preserve text payload (got ${getRes.text})`
          );
        } else if (sample.mime === 'text/html') {
          const htmlField = typeof cur?.html === 'string' ? cur.html : (typeof cur?.data === 'string' ? cur.data : '');
          assert.ok(
            htmlField.includes(expectedHtml),
            `text/html clipboard entry must preserve HTML markup "${expectedHtml}" (got ${getRes.text})`
          );
        } else if (sample.mime === 'application/json') {
          let parsedJson = cur?.json ?? cur?.data ?? null;
          if (typeof parsedJson === 'string') {
            try {
              parsedJson = JSON.parse(parsedJson);
            } catch {
              parsedJson = null;
            }
          }
          assert.equal(parsedJson?.nonce, nonce, `application/json clipboard entry must preserve json.nonce (got ${getRes.text})`);
          assert.equal(parsedJson?.plat, 'android', `application/json clipboard entry must preserve json.plat (got ${getRes.text})`);
          assert.equal(parsedJson?.kind, 'json-payload', `application/json clipboard entry must preserve json.kind (got ${getRes.text})`);
        } else if (sample.mime === 'image/png') {
          assert.equal(
            hasPngPayload(getRes.text, cur),
            true,
            `image/png clipboard entry must preserve PNG_1X1_B64 or decoded PNG bytes (got ${getRes.text})`
          );
        }

        const cliGet = await srv.runCli(['clipboard', 'get'], { json: true, expectZero: true });
        const cliCur = unwrapObject(cliGet.json, ['clipboard', 'current', 'data']);
        if (sample.mime === 'image/png') {
          assert.equal(
            hasPngPayload(cliGet.stdout, cliCur),
            true,
            `Remote CLI clipboard get must mirror image/png payload (got ${cliGet.stdout})`
          );
        } else if (sample.mime === 'text/html') {
          assert.ok(
            String(cliCur?.html ?? '').includes(expectedHtml) || cliGet.stdout.includes(expectedHtml),
            `Remote CLI clipboard get must mirror text/html markup "${expectedHtml}" (got ${cliGet.stdout})`
          );
        } else if (sample.mime === 'application/json') {
          assert.ok(
            cliGet.stdout.includes(nonce) && cliGet.stdout.includes('json-payload'),
            `Remote CLI clipboard get must mirror application/json payload (got ${cliGet.stdout})`
          );
        } else {
          assert.ok(
            cliGet.stdout.includes(`WIN_PLAIN_${nonce}`),
            `Remote CLI clipboard get must mirror text/plain payload (got ${cliGet.stdout})`
          );
        }
      }

      // Remote CLI write -> REST immediately sees it
      const cliText = `CLI_CLIP_${nonce}`;
      await srv.runCli(['clipboard', 'set', cliText], { json: true, expectZero: true });
      const afterCliRes = await srv.api.get('/api/v1/ipc/clipboard', { expectOk: true });
      assert.ok(afterCliRes.text.includes(cliText), `REST clipboard must immediately reflect CLI set "${cliText}"`);

      await srv.stop();
      srv = null;

      // Part B: Programmatic 20-entry bounded FIFO history rotating across all 4 platforms
      os = await loadPublicOmniOS();
      const clipboard = os.require('clipboard');
      const sources = ['win.app', 'mac.app', 'and.app', 'ios.app'];

      for (let i = 0; i < 24; i++) {
        const tag = String(i).padStart(2, '0');
        await clipboard.set({
          text: `xplat-${tag}-${nonce}`,
          mime: 'text/plain',
          sourceAppId: sources[i % sources.length],
        });
      }

      const hist20 = await clipboard.history(20);
      const hist50 = await clipboard.history(50);
      assert.equal(hist20.length, 20, 'history(20) must return exact 20 entries');
      assert.equal(hist50.length, 20, 'history(50) must stay bounded at exact 20 entries');

      const texts = hist50.map((e) => e?.text);
      for (let i = 0; i < 4; i++) {
        assert.equal(texts.includes(`xplat-${String(i).padStart(2, '0')}-${nonce}`), false, `Oldest entry ${i} must be evicted FIFO`);
      }
      for (let i = 4; i < 24; i++) {
        assert.equal(texts.includes(`xplat-${String(i).padStart(2, '0')}-${nonce}`), true, `Entry ${i} must be retained in 20-item FIFO window`);
      }
      const seenSources = new Set(hist50.map((e) => e?.sourceAppId));
      for (const src of sources) {
        assert.equal(seenSources.has(src), true, `Bounded clipboard history must retain entries from all 4 platforms (missing ${src})`);
      }
    } finally {
      await srv?.stop();
      await os?.shutdown();
    }
  });

  test('T3-P03-05 [F-022, F-026, F-040, F-063]: Unified system.dnd Config Sync x Notification Center DND Suppression & Restoration x Android Toast Stability', async () => {
    const srv = await startOmniServer();
    let ws = null;
    try {
      ws = await srv.connectWs();
      const nonce = makeNonce();

      // 1. Baseline DND=false -> normal delivery in REST + WS
      const offRes = await setSystemConfigHttp(srv.api, 'system.dnd', false);
      assert.ok(offRes.ok, `Setting system.dnd=false must succeed (got ${offRes.status})`);

      const c1 = ws.mark();
      const preTitle = `PreDnd-${nonce}`;
      const preRes = await srv.api.post('/api/v1/ipc/notifications', {
        appId: `com.p03.dnd.${nonce}`,
        platform: 'ios',
        title: preTitle,
        body: `pre-${nonce}`,
        priority: 'normal',
      }, { expectOk: true });
      assert.ok(preRes.ok);

      const preListRes = await srv.api.get('/api/v1/ipc/notifications', { expectOk: true });
      const preList = unwrapExplicitArray(preListRes.json, ['notifications', 'items', 'data']);
      assert.ok(Array.isArray(preList) && preList.some((n) => n?.title === preTitle), 'Baseline notification must appear when DND=false');
      await ws.waitForMessage((m) => m?.type === 'notification:posted' && JSON.stringify(m).includes(preTitle), { since: c1, timeoutMs: 5000 });

      // 2. Enable DND=true -> WS config:changed + suppression of low-priority notification
      const cCfgOn = ws.mark();
      const onRes = await setSystemConfigHttp(srv.api, 'system.dnd', true);
      assert.ok(onRes.ok, `Setting system.dnd=true must succeed (got ${onRes.status})`);
      await ws.waitForType('config:changed', { since: cCfgOn, timeoutMs: 5000 });

      const cfgCheck = await srv.api.get('/api/v1/config/system', { expectOk: true });
      assert.equal(readSystemDndFromJson(cfgCheck.json), true, 'Config store must confirm system.dnd === true');

      const c2 = ws.mark();
      const dndTitle = `DuringDnd-${nonce}`;
      const dndRes = await srv.api.post('/api/v1/ipc/notifications', {
        appId: `com.p03.dnd.${nonce}`,
        platform: 'ios',
        title: dndTitle,
        body: `dnd-${nonce}`,
        priority: 'low',
      });
      assert.ok(
        dndRes.status >= 200 && dndRes.status < 300,
        `POST /api/v1/ipc/notifications during DND=true must return 2xx (not HTTP error/crash, got ${dndRes.status}: ${dndRes.text})`
      );
      await sleep(450);

      const dndData = dndRes.json?.data ?? dndRes.json ?? {};
      const markedSuppressed = Boolean(
        dndData?.suppressed === true ||
        dndData?.dndSuppressed === true ||
        dndData?.filtered === true ||
        dndData?.silent === true ||
        dndData?.muted === true ||
        dndData?.delivered === false ||
        dndRes.json?.suppressed === true ||
        dndRes.json?.filtered === true
      );
      const duringListRes = await srv.api.get('/api/v1/ipc/notifications', { expectOk: true });
      const duringList = unwrapExplicitArray(duringListRes.json, ['notifications', 'items', 'data']);
      assert.ok(Array.isArray(duringList));
      const omittedFromActive = !duringList.some((n) => n?.title === dndTitle && !n?.suppressed && !n?.muted && !n?.filtered);
      const wsSuppressed = !ws.getMessages(c2).some((m) => m?.type === 'notification:posted' && JSON.stringify(m).includes(dndTitle));
      assert.ok(
        markedSuppressed || omittedFromActive || wsSuppressed,
        `DND=true must suppress low-priority notification "${dndTitle}" (marked=${markedSuppressed}, omitted=${omittedFromActive}, ws=${wsSuppressed})`
      );

      // 3. Install & launch real Android .apk emitting Toast during DND -> OS stays healthy
      const apkPkg = `com.p03.toast.${nonce}`;
      const apkInst = await installPackageHttp(
        srv.api,
        buildCustomApk({ packageName: apkPkg, appLabel: `Toast${nonce}`, notificationTitle: `AndToast_${nonce}`, notificationBody: nonce }),
        `p03-toast-${nonce}.apk`
      );
      assert.ok(apkInst.ok, `Android Toast APK install must succeed (got ${apkInst.status})`);
      const apkLaunch = await srv.api.post(`/api/v1/packages/${encodeURIComponent(extractAppId(apkInst.json, apkPkg))}/launch`, {});
      assert.ok(apkLaunch.ok, `Android Toast APK launch during DND must succeed (got ${apkLaunch.status})`);
      assert.equal((await srv.api.get('/api/health')).status, 200, 'Kernel health must remain 200 OK during DND + Android Toast');

      // 4. Disable DND=false -> WS config:changed + immediate notification delivery restored
      const cCfgOff = ws.mark();
      const restoreRes = await setSystemConfigHttp(srv.api, 'system.dnd', false);
      assert.ok(restoreRes.ok);
      await ws.waitForType('config:changed', { since: cCfgOff, timeoutMs: 5000 });

      const c3 = ws.mark();
      const postTitle = `AfterDnd-${nonce}`;
      const postRes = await srv.api.post('/api/v1/ipc/notifications', {
        appId: `com.p03.dnd.${nonce}`,
        platform: 'ios',
        title: postTitle,
        body: `post-${nonce}`,
        priority: 'normal',
      }, { expectOk: true });
      assert.ok(postRes.ok);

      const postListRes = await srv.api.get('/api/v1/ipc/notifications', { expectOk: true });
      const postList = unwrapExplicitArray(postListRes.json, ['notifications', 'items', 'data']);
      assert.ok(Array.isArray(postList) && postList.some((n) => n?.title === postTitle), 'Post-DND notification must deliver immediately');
      await ws.waitForMessage((m) => m?.type === 'notification:posted' && JSON.stringify(m).includes(postTitle), { since: c3, timeoutMs: 5000 });
    } finally {
      await ws?.close();
      await srv.stop();
    }
  });

  test('T3-P03-06 [F-023, F-024, F-025, F-026]: Cross-Platform IPC Named Channel + Shared Memory (SHM) Binary Transfer Composed With Clipboard & Notification Delivery', async () => {
    const os = await loadPublicOmniOS();
    const unsubs = [];
    const pids = [];
    try {
      const pm = os.require('processManager');
      const ipc = os.require('ipc');
      const clipboard = os.require('clipboard');
      const notifications = os.require('notifications');
      const nonce = makeNonce();

      const winProc = pm.spawn({
        name: `win-sender-${nonce}`,
        appId: `com.p03.winsend.${nonce}`,
        platform: 'windows',
        arch: 'x86_64',
        uid: 1000,
        gid: 1000,
        cwd: '/home/user',
        executionContext: makeYieldingContext(),
      });
      const macProc = pm.spawn({
        name: `mac-recv-${nonce}`,
        appId: `com.p03.macrecv.${nonce}`,
        platform: 'macos',
        arch: 'arm64',
        uid: 1000,
        gid: 1000,
        cwd: '/home/user',
        executionContext: makeYieldingContext(),
      });
      pids.push(winProc.pid, macProc.pid);

      const chan = `p03.pipe.${nonce}`;
      ipc.createChannel(chan, winProc.pid);

      const createdShm = ipc.shmCreate(`p03-shm-${nonce}`, 4096, winProc.pid);
      const shmId = typeof createdShm === 'object' && createdShm !== null
        ? (createdShm.id ?? createdShm.shmId ?? createdShm.name)
        : createdShm;
      assert.ok(shmId !== null && shmId !== undefined && String(shmId).length > 0, 'shmCreate() must return valid shmId');

      const binaryPayload = crypto.randomBytes(64);
      const expectedHex = binaryPayload.toString('hex');
      if (typeof ipc.shmAttach === 'function') {
        ipc.shmAttach(shmId, winProc.pid);
        ipc.shmAttach(shmId, macProc.pid);
      }
      ipc.shmWrite(shmId, 64, binaryPayload);

      const receivedMsgs = [];
      const unsub = ipc.subscribe(chan, (env) => {
        receivedMsgs.push(env?.payload ?? env);
      });
      if (typeof unsub === 'function') unsubs.push(unsub);

      ipc.send(chan, winProc.pid, { shmId, offset: 64, length: 64, nonce });
      assert.equal(receivedMsgs.length, 1, 'macOS subscriber must receive IPC descriptor message');
      const desc = receivedMsgs[0];
      assert.equal(desc.nonce, nonce);

      const readBack = Buffer.from(ipc.shmRead(desc.shmId, desc.offset, desc.length));
      assert.equal(Buffer.compare(readBack, binaryPayload), 0, 'SHM binary transfer must match byte-for-byte');

      // Publish decoded summary into shared multi-MIME clipboard and post notification
      const summaryJson = { nonce, hex: expectedHex };
      await clipboard.set({
        mime: 'application/json',
        json: summaryJson,
        text: JSON.stringify(summaryJson),
        sourceAppId: macProc.appId,
      });
      const clipCur = await clipboard.get();
      const clipJson = clipCur?.json ?? (typeof clipCur?.text === 'string' && clipCur.text.trim().startsWith('{') ? JSON.parse(clipCur.text) : null);
      assert.equal(clipJson?.nonce, nonce, `Shared clipboard JSON payload must preserve nonce "${nonce}" (got ${JSON.stringify(clipCur)})`);
      assert.equal(clipJson?.hex, expectedHex, `Shared clipboard JSON payload must preserve exact SHM hex digest`);

      const notif = await notifications.post({
        appId: macProc.appId,
        platform: 'macos',
        title: `SHM Done ${nonce}`,
        body: expectedHex.slice(0, 16),
        priority: 'normal',
      });
      const notifId = notif?.id ?? notif?.notificationId;
      assert.ok(notifId, 'Notification post after IPC/SHM transfer must return ID');
      const activeNotifs = await notifications.list({ includeDismissed: false });
      assert.ok(
        activeNotifs.some((n) => (n?.id ?? n?.notificationId) === notifId && n?.title === `SHM Done ${nonce}`),
        'Notification list must contain IPC/SHM completion alert'
      );
    } finally {
      for (const fn of unsubs) fn();
      const pm = os.processManager;
      for (const pid of pids) {
        try {
          const pcb = pm?.get?.(pid);
          if (pcb && pcb.state !== 'TERMINATED' && pcb.state !== 'ZOMBIE') await pm.kill(pid, 'SIGKILL');
        } catch {
          // ignore
        }
      }
      await os.shutdown();
    }
  });
});
