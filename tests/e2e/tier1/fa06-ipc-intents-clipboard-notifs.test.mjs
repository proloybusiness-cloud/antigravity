/**
 * Tier 1 E2E Tests — FA-06: Cross-Platform IPC, Universal Intent Router, Clipboard & Notifications
 * Features covered: F-023, F-024, F-025, F-026
 * Contracts: Contract 4 (IIPCManager, IIntentRouter, IClipboard, INotificationCenter), Contract 7 (REST/WS), Contract 8 (CLI)
 *
 * Strictly opaque-box: interacts ONLY through public OmniOS entrypoints via ../lib/env.mjs.
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  loadPublicOmniOS,
  startOmniServer,
} from '../lib/env.mjs';
import { buildCustomUapp } from '../lib/fixtures-apple-wasm.mjs';

// Genuine valid 1x1 transparent PNG image (base64)
const PNG_1X1_B64 =
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

function makeToken() {
  return crypto.randomBytes(4).toString('hex');
}

function unwrapExplicitArray(payload, keys = ['notifications', 'items', 'candidates', 'handlers', 'history', 'data', 'list']) {
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

function registerIntentHandler(router, appId, spec) {
  let arrayOk = false;
  try {
    router.registerHandlers(appId, [spec]);
    arrayOk = true;
  } catch (err) {
    if (!(err instanceof TypeError || /object|array|handler|iterable|invalid/i.test(String(err?.message ?? '')))) {
      throw err;
    }
  }

  // Verify array registration actually indexed the handler; fall back to singular object shape if not
  if (arrayOk) {
    const probeQuery = {};
    if (spec.actions?.[0]) probeQuery.action = spec.actions[0];
    if (spec.schemes?.[0]) probeQuery.scheme = spec.schemes[0];
    if (spec.mimeTypes?.[0]) probeQuery.mimeType = spec.mimeTypes[0];
    if (spec.extensions?.[0]) probeQuery.extension = spec.extensions[0];
    const resolved = router.resolve(probeQuery);
    if (Array.isArray(resolved) && resolved.some((h) => (h?.appId ?? h?.id ?? h) === appId)) {
      return;
    }
  }
  router.registerHandlers(appId, spec);
}

describe('Tier 1 — FA-06: Cross-Platform IPC, Universal Intent Router, Clipboard & Notifications', () => {
  test('T1 [F-023]: IPC named channels createChannel/send/recv/subscribe and request/reply RPC', async () => {
    const os = await loadPublicOmniOS();
    const unsubs = [];
    try {
      const ipc = os.require('ipc');
      const tok = makeToken();

      // 1. Pub/Sub ordered delivery
      const chanSub = `omni.sub.${tok}`;
      ipc.createChannel(chanSub, 1);
      const received = [];
      const u1 = ipc.subscribe(chanSub, (msg) => {
        received.push(msg?.payload ?? msg);
      });
      if (typeof u1 === 'function') unsubs.push(u1);

      ipc.send(chanSub, 1, { seq: 1, token: tok });
      ipc.send(chanSub, 1, { seq: 2, token: `${tok}_2` });

      assert.equal(received.length, 2, `Expected 2 ordered pub/sub deliveries, got ${received.length}`);
      assert.equal(received[0].seq, 1);
      assert.equal(received[0].token, tok);
      assert.equal(received[1].seq, 2);
      assert.equal(received[1].token, `${tok}_2`);

      // 2. Queued send/recv pull channel
      const chanPull = `omni.pull.${tok}`;
      ipc.createChannel(chanPull, 1);
      ipc.send(chanPull, 1, { pull: tok });
      const pulled = await ipc.recv(chanPull, 1);
      assert.ok(pulled !== null && pulled !== undefined, 'ipc.recv() must return queued message');
      assert.equal((pulled?.payload ?? pulled).pull, tok);

      // 3. Request/Reply RPC round-trip
      const reqChan = `omni.rpc.req.${tok}`;
      const repChan = `omni.rpc.rep.${tok}`;
      ipc.createChannel(reqChan, 1);
      ipc.createChannel(repChan, 1);

      const u2 = ipc.subscribe(reqChan, (envelope) => {
        const body = envelope?.payload ?? envelope;
        ipc.send(body.replyTo, 1, {
          corrId: body.corrId,
          sum: body.a + body.b,
        });
      });
      if (typeof u2 === 'function') unsubs.push(u2);

      const a = 10 + crypto.randomInt(50);
      const b = 10 + crypto.randomInt(50);
      ipc.send(reqChan, 1, { corrId: tok, a, b, replyTo: repChan });

      const replyEnv = await ipc.recv(repChan, 1);
      const reply = replyEnv?.payload ?? replyEnv;
      assert.equal(reply?.corrId, tok, 'RPC reply must preserve correlation ID');
      assert.equal(reply?.sum, a + b, `RPC reply must compute exact sum ${a + b}`);
    } finally {
      for (const fn of unsubs) fn();
      await os.shutdown();
    }
  });

  test('T2 [F-023]: IPC Shared Memory shmCreate/shmWrite/shmRead binary & partial-slice round-trip', async () => {
    const os = await loadPublicOmniOS();
    try {
      const ipc = os.require('ipc');
      const tok = makeToken();
      const payload = crypto.randomBytes(64);
      const patch = crypto.randomBytes(8);

      const created = ipc.shmCreate(`shm-${tok}`, 4096, 1);
      const shmId = typeof created === 'object' && created !== null
        ? (created.id ?? created.shmId ?? created.name)
        : created;
      assert.ok(shmId !== null && shmId !== undefined && String(shmId).length > 0, 'shmCreate() must return a valid SHM ID');

      if (typeof ipc.shmAttach === 'function') {
        ipc.shmAttach(shmId, 1);
      }

      ipc.shmWrite(shmId, 128, payload);
      const fullRead = Buffer.from(ipc.shmRead(shmId, 128, 64));
      assert.equal(Buffer.compare(fullRead, payload), 0, 'shmRead() must return exact written binary payload');

      // Partial slice overwrite at offset +16..+24
      ipc.shmWrite(shmId, 128 + 16, patch);
      const afterPatch = Buffer.from(ipc.shmRead(shmId, 128, 64));
      assert.equal(Buffer.compare(afterPatch.subarray(0, 16), payload.subarray(0, 16)), 0, 'Bytes before patch must remain intact');
      assert.equal(Buffer.compare(afterPatch.subarray(16, 24), patch), 0, 'Patched 8-byte slice must reflect new bytes');
      assert.equal(Buffer.compare(afterPatch.subarray(24, 64), payload.subarray(24, 64)), 0, 'Bytes after patch must remain intact');
    } finally {
      await os.shutdown();
    }
  });

  test('T3 [F-024]: Universal Intent Router ranked resolve() across action/scheme/MIME/extension and single-handler DELIVERED', async () => {
    const os = await loadPublicOmniOS();
    try {
      const router = os.require('intentRouter');
      const pkgManager = os.require('pkgManager');
      const tok = makeToken();

      const appLow = `com.test.low.${tok}`;
      const appHigh = `com.test.high.${tok}`;
      const action = `omni.open.${tok}`;
      const scheme = `om${tok}`;
      const mimeType = `text/x-${tok}`;
      const ext = `x${tok}`;

      registerIntentHandler(router, appLow, {
        platform: 'android',
        priority: 10,
        actions: [action],
        schemes: [scheme],
        mimeTypes: [mimeType],
        extensions: [ext],
      });
      registerIntentHandler(router, appHigh, {
        platform: 'macos',
        priority: 100,
        actions: [action],
        schemes: [scheme],
        mimeTypes: [mimeType],
        extensions: [ext],
      });

      const ranked = router.resolve({
        action,
        scheme,
        mimeType,
        uri: `${scheme}://doc/1`,
      });
      assert.ok(Array.isArray(ranked) && ranked.length >= 2, `Expected >= 2 resolved handlers, got ${JSON.stringify(ranked)}`);
      assert.equal(ranked[0].appId, appHigh, `Higher-priority handler "${appHigh}" must rank first`);
      assert.ok(ranked.some((h) => h.appId === appLow), 'Lower-priority handler must also appear in resolved list');

      // File extension resolution
      const appExt = `com.test.ext.${tok}`;
      registerIntentHandler(router, appExt, {
        platform: 'windows',
        priority: 50,
        extensions: [`ext${tok}`],
      });
      const extMatches = router.resolve({ extension: `ext${tok}` });
      assert.ok(
        Array.isArray(extMatches) && extMatches.some((h) => h.appId === appExt),
        'resolve({ extension }) must match registered file-association handler'
      );

      // Unique single-handler dispatch -> install real minimal .uapp + custom unique action -> DELIVERED
      const appSolo = `com.test.solo.${tok}`;
      const soloAction = `omni.view.${tok}`;
      const soloScheme = `solo${tok}`;
      const soloUapp = buildCustomUapp({
        appId: appSolo,
        name: `Solo-${tok}`,
        message: `SOLO_${tok}\n`,
        urlSchemes: [soloScheme],
      });
      await pkgManager.install(soloUapp, { filename: `solo-${tok}.uapp`, grantAll: true });
      registerIntentHandler(router, appSolo, {
        platform: 'universal',
        priority: 50,
        actions: [soloAction],
        schemes: [soloScheme],
      });
      const dispatched = await router.dispatch({
        action: soloAction,
        uri: `${soloScheme}://go`,
        sourcePid: 1,
      });
      assert.equal(dispatched?.status, 'DELIVERED', `Single-handler dispatch must return DELIVERED, got ${JSON.stringify(dispatched)}`);
      assert.equal(dispatched?.targetAppId, appSolo);
    } finally {
      await os.shutdown();
    }
  });

  test('T4 [F-024]: Universal Intent Router multi-handler CHOOSER_REQUIRED, preferredAppId override & NO_HANDLER', async () => {
    const os = await loadPublicOmniOS();
    try {
      const router = os.require('intentRouter');
      const pkgManager = os.require('pkgManager');
      const tok = makeToken();

      const appA = `com.test.sha.${tok}`;
      const appB = `com.test.shb.${tok}`;
      const shareAction = `omni.share.${tok}`;

      await pkgManager.install(
        buildCustomUapp({ appId: appA, name: `ShareA-${tok}`, message: `SHA_${tok}\n` }),
        { filename: `sha-${tok}.uapp`, grantAll: true }
      );
      await pkgManager.install(
        buildCustomUapp({ appId: appB, name: `ShareB-${tok}`, message: `SHB_${tok}\n` }),
        { filename: `shb-${tok}.uapp`, grantAll: true }
      );

      registerIntentHandler(router, appA, {
        platform: 'android',
        priority: 50,
        actions: [shareAction],
        mimeTypes: ['text/plain'],
      });
      registerIntentHandler(router, appB, {
        platform: 'ios',
        priority: 50,
        actions: [shareAction],
        mimeTypes: ['text/plain'],
      });

      // Without preferredAppId -> CHOOSER_REQUIRED with both candidates
      const chooser = await router.dispatch({
        action: shareAction,
        mimeType: 'text/plain',
        extras: { text: `share-${tok}` },
        sourcePid: 1,
      });
      assert.equal(chooser?.status, 'CHOOSER_REQUIRED', `Ambiguous dispatch must return CHOOSER_REQUIRED, got ${JSON.stringify(chooser)}`);
      assert.ok(Array.isArray(chooser.candidates), 'CHOOSER_REQUIRED must provide candidates array');
      const candIds = chooser.candidates.map((c) => (typeof c === 'string' ? c : c?.appId));
      assert.ok(candIds.includes(appA) && candIds.includes(appB), `Candidates must include both ${appA} and ${appB}`);

      // With preferredAppId -> DELIVERED directly to installed appB
      const direct = await router.dispatch({
        action: shareAction,
        mimeType: 'text/plain',
        extras: { text: `share-${tok}` },
        sourcePid: 1,
        preferredAppId: appB,
      });
      assert.equal(direct?.status, 'DELIVERED');
      assert.equal(direct?.targetAppId, appB);

      // Unregistered action -> NO_HANDLER
      const none = await router.dispatch({
        action: `omni.missing.${tok}`,
        sourcePid: 1,
      });
      assert.equal(none?.status, 'NO_HANDLER', `Unmatched intent must return NO_HANDLER, got ${JSON.stringify(none)}`);
    } finally {
      await os.shutdown();
    }
  });

  test('T5 [F-025]: Multi-MIME Shared Clipboard (text/plain, text/html, application/json, image/png) and 20-entry bounded history', async () => {
    const os = await loadPublicOmniOS();
    try {
      const clipboard = os.require('clipboard');
      const tok = makeToken();

      // 1. Multi-MIME text/plain + text/html + json
      clipboard.set({
        text: `Plain ${tok}`,
        html: `<b>${tok}</b>`,
        json: { tok, v: 99 },
        mime: 'text/plain',
        sourceAppId: `win.app.${tok}`,
      });
      const entry1 = clipboard.get();
      assert.equal(entry1?.text, `Plain ${tok}`);
      assert.equal(entry1?.html, `<b>${tok}</b>`);
      assert.deepEqual(entry1?.json, { tok, v: 99 });
      assert.equal(entry1?.sourceAppId, `win.app.${tok}`);

      // 2. application/json entry
      clipboard.set({
        mime: 'application/json',
        json: { mode: tok },
        text: JSON.stringify({ mode: tok }),
        sourceAppId: 'mac.app',
      });
      const entry2 = clipboard.get();
      assert.equal(entry2?.mime, 'application/json');
      assert.equal(entry2?.json?.mode, tok);

      // 3. image/png entry
      clipboard.set({
        mime: 'image/png',
        text: PNG_1X1_B64,
        image: PNG_1X1_B64,
        sourceAppId: 'ios.app',
      });
      const entry3 = clipboard.get();
      assert.equal(entry3?.mime, 'image/png');

      // 4. 20-entry bounded history FIFO eviction
      for (let i = 0; i < 25; i += 1) {
        const label = `item-${String(i).padStart(2, '0')}-${tok}`;
        clipboard.set({ text: label, mime: 'text/plain', sourceAppId: 'e2e.hist' });
      }

      assert.equal(clipboard.get()?.text, `item-24-${tok}`);
      const h20 = clipboard.history(20);
      const h50 = clipboard.history(50);
      assert.equal(h20.length, 20, `Clipboard history(20) must contain 20 entries, got ${h20.length}`);
      assert.equal(h50.length, 20, `Clipboard history must be bounded at 20 entries even when limit=50, got ${h50.length}`);

      const texts = h20.map((item) => item?.text);
      assert.ok(texts.includes(`item-24-${tok}`), 'History must retain newest entry item-24');
      assert.ok(texts.includes(`item-05-${tok}`), 'History must retain 20th-newest entry item-05');
      assert.equal(texts.includes(`item-00-${tok}`), false, 'Oldest entry item-00 must be evicted beyond 20 items');
      assert.equal(texts.includes(`item-04-${tok}`), false, 'Evicted entry item-04 must not remain in history');
    } finally {
      await os.shutdown();
    }
  });

  test('T6 [F-026]: Unified Notification Center post/list/invokeAction/dismiss/clearAll and Dynamic Island getLiveActivities()', async () => {
    const os = await loadPublicOmniOS();
    try {
      const notifications = os.require('notifications');
      const tok = makeToken();

      const n1 = notifications.post({
        appId: `com.ios.weather.${tok}`,
        platform: 'ios',
        title: `Weather ${tok}`,
        body: `72F Clear ${tok}`,
        priority: 'high',
        category: 'weather',
        actions: [{ id: 'ack', label: 'Ack' }],
        liveActivity: {
          id: `la-${tok}`,
          title: `Live ${tok}`,
          status: 'Active',
          progress: 0.6,
          icon: 'sun',
        },
      });
      const n2 = notifications.post({
        appId: `com.android.msg.${tok}`,
        platform: 'android',
        title: `Second ${tok}`,
        body: `Body ${tok}`,
        priority: 'normal',
        category: 'message',
      });

      assert.ok(n1?.id !== undefined && n1?.id !== null, 'notifications.post() must return an entry with id');
      assert.ok(n2?.id !== undefined && n2?.id !== null);

      const activeList = notifications.list({ includeDismissed: false });
      assert.ok(activeList.some((n) => n.id === n1.id), 'Active notification list must contain n1');
      assert.ok(activeList.some((n) => n.id === n2.id), 'Active notification list must contain n2');

      const liveActs = notifications.getLiveActivities();
      assert.ok(Array.isArray(liveActs), 'getLiveActivities() must return an Array');
      assert.ok(
        liveActs.some((la) => JSON.stringify(la).includes(`la-${tok}`) || JSON.stringify(la).includes(`Live ${tok}`)),
        `getLiveActivities() must expose posted Dynamic Island liveActivity: ${JSON.stringify(liveActs)}`
      );

      const actRes = await notifications.invokeAction(n1.id, 'ack');
      assert.ok(actRes !== false && actRes?.ok !== false, `invokeAction(n1.id, 'ack') failed: ${JSON.stringify(actRes)}`);

      notifications.dismiss(n1.id);
      const afterDismissActive = notifications.list({ includeDismissed: false });
      assert.equal(afterDismissActive.some((n) => n.id === n1.id), false, 'Dismissed notification must not appear in active list');
      assert.ok(afterDismissActive.some((n) => n.id === n2.id), 'Undismissed notification n2 must remain active');

      const withDismissed = notifications.list({ includeDismissed: true });
      assert.ok(withDismissed.some((n) => n.id === n1.id), 'list({ includeDismissed: true }) must still include dismissed n1');

      notifications.clearAll();
      assert.equal(notifications.list({ includeDismissed: false }).length, 0, 'clearAll() must clear all active notifications');
    } finally {
      await os.shutdown();
    }
  });

  test('T7 [F-024, F-025, F-026, Contracts 7 & 8]: Live REST /api/v1/ipc/*, RFC 6455 WS notification:posted & Remote CLI clipboard/notify', async () => {
    const srv = await startOmniServer();
    let ws = null;
    try {
      const tok = makeToken();
      ws = await srv.connectWs();

      // 1. Clipboard REST + Remote CLI
      const clipText = `rest-clip-${tok}`;
      let clipPut = await srv.api.put('/api/v1/ipc/clipboard', {
        text: clipText,
        html: `<i>${tok}</i>`,
        mime: 'text/plain',
        sourceAppId: 'e2e',
      });
      if (clipPut.status === 404 || clipPut.status === 405) {
        clipPut = await srv.api.post('/api/v1/ipc/clipboard', {
          text: clipText,
          html: `<i>${tok}</i>`,
          mime: 'text/plain',
          sourceAppId: 'e2e',
        });
      }
      assert.ok(clipPut.ok, `Setting /api/v1/ipc/clipboard failed (${clipPut.status}): ${clipPut.text}`);

      const clipGet = await srv.api.get('/api/v1/ipc/clipboard');
      assert.equal(clipGet.status, 200);
      assert.ok(clipGet.text.includes(clipText), `GET /api/v1/ipc/clipboard must contain "${clipText}"`);

      const cliClip = await srv.runCli(['clipboard', 'get'], { json: true, expectZero: true });
      assert.ok(cliClip.stdout.includes(clipText), `CLI "clipboard get" must contain "${clipText}", got: ${cliClip.stdout}`);

      // 2. Notification REST + WS notification:posted + Remote CLI notify list + action/dismiss
      const mark = ws.mark();
      const postNotif = await srv.api.post('/api/v1/ipc/notifications', {
        appId: `e2e.n.${tok}`,
        platform: 'android',
        title: `WsAlert ${tok}`,
        body: `Msg ${tok}`,
        actions: [{ id: 'open', label: 'Open' }],
      });
      assert.ok(postNotif.ok, `POST /api/v1/ipc/notifications failed (${postNotif.status}): ${postNotif.text}`);
      const postedObj = unwrapObject(postNotif.json);
      const notifId = postedObj?.id ?? postNotif.json?.id;
      assert.ok(notifId !== undefined && notifId !== null, `Posted notification must return an id: ${postNotif.text}`);

      const wsMsg = await ws.waitForType('notification:posted', { since: mark, timeoutMs: 5000 });
      assert.ok(
        JSON.stringify(wsMsg).includes(`WsAlert ${tok}`),
        `WS notification:posted must include "WsAlert ${tok}", got: ${JSON.stringify(wsMsg)}`
      );

      const cliNotif = await srv.runCli(['notify', 'list'], { json: true, expectZero: true });
      assert.ok(cliNotif.stdout.includes(`WsAlert ${tok}`), `CLI "notify list" must include "WsAlert ${tok}"`);

      const actRes = await srv.api.post(`/api/v1/ipc/notifications/${encodeURIComponent(String(notifId))}/action`, {
        actionId: 'open',
      });
      assert.ok(actRes.ok, `POST /api/v1/ipc/notifications/:id/action failed (${actRes.status}): ${actRes.text}`);

      const disRes = await srv.api.post(`/api/v1/ipc/notifications/${encodeURIComponent(String(notifId))}/dismiss`, {});
      assert.ok(disRes.ok, `POST /api/v1/ipc/notifications/:id/dismiss failed (${disRes.status}): ${disRes.text}`);

      // 3. Intent resolve & dispatch REST endpoints (install dynamic .uapp with custom URL scheme to verify non-vacuously)
      const restIntentApp = `com.rest.intent.${tok}`;
      const restScheme = `rest${tok}`;
      const restUappB64 = Buffer.from(
        buildCustomUapp({
          appId: restIntentApp,
          name: `RestIntent-${tok}`,
          message: `RESTINTENT_${tok}\n`,
          urlSchemes: [restScheme],
        })
      ).toString('base64');
      const instIntent = await srv.api.post('/api/v1/packages/install', {
        base64: restUappB64,
        data: restUappB64,
        filename: `intent-${tok}.uapp`,
        grantAll: true,
      });
      assert.ok(instIntent.ok, `Installing intent handler .uapp failed (${instIntent.status}): ${instIntent.text}`);

      let resIntent = await srv.api.post('/api/v1/ipc/intents/resolve', {
        scheme: restScheme,
        uri: `${restScheme}://open/1`,
      });
      if (resIntent.status === 404 || resIntent.status === 405) {
        resIntent = await srv.api.get('/api/v1/ipc/intents/resolve', {
          query: { scheme: restScheme, uri: `${restScheme}://open/1` },
        });
      }
      assert.equal(resIntent.status, 200, `/api/v1/ipc/intents/resolve failed (${resIntent.status}): ${resIntent.text}`);
      const resolvedHandlers = unwrapExplicitArray(resIntent.json, ['candidates', 'handlers', 'results', 'items', 'data', 'list']);
      assert.ok(
        Array.isArray(resolvedHandlers),
        `/api/v1/ipc/intents/resolve must return an explicit JSON array/list field, got: ${resIntent.text}`
      );
      assert.ok(
        resolvedHandlers.some((h) => (typeof h === 'string' ? h : h?.appId ?? h?.id) === restIntentApp),
        `/api/v1/ipc/intents/resolve must include auto-indexed handler "${restIntentApp}", got: ${JSON.stringify(resolvedHandlers)}`
      );

      const dispIntent = await srv.api.post('/api/v1/ipc/intents/dispatch', {
        action: `omni.unknown.${tok}`,
      });
      assert.equal(dispIntent.status, 200);
      const dispObj = unwrapObject(dispIntent.json);
      assert.equal(dispObj?.status, 'NO_HANDLER');
    } finally {
      await ws?.close();
      await srv.stop();
    }
  });
});
