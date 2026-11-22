/**
 * Tier 2 Boundary, Corner & Negative E2E Suite — FA-06:
 * Cross-Platform IPC, Shared Memory (SHM), Universal Intent Router, Clipboard 20-Item Cap
 * & Notification Center DND/Error Boundaries (F-023 – F-026).
 *
 * Strictly opaque-box: imports ONLY Node 24 built-ins, ../lib/env.mjs, and ../lib/fixtures-apple-wasm.mjs.
 * Zero skips, zero stubs, zero private internal os imports.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { loadPublicOmniOS, startOmniServer } from '../lib/env.mjs';
import { buildCustomUapp } from '../lib/fixtures-apple-wasm.mjs';

function makeToken() {
  return crypto.randomBytes(4).toString('hex');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function extractArrayStrict(payload, keys = ['items', 'candidates', 'handlers', 'notifications', 'results', 'entries']) {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== 'object') return null;
  for (const key of keys) {
    if (Array.isArray(payload[key])) return payload[key];
  }
  if (Array.isArray(payload.data)) return payload.data;
  if (payload.data && typeof payload.data === 'object') {
    for (const key of keys) {
      if (Array.isArray(payload.data[key])) return payload.data[key];
    }
  }
  return null;
}

function assertKernelHealthy(os) {
  const diag = os.require('kernel').getDiagnostics();
  assert.equal(diag?.state, 'RUNNING', `Kernel must remain RUNNING (got ${diag?.state})`);
}

async function assertRejectsOrFalse(fn, label, { allowNull = false } = {}) {
  let result;
  let caught = null;
  try {
    result = await fn();
  } catch (err) {
    caught = err;
  }
  if (caught) {
    assert.ok(caught instanceof Error && caught.message.length > 0, `${label}: error must have non-empty message`);
    return { threw: true, error: caught };
  }
  if (result === false || (result && typeof result === 'object' && result.ok === false)) {
    return { threw: false, result };
  }
  if (allowNull && (result === null || result === undefined)) {
    return { threw: false, result };
  }
  assert.fail(`${label}: expected Error or false/{ ok: false }${allowNull ? '/null' : ''}, got ${JSON.stringify(result)}`);
}

async function registerIntentHandlers(router, appId, specs) {
  // Contract 4 plural signature: array-first, object fallback only if array rejected
  try {
    return await router.registerHandlers(appId, specs);
  } catch {
    for (const spec of specs) {
      await router.registerHandlers(appId, spec);
    }
  }
}

async function setSystemDndRest(api, enabled) {
  const attempts = [
    () => api.put('/api/v1/config/system', { 'system.dnd': enabled }),
    () => api.post('/api/v1/config/system', { 'system.dnd': enabled }),
    () => api.patch('/api/v1/config/system', { 'system.dnd': enabled }),
    () => api.put('/api/v1/config/system', { key: 'system.dnd', value: enabled }),
    () => api.post('/api/v1/config/system', { key: 'system.dnd', value: enabled }),
    () => api.patch('/api/v1/config/system', { key: 'system.dnd', value: enabled }),
    () => api.put('/api/v1/config/system', { 'system.dnd': enabled, dnd: enabled }),
    () => api.post('/api/v1/config/system', { 'system.dnd': enabled, dnd: enabled }),
  ];
  let lastRes = null;
  for (const attempt of attempts) {
    const res = await attempt();
    lastRes = res;
    if (res.ok) return res;
    if (res.status !== 404 && res.status !== 405 && res.status !== 400) break;
  }
  assert.fail(`Failed to set system.dnd=${enabled} via REST (last status=${lastRes?.status}: ${lastRes?.text})`);
}

function readSystemDndFromJson(json) {
  const obj = (json?.data && typeof json.data === 'object' && !Array.isArray(json.data)) ? json.data : json;
  const nested = (obj?.system && typeof obj.system === 'object') ? obj.system : obj;
  if (typeof obj?.['system.dnd'] === 'boolean') return obj['system.dnd'];
  if (typeof obj?.dnd === 'boolean') return obj.dnd;
  if (typeof nested?.dnd === 'boolean') return nested.dnd;
  if (typeof nested?.['system.dnd'] === 'boolean') return nested['system.dnd'];
  return undefined;
}

test.describe('Tier 2 — FA-06: Cross-Platform IPC, Universal Intent Router, Clipboard & Notifications (Boundary & Negative)', () => {
  test('T1 [F-023]: IPC send/recv on non-existent channel, empty channel name rejection & healthy sibling continuity', async () => {
    const tok = makeToken();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const ipc = os.require('ipc');

      const healthyChan = `omni.ok.${tok}`;
      await ipc.createChannel(healthyChan, 1);
      await ipc.send(healthyChan, 1, { nonce: tok });

      // send() to non-existent channel MUST reject or return false / { ok: false }
      await assertRejectsOrFalse(
        () => ipc.send(`omni.missing.${tok}`, 1, { bad: 1 }),
        'ipc.send on non-existent channel'
      );

      // recv() on non-existent channel MUST reject or return null/undefined promptly (MUST NOT hang!)
      let recvTimer = null;
      const recvGuard = Promise.race([
        Promise.resolve().then(() => ipc.recv(`omni.missing.${tok}`, 1)),
        new Promise((_, reject) => {
          recvTimer = setTimeout(() => {
            const timeoutErr = new Error('ipc.recv on non-existent channel hung for >2000ms');
            timeoutErr.code = 'E_RECV_TIMEOUT';
            reject(timeoutErr);
          }, 2000);
          recvTimer.unref?.();
        }),
      ]).finally(() => clearTimeout(recvTimer));

      const recvCheck = await assertRejectsOrFalse(
        () => recvGuard,
        'ipc.recv on non-existent channel',
        { allowNull: true }
      );
      if (recvCheck.threw) {
        assert.notEqual(
          recvCheck.error?.code,
          'E_RECV_TIMEOUT',
          'ipc.recv on non-existent channel must reject or return null immediately instead of hanging'
        );
      }

      // Empty channel name MUST reject cleanly without crashing kernel
      await assertRejectsOrFalse(
        () => ipc.createChannel('', 1),
        'ipc.createChannel("") empty name'
      );

      // Healthy sibling channel continues delivering queued payload intact
      const received = await ipc.recv(healthyChan, 1);
      const payload = received?.payload ?? received;
      assert.equal(payload?.nonce, tok, `Healthy channel must still deliver queued payload (got ${JSON.stringify(received)})`);
      assertKernelHealthy(os);
    } finally {
      await os?.shutdown();
    }
  });

  test('T2 [F-023]: SHM OOB offset/length read/write rejection, invalid IDs & exact 0-byte / tail-boundary integrity', async () => {
    const tok = makeToken();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const ipc = os.require('ipc');

      const created = await ipc.shmCreate(`shm-bnd-${tok}`, 64, 1);
      const shmId = typeof created === 'string' || typeof created === 'number'
        ? created
        : (created?.id ?? created?.shmId ?? created?.name);
      assert.ok(shmId !== undefined && shmId !== null, `shmCreate must return an ID or descriptor (got ${JSON.stringify(created)})`);
      if (typeof ipc.shmAttach === 'function') {
        await ipc.shmAttach(shmId, 1);
      }

      // Positive exact lower & upper boundaries (offset 0..4 and 60..64 on 64-byte segment)
      const head = crypto.randomBytes(4);
      const tail = crypto.randomBytes(4);
      await ipc.shmWrite(shmId, 0, head);
      await ipc.shmWrite(shmId, 60, tail);
      assert.equal(Buffer.compare(Buffer.from(await ipc.shmRead(shmId, 0, 4)), head), 0, 'SHM head boundary [0..4) must match');
      assert.equal(Buffer.compare(Buffer.from(await ipc.shmRead(shmId, 60, 4)), tail), 0, 'SHM tail boundary [60..64) must match');

      // Zero-byte boundary write & read
      await ipc.shmWrite(shmId, 32, new Uint8Array(0));
      assert.equal(Buffer.from(await ipc.shmRead(shmId, 32, 0)).length, 0, 'Zero-length shmRead must return 0 bytes');

      // Negative OOB offsets, straddling lengths, invalid IDs & invalid sizes MUST throw/reject
      const oobCases = [
        ['shmWrite negative offset', () => ipc.shmWrite(shmId, -1, Uint8Array.from([0xaa]))],
        ['shmWrite at exact size (64)', () => ipc.shmWrite(shmId, 64, Uint8Array.from([0xbb]))],
        ['shmWrite crossing end (60+8)', () => ipc.shmWrite(shmId, 60, new Uint8Array(8))],
        ['shmRead negative offset', () => ipc.shmRead(shmId, -1, 4)],
        ['shmRead crossing end (60+8)', () => ipc.shmRead(shmId, 60, 8)],
        ['shmRead past end (65, 1)', () => ipc.shmRead(shmId, 65, 1)],
        ['shmRead negative length', () => ipc.shmRead(shmId, 0, -4)],
        ['shmRead non-existent ID', () => ipc.shmRead(`shm-ghost-${tok}`, 0, 4)],
        ['shmWrite non-existent ID', () => ipc.shmWrite(`shm-ghost-${tok}`, 0, Uint8Array.from([1]))],
        ['shmCreate negative size', () => ipc.shmCreate(`shm-neg-${tok}`, -32, 1)],
        ['shmCreate zero size', () => ipc.shmCreate(`shm-zero-${tok}`, 0, 1)],
      ];
      for (const [label, fn] of oobCases) {
        await assert.rejects(
          async () => fn(),
          (err) => err instanceof Error && err.message.length > 0,
          `${label} MUST throw/reject cleanly`
        );
      }

      // Non-corruption proof: full 64B region retains exact head & tail bytes
      const full = Buffer.from(await ipc.shmRead(shmId, 0, 64));
      assert.equal(full.length, 64);
      assert.equal(Buffer.compare(full.subarray(0, 4), head), 0, 'Head bytes must remain intact after OOB attempts');
      assert.equal(Buffer.compare(full.subarray(60, 64), tail), 0, 'Tail bytes must remain intact after OOB attempts');
      assertKernelHealthy(os);
    } finally {
      await os?.shutdown();
    }
  });

  test('T3 [F-024]: Intent Router NO_HANDLER across unregistered action/scheme/MIME/extension + priority tie conflict & invalid preferredAppId', async () => {
    const tok = makeToken();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const router = os.require('intentRouter');
      const pkgManager = os.require('pkgManager');

      // Part A: Unregistered action, scheme, MIME, extension -> resolve [] & dispatch NO_HANDLER
      const unregAction = `omni.none.act.${tok}`;
      const unregScheme = `none${tok}`;
      const unregMime = `application/x-none-${tok}`;
      const unregExt = `noext${tok}`;

      assert.deepEqual(await router.resolve({ action: unregAction }), [], 'Unregistered action must resolve to []');
      assert.equal((await router.dispatch({ action: unregAction, sourcePid: 1 }))?.status, 'NO_HANDLER');

      assert.deepEqual(await router.resolve({ scheme: unregScheme, uri: `${unregScheme}://item/1` }), []);
      assert.equal((await router.dispatch({ uri: `${unregScheme}://item/1`, sourcePid: 1 }))?.status, 'NO_HANDLER');

      assert.deepEqual(await router.resolve({ mimeType: unregMime }), []);
      assert.equal((await router.dispatch({ action: 'omni.open', mimeType: unregMime, sourcePid: 1 }))?.status, 'NO_HANDLER');

      assert.deepEqual(await router.resolve({ extension: unregExt }), []);

      // Part B: Install 3 real minimal .uapp packages for tie conflict & priority ranking
      const appTieA = `com.intent.tieA.${tok}`;
      const appTieB = `com.intent.tieB.${tok}`;
      const appHigh = `com.intent.high.${tok}`;

      for (const appId of [appTieA, appTieB, appHigh]) {
        const uapp = buildCustomUapp({ appId, name: appId, message: `hi-${appId}\n` });
        await pkgManager.install(uapp, { grantAll: true });
      }

      const tieAction = `omni.tie.${tok}`;
      const tieMime = `text/x-tie-${tok}`;
      await registerIntentHandlers(router, appTieA, [{ action: tieAction, mimeType: tieMime, priority: 50 }]);
      await registerIntentHandlers(router, appTieB, [{ action: tieAction, mimeType: tieMime, priority: 50 }]);

      // Equal priority tie MUST trigger CHOOSER_REQUIRED with both candidates
      const tieRes = await router.dispatch({ action: tieAction, mimeType: tieMime, sourcePid: 1 });
      assert.equal(tieRes?.status, 'CHOOSER_REQUIRED', `Equal-priority tie must return CHOOSER_REQUIRED (got ${JSON.stringify(tieRes)})`);
      assert.ok(Array.isArray(tieRes?.candidates) && tieRes.candidates.length >= 2, 'CHOOSER_REQUIRED must list >= 2 candidates');
      const candIds = tieRes.candidates.map((c) => (typeof c === 'string' ? c : (c?.appId ?? c?.id)));
      assert.ok(candIds.includes(appTieA) && candIds.includes(appTieB), `Candidates must include both tied apps (got ${JSON.stringify(candIds)})`);

      // Invalid preferredAppId MUST NOT deliver to non-existent ghost app
      const ghostApp = `com.ghost.${tok}`;
      let ghostRes = null;
      let ghostErr = null;
      try {
        ghostRes = await router.dispatch({ action: tieAction, mimeType: tieMime, sourcePid: 1, preferredAppId: ghostApp });
      } catch (err) {
        ghostErr = err;
      }
      if (ghostErr) {
        assert.ok(ghostErr instanceof Error && ghostErr.message.length > 0);
      } else {
        assert.notEqual(ghostRes?.targetAppId, ghostApp, 'Invalid preferredAppId must NEVER deliver to ghost app');
        assert.ok(
          ghostRes?.status === 'CHOOSER_REQUIRED' || ghostRes?.status === 'NO_HANDLER',
          `Invalid preferredAppId must reject or return CHOOSER_REQUIRED/NO_HANDLER (got ${JSON.stringify(ghostRes)})`
        );
      }

      // Higher-priority handler MUST rank strictly before lower-priority handler
      const prioAction = `omni.prio.${tok}`;
      await registerIntentHandlers(router, appTieA, [{ action: prioAction, priority: 15 }]);
      await registerIntentHandlers(router, appHigh, [{ action: prioAction, priority: 95 }]);
      const ranked = await router.resolve({ action: prioAction });
      assert.ok(Array.isArray(ranked) && ranked.length >= 2, 'resolve() must return both registered handlers');
      const rankedIds = ranked.map((r) => (typeof r === 'string' ? r : (r?.appId ?? r?.id)));
      assert.equal(rankedIds[0], appHigh, `Higher-priority handler (95) must rank strictly first (got ${JSON.stringify(rankedIds)})`);
      assert.ok(rankedIds.indexOf(appTieA) > 0, 'Lower-priority handler (15) must rank after high-priority handler');
      assertKernelHealthy(os);
    } finally {
      await os?.shutdown();
    }
  });

  test('T4 [F-025]: Clipboard exact 20-item history cap boundary (empty -> 20 -> 21 evicts #0 -> 25 retains exact #5..#24)', async () => {
    const tok = makeToken();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const clipboard = os.require('clipboard');

      // Empty initial state
      const emptyHist = await clipboard.history(20);
      assert.ok(Array.isArray(emptyHist) && emptyHist.length === 0, 'Initial clipboard history must be empty []');
      const emptyCur = await clipboard.get();
      assert.ok(emptyCur === null || emptyCur === undefined || emptyCur?.text === '' || emptyCur?.text === undefined);

      const itemText = (i) => `clip-${String(i).padStart(2, '0')}-${tok}`;
      const textsFrom = (arr) => arr.map((e) => e?.text);

      // Write items 00..19 (exact 20-item capacity)
      for (let i = 0; i < 20; i++) {
        await clipboard.set({ text: itemText(i), mime: 'text/plain', sourceAppId: 'e2e.clip' });
      }
      const h20 = await clipboard.history(20);
      const h20Over = await clipboard.history(50);
      assert.equal(h20.length, 20, '20 writes must yield exact 20 history items');
      assert.equal(h20Over.length, 20, 'history(50) after 20 writes must yield 20 items');
      assert.ok(textsFrom(h20).includes(itemText(0)), 'Item 00 must still be present at exact capacity 20');
      assert.ok(textsFrom(h20).includes(itemText(19)), 'Item 19 must be present at exact capacity 20');

      // Write item 20 (exact 21st write -> evicts item 00 FIFO!)
      await clipboard.set({ text: itemText(20), mime: 'text/plain', sourceAppId: 'e2e.clip' });
      const h21 = await clipboard.history(50);
      assert.equal(h21.length, 20, '21st write must cap history at exact 20 items');
      const t21 = textsFrom(h21);
      assert.equal(t21.includes(itemText(0)), false, '21st write MUST evict oldest item 00 FIFO');
      assert.ok(t21.includes(itemText(1)), 'Item 01 must remain after 21st write');
      assert.ok(t21.includes(itemText(20)), 'Item 20 must be present after 21st write');

      // Write items 21..24 (total 25 writes -> exact window #05..#24)
      for (let i = 21; i < 25; i++) {
        await clipboard.set({ text: itemText(i), mime: 'text/plain', sourceAppId: 'e2e.clip' });
      }
      assert.equal((await clipboard.get())?.text, itemText(24), 'clipboard.get() must return latest item 24');

      const h25 = await clipboard.history(20);
      const h25Cap = await clipboard.history(100);
      assert.equal(h25.length, 20, 'history(20) after 25 writes must equal 20');
      assert.equal(h25Cap.length, 20, 'history(100) after 25 writes must remain capped at 20');

      const t25 = textsFrom(h25Cap);
      for (let i = 0; i < 5; i++) {
        assert.equal(t25.includes(itemText(i)), false, `Evicted item ${i} must NOT appear in capped history`);
      }
      for (let i = 5; i < 25; i++) {
        assert.equal(t25.includes(itemText(i)), true, `Retained item ${i} MUST appear in 20-item FIFO window`);
      }

      // Smaller limit and zero limit boundaries
      const h5 = await clipboard.history(5);
      assert.equal(h5.length, 5, 'history(5) must respect smaller limit');
      const t5 = textsFrom(h5);
      for (let i = 20; i < 25; i++) {
        assert.equal(t5.includes(itemText(i)), true, `history(5) must retain latest item ${i}`);
      }
      const h0 = await clipboard.history(0);
      assert.ok(Array.isArray(h0) && h0.length === 0, 'history(0) must return empty []');

      // Empty string write works cleanly without crashing
      await clipboard.set({ text: '', mime: 'text/plain', sourceAppId: 'e2e.clip' });
      assert.equal((await clipboard.get())?.text, '', 'Empty-string clipboard write must round-trip as ""');
      assertKernelHealthy(os);
    } finally {
      await os?.shutdown();
    }
  });

  test('T5 [F-026]: Notification Center DND filtering (system.dnd = true) suppresses delivery & restores when system.dnd = false', async () => {
    const tok = makeToken();
    let srv = null;
    let ws = null;
    try {
      srv = await startOmniServer();
      ws = await srv.connectWs();

      // 1. Baseline (DND OFF)
      await setSystemDndRest(srv.api, false);
      const c1 = ws.mark();
      const preTitle = `PreDnd-${tok}`;
      const preRes = await srv.api.post('/api/v1/ipc/notifications', {
        appId: `com.dnd.test.${tok}`,
        platform: 'ios',
        title: preTitle,
        body: `pre-body-${tok}`,
        priority: 'normal',
      });
      assert.ok(preRes.ok, `Baseline notification post must succeed (got ${preRes.status}: ${preRes.text})`);

      const preListRes = await srv.api.get('/api/v1/ipc/notifications');
      assert.equal(preListRes.status, 200);
      const preList = extractArrayStrict(preListRes.json, ['notifications', 'items']);
      assert.ok(Array.isArray(preList), 'GET /api/v1/ipc/notifications must return an array');
      assert.ok(
        preList.some((n) => n?.title === preTitle),
        `Baseline notification "${preTitle}" must appear in active list when DND=false`
      );

      await ws.waitForMessage(
        (m) => m?.type === 'notification:posted' && JSON.stringify(m).includes(preTitle),
        { since: c1, timeoutMs: 4000 }
      );

      // 2. Enable DND (system.dnd = true)
      await setSystemDndRest(srv.api, true);
      const cfgCheck = await srv.api.get('/api/v1/config/system');
      assert.equal(cfgCheck.status, 200);
      assert.equal(readSystemDndFromJson(cfgCheck.json), true, 'Config store must confirm system.dnd === true');

      const c2 = ws.mark();
      const dndTitle = `DuringDnd-${tok}`;
      const dndRes = await srv.api.post('/api/v1/ipc/notifications', {
        appId: `com.dnd.test.${tok}`,
        platform: 'ios',
        title: dndTitle,
        body: `dnd-body-${tok}`,
        priority: 'low',
      });
      assert.ok(
        dndRes.status >= 200 && dndRes.status < 300,
        `POST /api/v1/ipc/notifications while system.dnd=true must succeed cleanly with 2xx (never 500/404, got ${dndRes.status}: ${dndRes.text})`
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
        dndData === null ||
        dndRes.json?.suppressed === true ||
        dndRes.json?.filtered === true
      );

      const duringListRes = await srv.api.get('/api/v1/ipc/notifications');
      assert.equal(duringListRes.status, 200);
      const duringList = extractArrayStrict(duringListRes.json, ['notifications', 'items']);
      assert.ok(Array.isArray(duringList));
      const omittedFromActive = !duringList.some((n) => n?.title === dndTitle && !n?.suppressed && !n?.muted && !n?.filtered);

      const wsDuring = ws.getMessages(c2);
      const wsSuppressed = !wsDuring.some((m) => m?.type === 'notification:posted' && JSON.stringify(m).includes(dndTitle));

      assert.ok(
        markedSuppressed || omittedFromActive || wsSuppressed,
        `DND=true MUST genuinely suppress/filter low-priority notification "${dndTitle}" ` +
        `(markedSuppressed=${markedSuppressed}, omittedFromActive=${omittedFromActive}, wsSuppressed=${wsSuppressed})`
      );

      // 3. Restore DND (system.dnd = false) -> normal delivery & WS push resume!
      await setSystemDndRest(srv.api, false);
      const c3 = ws.mark();
      const postTitle = `AfterDnd-${tok}`;
      const postRes = await srv.api.post('/api/v1/ipc/notifications', {
        appId: `com.dnd.test.${tok}`,
        platform: 'ios',
        title: postTitle,
        body: `post-body-${tok}`,
        priority: 'normal',
      });
      assert.ok(postRes.ok, `Post-DND notification must succeed (got ${postRes.status})`);

      const postListRes = await srv.api.get('/api/v1/ipc/notifications');
      assert.equal(postListRes.status, 200);
      const postList = extractArrayStrict(postListRes.json, ['notifications', 'items']);
      assert.ok(Array.isArray(postList) && postList.some((n) => n?.title === postTitle), 'Restored DND=false must deliver notification to active list');

      await ws.waitForMessage(
        (m) => m?.type === 'notification:posted' && JSON.stringify(m).includes(postTitle),
        { since: c3, timeoutMs: 4000 }
      );
    } finally {
      await ws?.close();
      await srv?.stop();
    }
  });

  test('T6 [F-026]: Notification Center non-existent ID dismiss/action, invalid action ID & double-dismiss safety', async () => {
    const tok = makeToken();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const notifications = os.require('notifications');

      const n1 = await notifications.post({
        appId: `com.notif.edge.${tok}`,
        platform: 'android',
        title: `Notif1-${tok}`,
        body: `body1-${tok}`,
        priority: 'normal',
        actions: [{ id: 'reply', label: 'Reply' }],
      });
      const n1Id = n1?.id ?? n1?.notificationId;
      assert.ok(n1Id !== undefined && n1Id !== null, `notifications.post must return an ID (got ${JSON.stringify(n1)})`);

      // Dismiss non-existent ID -> throws OR returns false/{ ok: false }/null; n1 remains active
      await assertRejectsOrFalse(
        () => notifications.dismiss(`notif-missing-${tok}`),
        'dismiss non-existent notification ID',
        { allowNull: true }
      );
      const active1 = await notifications.list({ includeDismissed: false });
      assert.ok(active1.some((n) => (n?.id ?? n?.notificationId) === n1Id), 'n1 must remain active after missing-ID dismiss');

      // invokeAction on non-existent notification ID -> throws OR returns false/{ ok: false }/null
      await assertRejectsOrFalse(
        () => notifications.invokeAction(`notif-missing-${tok}`, 'reply'),
        'invokeAction on non-existent notification ID',
        { allowNull: true }
      );

      // invokeAction with bogus actionId on real notification -> throws OR returns false/{ ok: false }/null
      await assertRejectsOrFalse(
        () => notifications.invokeAction(n1Id, `bogus-action-${tok}`),
        'invokeAction with unknown actionId',
        { allowNull: true }
      );

      // Valid dismiss followed by double-dismiss must not crash kernel
      await notifications.dismiss(n1Id);
      const activeAfterDismiss = await notifications.list({ includeDismissed: false });
      assert.equal(
        activeAfterDismiss.some((n) => (n?.id ?? n?.notificationId) === n1Id),
        false,
        'Dismissed notification n1 must leave active list'
      );
      let doubleDismissErr = null;
      try {
        await notifications.dismiss(n1Id);
      } catch (err) {
        doubleDismissErr = err;
      }
      if (doubleDismissErr) {
        assert.ok(doubleDismissErr instanceof Error && doubleDismissErr.message.length > 0);
      }

      // Subsequent notification posts cleanly
      const n2 = await notifications.post({
        appId: `com.notif.edge.${tok}`,
        platform: 'android',
        title: `Notif2-${tok}`,
        body: `body2-${tok}`,
        priority: 'normal',
      });
      const n2Id = n2?.id ?? n2?.notificationId;
      const active2 = await notifications.list({ includeDismissed: false });
      assert.ok(active2.some((n) => (n?.id ?? n?.notificationId) === n2Id), 'n2 must appear in active list after error cases');
      assertKernelHealthy(os);
    } finally {
      await os?.shutdown();
    }
  });

  test('T7 [F-024, F-025, F-026, Contract 7]: Live REST /api/v1/ipc/* negative 404/400 & empty resolve handling', async () => {
    const tok = makeToken();
    let srv = null;
    try {
      srv = await startOmniServer();

      // Helper to resolve notification id from post response or active list
      const postLiveNotif = async (title, extra = {}) => {
        const res = await srv.api.post('/api/v1/ipc/notifications', {
          appId: `com.notif.rest.${tok}`,
          platform: 'android',
          title,
          body: `body-${title}`,
          priority: 'normal',
          ...extra,
        });
        assert.ok(res.ok, `Pre-condition: posting live notification "${title}" must succeed (got ${res.status}: ${res.text})`);
        const obj = res.json?.data ?? res.json?.notification ?? res.json;
        let id = obj?.id ?? obj?.notificationId;
        if (id === undefined || id === null) {
          const listRes = await srv.api.get('/api/v1/ipc/notifications');
          const list = extractArrayStrict(listRes.json, ['notifications', 'items']) ?? [];
          const found = list.find((n) => n?.title === title);
          id = found?.id ?? found?.notificationId;
        }
        assert.ok(id !== undefined && id !== null, `Pre-condition: live notification "${title}" must expose an ID (got ${res.text})`);
        return id;
      };

      // Pre-condition 1: prove /notifications/:id/action works on a real notification (separate from dismiss to avoid auto-dismiss collision)
      const liveActionId = await postLiveNotif(`LiveAct-${tok}`, { actions: [{ id: 'ack', label: 'Ack' }] });
      let actionMethod = 'POST';
      let realActionRes = await srv.api.post(`/api/v1/ipc/notifications/${encodeURIComponent(String(liveActionId))}/action`, { actionId: 'ack' });
      if (realActionRes.status === 404 || realActionRes.status === 405) {
        actionMethod = 'PUT';
        realActionRes = await srv.api.put(`/api/v1/ipc/notifications/${encodeURIComponent(String(liveActionId))}/action`, { actionId: 'ack' });
      }
      assert.ok(
        realActionRes.ok,
        `Pre-condition: invoking valid action on live notification ${liveActionId} must succeed (got ${realActionRes.status}: ${realActionRes.text})`
      );

      // Pre-condition 2: prove /notifications/:id/dismiss works on a real notification and removes it from active list
      const liveDismissTitle = `LiveDis-${tok}`;
      const liveDismissId = await postLiveNotif(liveDismissTitle);
      let dismissMethod = 'POST';
      let realDismissRes = await srv.api.post(`/api/v1/ipc/notifications/${encodeURIComponent(String(liveDismissId))}/dismiss`, {});
      if (realDismissRes.status === 404 || realDismissRes.status === 405) {
        dismissMethod = 'PUT';
        realDismissRes = await srv.api.put(`/api/v1/ipc/notifications/${encodeURIComponent(String(liveDismissId))}/dismiss`, {});
      }
      if (realDismissRes.status === 404 || realDismissRes.status === 405) {
        dismissMethod = 'DELETE';
        realDismissRes = await srv.api.delete(`/api/v1/ipc/notifications/${encodeURIComponent(String(liveDismissId))}/dismiss`);
      }
      assert.ok(
        realDismissRes.ok,
        `Pre-condition: dismissing live notification ${liveDismissId} must succeed (got ${realDismissRes.status}: ${realDismissRes.text})`
      );
      const afterDismissListRes = await srv.api.get('/api/v1/ipc/notifications');
      assert.equal(afterDismissListRes.status, 200);
      const afterDismissList = extractArrayStrict(afterDismissListRes.json, ['notifications', 'items']) ?? [];
      assert.equal(
        afterDismissList.some((n) => (n?.id ?? n?.notificationId) === liveDismissId || n?.title === liveDismissTitle),
        false,
        'Pre-condition: dismissed live notification must leave active list'
      );

      // Dismiss non-existent notification using EXACT proven dismissMethod (ZERO fallback!) -> 4xx (never 200, 405, or 500)
      const resDismiss404 = await srv.api.request(
        dismissMethod,
        `/api/v1/ipc/notifications/nonexistent-${tok}/dismiss`,
        dismissMethod === 'DELETE' ? {} : { body: {} }
      );
      assert.ok(
        resDismiss404.status >= 400 && resDismiss404.status < 500 && resDismiss404.status !== 405,
        `${dismissMethod} dismiss on non-existent notification must return 404/400 (got ${resDismiss404.status}: ${resDismiss404.text})`
      );

      // Action on non-existent notification using EXACT proven actionMethod (ZERO fallback!) -> 4xx (never 200, 405, or 500)
      const resAction404 = await srv.api.request(
        actionMethod,
        `/api/v1/ipc/notifications/nonexistent-${tok}/action`,
        { body: { actionId: 'x' } }
      );
      assert.ok(
        resAction404.status >= 400 && resAction404.status < 500 && resAction404.status !== 405,
        `${actionMethod} action on non-existent notification must return 404/400 (got ${resAction404.status}: ${resAction404.text})`
      );

      // Unregistered intent dispatch -> 200 with status === 'NO_HANDLER'
      const resDisp = await srv.api.post('/api/v1/ipc/intents/dispatch', { action: `omni.unreg.${tok}` });
      assert.equal(resDisp.status, 200, `Unregistered intent dispatch must return 200 (got ${resDisp.status}: ${resDisp.text})`);
      const dispData = resDisp.json?.data ?? resDisp.json;
      assert.equal(dispData?.status, 'NO_HANDLER', `Expected NO_HANDLER (got ${JSON.stringify(resDisp.json)})`);

      // Unregistered intent resolve -> 200 with genuine empty Array (404 || 405 positive-probe verb discovery; asserts === 200!)
      let resResolve = await srv.api.post('/api/v1/ipc/intents/resolve', {
        action: `omni.unreg.${tok}`,
        scheme: `unreg${tok}`,
      });
      if (resResolve.status === 404 || resResolve.status === 405) {
        resResolve = await srv.api.get('/api/v1/ipc/intents/resolve', {
          query: { action: `omni.unreg.${tok}`, scheme: `unreg${tok}` },
        });
      }
      assert.equal(resResolve.status, 200, `Intent resolve must return 200 (got ${resResolve.status}: ${resResolve.text})`);
      const resolvedList = extractArrayStrict(resResolve.json, ['candidates', 'handlers', 'results', 'intents', 'items']);
      assert.ok(Array.isArray(resolvedList) && resolvedList.length === 0, `Unregistered resolve must return [] (got ${JSON.stringify(resResolve.json)})`);

      // Final health check
      const health = await srv.api.get('/api/health');
      assert.equal(health.status, 200);
      assert.equal(health.json?.ok, true);
    } finally {
      await srv?.stop();
    }
  });
});
