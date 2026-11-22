/**
 * Tier 2 Boundary, Corner & Negative E2E Suite — FA-08:
 * Headless Window Compositor, Dual Surfaces (flat & nested bounds/surface compatibility),
 * maxWindows Quota & Input Isolation (F-029 – F-031, F-011).
 *
 * Strictly opaque-box: imports ONLY Node 24 built-ins and ../lib/env.mjs.
 * Zero skips, zero stubs, zero private internal os imports.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { loadPublicOmniOS, startOmniServer } from '../lib/env.mjs';

function makeToken() {
  return crypto.randomBytes(4).toString('hex');
}

function getWinId(win) {
  if (typeof win === 'string' || typeof win === 'number') return win;
  return win?.windowId ?? win?.id ?? null;
}

function getBounds(win) {
  const b = (win?.bounds && typeof win.bounds === 'object') ? win.bounds : win;
  return {
    x: b?.x,
    y: b?.y,
    width: b?.width,
    height: b?.height,
  };
}

function getUiTree(win) {
  return win?.uiTree ?? win?.surface?.uiTree ?? null;
}

function getDrawOps(win) {
  return win?.drawOps ?? win?.surface?.drawOps ?? null;
}

function getZOrder(win) {
  return win?.zIndex ?? win?.zOrder;
}

function extractArrayStrict(payload, keys = ['windows']) {
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

function findWindow(snapshot, windowId) {
  const wins = extractArrayStrict(snapshot, ['windows']);
  if (!wins) return null;
  return wins.find((w) => getWinId(w) === windowId) ?? null;
}

function normalizeServicesMap(raw) {
  const map = new Map();
  if (!raw) return map;
  if (raw instanceof Map) {
    for (const [k, v] of raw.entries()) map.set(String(k), v);
    return map;
  }
  const arr = extractArrayStrict(raw, ['services']);
  if (arr) {
    for (const entry of arr) {
      if (entry && typeof entry === 'object' && entry.name) map.set(String(entry.name), entry);
    }
    return map;
  }
  const obj = (raw.services && typeof raw.services === 'object') ? raw.services
    : (raw.data?.services && typeof raw.data.services === 'object') ? raw.data.services
      : (raw.data && typeof raw.data === 'object') ? raw.data
        : raw;
  if (obj && typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj)) {
      if (v && typeof v === 'object') map.set(String(v.name ?? k), v);
    }
  }
  return map;
}

function assertCompositorHealthy(os) {
  assert.equal(os.require('kernel').getDiagnostics()?.state, 'RUNNING', 'Kernel must remain RUNNING');
  const svcs = normalizeServicesMap(os.require('serviceManager').getStatus());
  const compSvc = svcs.get('compositord');
  assert.ok(compSvc && typeof compSvc === 'object', 'compositord must remain registered');
  const state = String(compSvc.state ?? compSvc.status ?? '').trim();
  assert.match(state, /^(running|active|healthy|ready|started|ok)$/i, `compositord must remain healthy (got "${state}")`);
  assert.notEqual(compSvc.healthy, false, 'compositord must not report healthy === false');
}

async function assertOpRejected(fn, label) {
  let result;
  let caught = null;
  try {
    result = await fn();
  } catch (err) {
    caught = err;
  }
  if (caught) {
    assert.ok(caught instanceof Error && caught.message.length > 0, `${label}: thrown Error must have a non-empty message`);
    return;
  }
  assert.ok(
    result === false || (result && typeof result === 'object' && result.ok === false),
    `${label}: MUST throw Error or return false/{ ok: false } (got ${JSON.stringify(result)})`
  );
}

function makeInputTrackingContext() {
  const ctx = {
    steps: 0,
    disposed: false,
    delivered: [],
    step(budget) {
      ctx.steps += 1;
      return { status: 'YIELD', instructionsExecuted: Math.max(1, Number(budget) || 1) };
    },
    deliverEvent(ev) {
      ctx.delivered.push(ev);
    },
    getDebugState() {
      return { arch: 'wasm', pc: ctx.steps, sp: 0, registers: {}, instructionsExecuted: ctx.steps, lastSyscall: null, stackTop: 0 };
    },
    dispose() {
      ctx.disposed = true;
    },
  };
  return ctx;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function unwrapSnapshot(payload) {
  if (!payload || typeof payload !== 'object') return payload;
  if (Array.isArray(payload.windows)) return payload;
  if (payload.snapshot && typeof payload.snapshot === 'object') return payload.snapshot;
  if (payload.data && typeof payload.data === 'object') return payload.data;
  return payload;
}

async function discoverWorkingMethod(api, methods, urlPath, body) {
  let lastRes = null;
  let chosenMethod = methods[0];
  for (const method of methods) {
    chosenMethod = method;
    const res = await api.request(method, urlPath, body !== undefined && method !== 'DELETE' ? { body } : {});
    lastRes = res;
    if (res.ok) return { method, res };
    if (res.status !== 404 && res.status !== 405) return { method, res };
  }
  return { method: chosenMethod, res: lastRes };
}

test.describe('Tier 2 — FA-08: Headless Window Compositor, Dual Surfaces & Input Routing (Boundary & Negative)', () => {
  test('T1 [F-029, F-030, F-031]: All 7 compositor operations on non-existent & already-closed windowId rejected cleanly without crashing compositord', async () => {
    const tok = makeToken();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const comp = os.require('compositor');

      // Create one healthy live window with both uiTree and drawOps
      const liveCreated = await comp.createWindow(1, {
        appId: `com.comp.live.${tok}`,
        platform: 'macos',
        title: `Live-${tok}`,
        width: 520,
        height: 360,
        x: 40,
        y: 50,
        uiTree: { id: 'root', type: 'view', children: [{ id: 'btn', type: 'button', text: `OK-${tok}` }] },
        drawOps: [{ op: 'rect', x: 0, y: 0, w: 20, h: 20 }],
      });
      const liveWinId = getWinId(liveCreated);
      assert.ok(liveWinId !== null && liveWinId !== undefined, 'createWindow must return a windowId');

      const ghostId = `win-nonexistent-${tok}`;
      await assertOpRejected(() => comp.moveWindow(ghostId, 10, 20), 'moveWindow(ghost)');
      await assertOpRejected(() => comp.resizeWindow(ghostId, 400, 300), 'resizeWindow(ghost)');
      await assertOpRejected(() => comp.focusWindow(ghostId), 'focusWindow(ghost)');
      await assertOpRejected(() => comp.setWindowState(ghostId, 'maximized'), 'setWindowState(ghost)');
      await assertOpRejected(() => comp.closeWindow(ghostId), 'closeWindow(ghost)');
      await assertOpRejected(() => comp.dispatchInput(ghostId, { type: 'click', nodeId: 'b1' }), 'dispatchInput(ghost)');
      await assertOpRejected(() => comp.updateSurface(ghostId, { title: 'Ghost' }), 'updateSurface(ghost)');

      // Create & close a temporary window, then reject post-close operations
      const tempCreated = await comp.createWindow(1, {
        appId: `com.comp.temp.${tok}`,
        platform: 'windows',
        title: `Temp-${tok}`,
        width: 300,
        height: 200,
        x: 10,
        y: 10,
      });
      const tempWinId = getWinId(tempCreated);
      assert.ok(tempWinId !== null && tempWinId !== undefined);
      await comp.closeWindow(tempWinId);
      assert.equal(findWindow(comp.getSnapshot(), tempWinId), null, 'Closed temp window must disappear from snapshot');

      await assertOpRejected(() => comp.moveWindow(tempWinId, 20, 30), 'moveWindow(closed)');
      await assertOpRejected(() => comp.updateSurface(tempWinId, { title: 'Zombie' }), 'updateSurface(closed)');
      await assertOpRejected(() => comp.focusWindow(tempWinId), 'focusWindow(closed)');

      // Live window remains intact with flat/nested bounds & surface preserved
      const liveWin = findWindow(comp.getSnapshot(), liveWinId);
      assert.ok(liveWin, 'Healthy live window must remain intact in snapshot');
      assert.equal(liveWin.title, `Live-${tok}`);
      const bounds = getBounds(liveWin);
      assert.equal(bounds.width, 520);
      assert.equal(bounds.height, 360);
      assert.ok(getUiTree(liveWin), 'Live window uiTree must remain preserved');
      assert.ok(Array.isArray(getDrawOps(liveWin)) && getDrawOps(liveWin).length >= 1, 'Live window drawOps must remain preserved');
      assertCompositorHealthy(os);
    } finally {
      await os?.shutdown();
    }
  });

  test('T2 [F-029]: Negative, zero, NaN & Infinity window dimensions clamping or rejection', async () => {
    const tok = makeToken();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const comp = os.require('compositor');

      const created = await comp.createWindow(1, {
        appId: `com.comp.dim.${tok}`,
        platform: 'windows',
        title: `Dim-${tok}`,
        width: 500,
        height: 400,
        x: 20,
        y: 20,
      });
      const winId = getWinId(created);
      assert.ok(winId !== null);

      const badDims = [
        [0, 0],
        [-200, -150],
        [0, 300],
        [400, -50],
        [Number.NaN, Number.POSITIVE_INFINITY],
      ];

      for (const [w, h] of badDims) {
        let resizeErr = null;
        try {
          await comp.resizeWindow(winId, w, h);
        } catch (err) {
          resizeErr = err;
        }
        if (resizeErr) {
          assert.ok(resizeErr instanceof Error && resizeErr.message.length > 0);
        }
        const snapWin = findWindow(comp.getSnapshot(), winId);
        assert.ok(snapWin, 'Window must still exist after invalid resize attempt');
        const b = getBounds(snapWin);
        assert.ok(
          Number.isFinite(b.width) && b.width > 0 && Number.isFinite(b.height) && b.height > 0,
          `After resizeWindow(${w}, ${h}), bounds MUST remain strictly positive & finite (got ${JSON.stringify(b)})`
        );
      }

      // createWindow with negative/zero dimensions -> either rejects OR clamps to strictly positive finite bounds
      let negCreated = null;
      let negCreateErr = null;
      try {
        negCreated = await comp.createWindow(1, {
          appId: `com.comp.neg.${tok}`,
          platform: 'windows',
          title: `Neg-${tok}`,
          width: -100,
          height: 0,
          x: 0,
          y: 0,
        });
      } catch (err) {
        negCreateErr = err;
      }
      if (negCreateErr) {
        assert.ok(negCreateErr instanceof Error && negCreateErr.message.length > 0);
      }
      if (negCreated) {
        const negId = getWinId(negCreated);
        const snapNeg = findWindow(comp.getSnapshot(), negId);
        assert.ok(snapNeg);
        const nb = getBounds(snapNeg);
        assert.ok(
          Number.isFinite(nb.width) && nb.width > 0 && Number.isFinite(nb.height) && nb.height > 0,
          `Clamped createWindow(-100, 0) must have strictly positive finite bounds (got ${JSON.stringify(nb)})`
        );
        await comp.closeWindow(negId);
      }

      // Valid resize afterwards works cleanly
      await comp.resizeWindow(winId, 640, 480);
      const finalBounds = getBounds(findWindow(comp.getSnapshot(), winId));
      assert.equal(finalBounds.width, 640);
      assert.equal(finalBounds.height, 480);
      assertCompositorHealthy(os);
    } finally {
      await os?.shutdown();
    }
  });

  test('T3 [F-029]: Invalid setWindowState("bogus-state") rejection & prior state preservation', async () => {
    const tok = makeToken();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const comp = os.require('compositor');

      const winId = getWinId(await comp.createWindow(1, {
        appId: `com.comp.state.${tok}`,
        platform: 'windows',
        title: `State-${tok}`,
        width: 480,
        height: 320,
        x: 30,
        y: 30,
      }));
      assert.ok(winId !== null);

      await comp.setWindowState(winId, 'maximized');
      assert.equal(findWindow(comp.getSnapshot(), winId)?.state, 'maximized', 'Pre-condition: window must enter maximized state');

      for (const badState of ['bogus-state', '', null, 'snapped-diagonal', 12345]) {
        await assertOpRejected(
          () => comp.setWindowState(winId, badState),
          `setWindowState(${JSON.stringify(badState)})`
        );
        assert.equal(
          findWindow(comp.getSnapshot(), winId)?.state,
          'maximized',
          `Invalid state ${JSON.stringify(badState)} must preserve prior "maximized" state`
        );
      }

      await comp.setWindowState(winId, 'normal');
      assert.equal(findWindow(comp.getSnapshot(), winId)?.state, 'normal', 'Valid state transition to "normal" must succeed');
      assertCompositorHealthy(os);
    } finally {
      await os?.shutdown();
    }
  });

  test('T4 [F-029]: Closing focused window shifts focus cleanly & clears focusedWindowId when last window closes', async () => {
    const tok = makeToken();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const comp = os.require('compositor');

      // Close any pre-existing windows so "last window closes" tests an empty compositor cleanly
      for (const existing of extractArrayStrict(comp.getSnapshot(), ['windows']) ?? []) {
        const eid = getWinId(existing);
        if (eid !== null && eid !== undefined) {
          try { await comp.closeWindow(eid); } catch { /* ignore */ }
        }
      }

      const w1 = getWinId(await comp.createWindow(1, {
        appId: `com.focus.w1.${tok}`,
        platform: 'macos',
        title: `W1-${tok}`,
        width: 400,
        height: 300,
        x: 10,
        y: 10,
        menuBar: [{ label: `M1-${tok}`, items: [{ id: 'a1', label: 'A1' }] }],
      }));
      const w2 = getWinId(await comp.createWindow(1, {
        appId: `com.focus.w2.${tok}`,
        platform: 'macos',
        title: `W2-${tok}`,
        width: 400,
        height: 300,
        x: 30,
        y: 30,
        menuBar: [{ label: `M2-${tok}`, items: [{ id: 'a2', label: 'A2' }] }],
      }));
      const w3 = getWinId(await comp.createWindow(1, {
        appId: `com.focus.w3.${tok}`,
        platform: 'macos',
        title: `W3-${tok}`,
        width: 400,
        height: 300,
        x: 50,
        y: 50,
        menuBar: [{ label: `M3-${tok}`, items: [{ id: 'a3', label: 'A3' }] }],
      }));

      await comp.focusWindow(w1);
      await comp.focusWindow(w2);
      await comp.focusWindow(w3);

      const snapBefore = comp.getSnapshot();
      assert.equal(snapBefore.focusedWindowId, w3, 'w3 must be focused');
      assert.ok(JSON.stringify(snapBefore.activeMenuBar ?? '').includes(`M3-${tok}`), 'activeMenuBar must reflect focused w3');
      const z1 = getZOrder(findWindow(snapBefore, w1));
      const z3 = getZOrder(findWindow(snapBefore, w3));
      if (typeof z1 === 'number' && typeof z3 === 'number') {
        assert.ok(z3 > z1, `Focused w3 z-order (${z3}) must be > w1 (${z1})`);
      }

      // Close focused w3 -> focus shifts cleanly to w2 or w1 and M3 disappears from activeMenuBar
      await comp.closeWindow(w3);
      const snapAfterW3 = comp.getSnapshot();
      assert.equal(findWindow(snapAfterW3, w3), null, 'Closed w3 must be removed');
      assert.notEqual(snapAfterW3.focusedWindowId, w3, 'focusedWindowId must not dangle on closed w3');
      assert.ok(
        snapAfterW3.focusedWindowId === w2 || snapAfterW3.focusedWindowId === w1,
        `Focus must shift to a remaining window (got ${snapAfterW3.focusedWindowId})`
      );
      assert.equal(
        JSON.stringify(snapAfterW3.activeMenuBar ?? '').includes(`M3-${tok}`),
        false,
        'Closed w3 menuBar must no longer remain active'
      );

      // Close remaining 2 windows -> 0 windows & null/undefined focusedWindowId
      await comp.closeWindow(w2);
      await comp.closeWindow(w1);
      const snapEmpty = comp.getSnapshot();
      const remaining = extractArrayStrict(snapEmpty, ['windows']);
      assert.ok(Array.isArray(remaining) && remaining.length === 0, 'All windows must be closed');
      assert.ok(
        snapEmpty.focusedWindowId === null || snapEmpty.focusedWindowId === undefined,
        `focusedWindowId must clear when last window closes (got ${JSON.stringify(snapEmpty.focusedWindowId)})`
      );
      assertCompositorHealthy(os);
    } finally {
      await os?.shutdown();
    }
  });

  test('T5 [F-011, F-029]: Per-process maxWindows sandbox quota enforcement & slot recovery', async () => {
    const tok = makeToken();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const comp = os.require('compositor');
      const pm = os.require('processManager');
      os.require('scheduler').stop();

      const pcb = pm.spawn({
        name: `win-quota-${tok}`,
        appId: `com.win.quota.${tok}`,
        platform: 'windows',
        arch: 'wasm',
        quotas: { maxWindows: 2 },
        executionContext: makeInputTrackingContext(),
      });
      const pcbOther = pm.spawn({
        name: `win-other-${tok}`,
        appId: `com.win.other.${tok}`,
        platform: 'windows',
        arch: 'wasm',
        executionContext: makeInputTrackingContext(),
      });

      const createdIds = [];
      try {
        const w1 = getWinId(await comp.createWindow(pcb.pid, {
          appId: `com.win.quota.${tok}`,
          platform: 'windows',
          title: `Q1-${tok}`,
          width: 300,
          height: 200,
          x: 10,
          y: 10,
        }));
        createdIds.push(w1);

        const w2 = getWinId(await comp.createWindow(pcb.pid, {
          appId: `com.win.quota.${tok}`,
          platform: 'windows',
          title: `Q2-${tok}`,
          width: 300,
          height: 200,
          x: 40,
          y: 40,
        }));
        createdIds.push(w2);

        // 3rd window for same PID MUST reject due to maxWindows: 2 quota!
        await assert.rejects(
          async () => comp.createWindow(pcb.pid, {
            appId: `com.win.quota.${tok}`,
            platform: 'windows',
            title: `Q3-${tok}`,
            width: 300,
            height: 200,
            x: 70,
            y: 70,
          }),
          (err) => err instanceof Error && err.message.length > 0,
          'Creating 3rd window when maxWindows=2 MUST reject with quota error'
        );

        const winsNow = extractArrayStrict(comp.getSnapshot(), ['windows']) ?? [];
        assert.equal(winsNow.filter((w) => w.pid === pcb.pid).length, 2, 'PID at maxWindows=2 must own exactly 2 windows');

        // Sibling PID is unaffected by pcb's window quota
        const wSib = getWinId(await comp.createWindow(pcbOther.pid, {
          appId: `com.win.other.${tok}`,
          platform: 'windows',
          title: `Sib-${tok}`,
          width: 300,
          height: 200,
          x: 100,
          y: 100,
        }));
        createdIds.push(wSib);
        assert.ok(wSib !== null, 'Sibling process must create windows cleanly while peer is at quota');

        // Closing w1 frees a quota slot -> w4 succeeds!
        await comp.closeWindow(w1);
        const w4 = getWinId(await comp.createWindow(pcb.pid, {
          appId: `com.win.quota.${tok}`,
          platform: 'windows',
          title: `Q4-${tok}`,
          width: 300,
          height: 200,
          x: 130,
          y: 130,
        }));
        createdIds.push(w4);
        assert.ok(w4 !== null, 'Closing window #1 must free quota slot so window #4 succeeds');
        assertCompositorHealthy(os);
      } finally {
        for (const id of createdIds) {
          if (id !== null && id !== undefined) {
            try { await comp.closeWindow(id); } catch { /* ignore */ }
          }
        }
        try { pm.kill(pcb.pid, 'SIGKILL'); } catch { /* ignore */ }
        try { pm.kill(pcbOther.pid, 'SIGKILL'); } catch { /* ignore */ }
      }
    } finally {
      await os?.shutdown();
    }
  });

  test('T6 [F-030, F-031]: Malformed dispatchInput safety & dead/killed owning process input isolation', async () => {
    const tok = makeToken();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const comp = os.require('compositor');
      const pm = os.require('processManager');
      os.require('scheduler').stop();

      const ctx = makeInputTrackingContext();
      const pcb = pm.spawn({
        name: `inp-iso-${tok}`,
        appId: `com.inp.iso.${tok}`,
        platform: 'ios',
        arch: 'wasm',
        executionContext: ctx,
      });

      let winId = null;
      try {
        winId = getWinId(await comp.createWindow(pcb.pid, {
          appId: `com.inp.iso.${tok}`,
          platform: 'ios',
          title: `Inp-${tok}`,
          width: 360,
          height: 600,
          x: 20,
          y: 20,
          uiTree: { id: 'root', type: 'view', children: [{ id: `alive-${tok}`, type: 'button', text: 'Tap' }] },
        }));
        assert.ok(winId !== null);

        // Malformed inputs (null, undefined, {}) must reject cleanly or safely ignore without crashing compositord
        for (const badEv of [null, undefined, {}]) {
          let badInputErr = null;
          try {
            await comp.dispatchInput(winId, badEv);
          } catch (err) {
            badInputErr = err;
          }
          if (badInputErr) {
            assert.ok(badInputErr instanceof Error && badInputErr.message.length > 0);
          }
        }
        assertCompositorHealthy(os);

        // Non-vacuous pre-condition: valid input DOES deliver while owning process is alive
        await comp.dispatchInput(winId, { type: 'click', nodeId: `alive-${tok}` });
        assert.ok(ctx.delivered.length >= 1, 'Valid input event must be delivered to live owning process');

        // Kill owning process -> zero further events may reach killed executionContext
        await pm.kill(pcb.pid, 'SIGKILL');
        const countAtKill = ctx.delivered.length;

        let postKillErr = null;
        try {
          await comp.dispatchInput(winId, { type: 'click', nodeId: 'after-kill' });
        } catch (err) {
          postKillErr = err;
        }
        if (postKillErr) {
          assert.ok(postKillErr instanceof Error && postKillErr.message.length > 0);
        }

        assert.equal(ctx.delivered.length, countAtKill, 'Killed process MUST NEVER receive subsequent compositor input events');
        assertCompositorHealthy(os);
      } finally {
        if (winId !== null) {
          try { await comp.closeWindow(winId); } catch { /* ignore */ }
        }
        try { pm.kill(pcb.pid, 'SIGKILL'); } catch { /* ignore */ }
      }
    } finally {
      await os?.shutdown();
    }
  });

  test('T7 [F-029, F-031, Contract 7]: Live REST /api/v1/compositor/windows/* non-vacuous 404 handling & invalid shell-mode 400 rejection', async () => {
    const tok = makeToken();
    let srv = null;
    const launchedPids = [];
    try {
      srv = await startOmniServer();
      const ghostId = `win-nonexistent-${tok}`;

      // 1. Valid shell-mode round-trip FIRST (404 || 405 positive verb & single-key schema discovery) -> proves route is wired!
      const initSnapRes = await srv.api.get('/api/v1/compositor/snapshot');
      assert.equal(initSnapRes.status, 200, `GET /api/v1/compositor/snapshot must return 200 (got ${initSnapRes.status})`);
      const initSnap = unwrapSnapshot(initSnapRes.json);
      const origMode = initSnap?.shellMode ?? 'unified';
      const targetValidMode = origMode === 'macos' ? 'windows' : 'macos';

      let shellModeMethod = null;
      let makeModeBody = (m) => ({ mode: m });
      let validModeRes = null;
      let afterValidSnap = null;
      for (const factory of [(m) => ({ mode: m }), (m) => ({ shellMode: m })]) {
        const probe = await discoverWorkingMethod(
          srv.api,
          ['POST', 'PUT', 'PATCH'],
          '/api/v1/compositor/shell-mode',
          factory(targetValidMode)
        );
        validModeRes = probe.res;
        if (probe.res.ok) {
          const snapCheck = unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot')).json);
          if (snapCheck?.shellMode === targetValidMode) {
            shellModeMethod = probe.method;
            makeModeBody = factory;
            afterValidSnap = snapCheck;
            break;
          }
        }
      }
      assert.ok(
        shellModeMethod !== null && validModeRes?.ok,
        `Pre-condition: valid /api/v1/compositor/shell-mode update to "${targetValidMode}" must succeed (last status=${validModeRes?.status}: ${validModeRes?.text})`
      );
      assert.equal(
        afterValidSnap?.shellMode,
        targetValidMode,
        `Snapshot shellMode must update to "${targetValidMode}" (got ${JSON.stringify(afterValidSnap?.shellMode)})`
      );

      // Invalid shell-mode using EXACT proven shellModeMethod & schema (ZERO fallback!) -> exact 400 or 422 (NEVER 404/405!)
      const bogusMode = `bogus-mode-${tok}`;
      const resMode = await srv.api.request(shellModeMethod, '/api/v1/compositor/shell-mode', {
        body: makeModeBody(bogusMode),
      });
      assert.ok(
        resMode.status === 400 || resMode.status === 422,
        `Invalid shell-mode via ${shellModeMethod} /api/v1/compositor/shell-mode must return HTTP 400 or 422 (got ${resMode.status}: ${resMode.text})`
      );
      const snapAfterBogus = unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot')).json);
      assert.equal(
        snapAfterBogus?.shellMode,
        targetValidMode,
        `Rejected shell-mode must preserve valid "${targetValidMode}" (got ${JSON.stringify(snapAfterBogus?.shellMode)})`
      );

      // Restore original shell mode cleanly
      await srv.api.request(shellModeMethod, '/api/v1/compositor/shell-mode', {
        body: makeModeBody(origMode),
      });

      // 2. Acquire a real live window dynamically via /api/v1/packages (fallback /api/v1/packages/catalog; zero hardcoded IDs!)
      const pkgsRes = await srv.api.get('/api/v1/packages');
      assert.equal(pkgsRes.status, 200, `GET /api/v1/packages must return 200 (got ${pkgsRes.status})`);
      let pkgs = extractArrayStrict(pkgsRes.json, ['packages', 'apps', 'items']) ?? [];
      if (pkgs.length === 0) {
        const catRes = await srv.api.get('/api/v1/packages/catalog');
        if (catRes.ok) {
          pkgs = extractArrayStrict(catRes.json, ['packages', 'catalog', 'apps', 'items']) ?? [];
        }
      }
      assert.ok(pkgs.length > 0, 'Pre-condition: booted OS must expose at least one launchable GUI app in /api/v1/packages or /catalog');

      const guiFirst = [
        ...pkgs.filter((p) => /notes|term|files|settings|monitor|apphub|inspector/i.test(`${p?.name ?? ''} ${p?.title ?? ''} ${p?.appId ?? p?.id ?? ''}`)),
        ...pkgs.filter((p) => !/notes|term|files|settings|monitor|apphub|inspector/i.test(`${p?.name ?? ''} ${p?.title ?? ''} ${p?.appId ?? p?.id ?? ''}`)),
      ];

      let liveWinId = null;
      for (const candidate of guiFirst.slice(0, 3)) {
        const appId = candidate?.appId ?? candidate?.id ?? candidate?.packageName;
        if (!appId) continue;
        const launchRes = await srv.api.post(`/api/v1/packages/${encodeURIComponent(appId)}/launch`, {});
        if (!launchRes.ok) continue;
        const lData = launchRes.json?.data ?? launchRes.json;
        const pid = lData?.pid ?? lData?.process?.pid;
        if (Number.isInteger(pid) && pid > 1) launchedPids.push(pid);
        const reportedIds = Array.isArray(lData?.windowIds) ? lData.windowIds : [];

        const deadline = Date.now() + 2000;
        while (Date.now() < deadline && liveWinId === null) {
          const s = unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot')).json);
          const wins = extractArrayStrict(s, ['windows']) ?? [];
          const match =
            wins.find((w) => reportedIds.includes(getWinId(w))) ??
            wins.find((w) => (pid && w?.pid === pid) || w?.appId === appId) ??
            null;
          if (match) {
            liveWinId = getWinId(match);
            break;
          }
          await sleep(50);
        }
        if (liveWinId !== null) break;
      }
      assert.ok(liveWinId !== null && liveWinId !== undefined, 'Pre-condition: launching a built-in app must open a live compositor window');

      // 3. Prove ALL 6 window mutation routes work on liveWinId (discover exact working verbs, close LAST!)
      const liveSpecs = [
        ['move', ['POST', 'PUT', 'PATCH'], { x: 90, y: 80 }],
        ['resize', ['POST', 'PUT', 'PATCH'], { width: 520, height: 360 }],
        ['focus', ['POST', 'PUT'], {}],
        ['state', ['POST', 'PUT', 'PATCH'], { state: 'maximized' }],
        ['input', ['POST'], { type: 'keydown', key: 'a' }],
        ['close', ['POST', 'DELETE'], {}],
      ];
      const provenVerbs = new Map();
      for (const [action, methods, body] of liveSpecs) {
        const { method, res } = await discoverWorkingMethod(
          srv.api,
          methods,
          `/api/v1/compositor/windows/${encodeURIComponent(String(liveWinId))}/${action}`,
          body
        );
        assert.ok(
          res.ok,
          `Pre-condition: live window mutation /api/v1/compositor/windows/${liveWinId}/${action} must succeed (got ${res.status}: ${res.text})`
        );
        provenVerbs.set(action, method);
      }

      const afterCloseSnap = unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot')).json);
      assert.equal(findWindow(afterCloseSnap, liveWinId), null, 'Pre-condition: live window must be removed after REST close');

      // 4. Test ALL 6 nonexistent-window routes using EXACT proven verbs (ZERO fallback!) -> exact HTTP 404
      const ghostSpecs = [
        ['move', { x: 10, y: 20 }],
        ['resize', { width: 300, height: 200 }],
        ['focus', {}],
        ['state', { state: 'maximized' }],
        ['input', { type: 'click', nodeId: 'b1' }],
        ['close', {}],
      ];
      for (const [action, body] of ghostSpecs) {
        const method = provenVerbs.get(action);
        const res = await srv.api.request(
          method,
          `/api/v1/compositor/windows/${encodeURIComponent(ghostId)}/${action}`,
          method === 'DELETE' ? {} : { body }
        );
        assert.equal(
          res.status,
          404,
          `REST ${method} /api/v1/compositor/windows/nonexistent/${action} MUST return exact HTTP 404 (got ${res.status}: ${res.text})`
        );
      }

      const health = await srv.api.get('/api/health');
      assert.equal(health.status, 200);
      assert.equal(health.json?.ok, true);
    } finally {
      if (srv) {
        for (const pid of launchedPids) {
          try { await srv.api.post(`/api/v1/processes/${pid}/signal`, { signal: 'SIGKILL' }); } catch { /* ignore */ }
        }
      }
      await srv?.stop();
    }
  });
});
