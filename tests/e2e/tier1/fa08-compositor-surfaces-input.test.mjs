/**
 * Tier 1 E2E Tests — FA-08: Headless Window Compositor, Dual Surfaces & Input Routing
 * Features covered: F-029, F-030, F-031
 * Contracts: Contract 6 (ICompositor), Contract 7 (REST /api/v1/compositor/* & RFC 6455 WS /ws)
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

function makeToken() {
  return crypto.randomBytes(4).toString('hex');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitUntil(fn, { timeoutMs = 5000, intervalMs = 40, label = 'condition' } = {}) {
  const deadline = Date.now() + timeoutMs;
  let lastErr = null;
  while (Date.now() < deadline) {
    try {
      const val = await fn();
      if (val) return val;
    } catch (err) {
      lastErr = err;
    }
    await sleep(intervalMs);
  }
  throw new Error(`Timed out after ${timeoutMs}ms waiting for ${label}${lastErr ? `: ${lastErr.message}` : ''}`);
}

function getWinId(win) {
  const id = win?.windowId ?? win?.id;
  assert.ok(typeof id === 'string' && id.length > 0, `Expected non-empty string windowId, got ${JSON.stringify(win)}`);
  return id;
}

function getBounds(win) {
  const b = win?.bounds ?? win;
  assert.ok(b && typeof b === 'object', `Window missing bounds: ${JSON.stringify(win)}`);
  return {
    x: b.x,
    y: b.y,
    width: b.width ?? b.w,
    height: b.height ?? b.h,
  };
}

function unwrapSnapshot(payload) {
  if (!payload || typeof payload !== 'object') return payload;
  if (Array.isArray(payload.windows)) return payload;
  if (payload.snapshot && typeof payload.snapshot === 'object') return payload.snapshot;
  if (payload.data && typeof payload.data === 'object') return payload.data;
  if (payload.payload && typeof payload.payload === 'object') return payload.payload;
  return payload;
}

function findWindow(snapshot, winId) {
  const wins = snapshot?.windows ?? [];
  return wins.find((w) => (w?.windowId ?? w?.id) === winId) ?? null;
}

function unwrapList(payload, keys = ['packages', 'windows', 'items', 'data']) {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== 'object') return [];
  for (const key of keys) {
    if (Array.isArray(payload[key])) return payload[key];
  }
  return [];
}

function assertWindowRaisedAbove(snap, topWinId, belowWinId, contextMsg) {
  const wins = snap?.windows ?? [];
  const topIdx = wins.findIndex((w) => (w?.windowId ?? w?.id) === topWinId);
  const belowIdx = wins.findIndex((w) => (w?.windowId ?? w?.id) === belowWinId);
  assert.ok(topIdx >= 0 && belowIdx >= 0, `${contextMsg}: both windows must exist in snapshot`);
  const wTop = wins[topIdx];
  const wBelow = wins[belowIdx];
  const zTop = wTop.zIndex ?? wTop.zOrder ?? wTop.z;
  const zBelow = wBelow.zIndex ?? wBelow.zOrder ?? wBelow.z;
  if (typeof zTop === 'number' && typeof zBelow === 'number') {
    assert.ok(zTop > zBelow, `${contextMsg}: focused window z-order (${zTop}) must exceed lower window (${zBelow})`);
  } else {
    assert.ok(
      topIdx > belowIdx,
      `${contextMsg}: focused window index (${topIdx}) must appear above lower window (${belowIdx})`
    );
  }
  if (typeof wTop.focused === 'boolean') {
    assert.equal(wTop.focused, true, `${contextMsg}: focused window must have focused === true when boolean is present`);
  }
  if (typeof wBelow.focused === 'boolean') {
    assert.equal(wBelow.focused, false, `${contextMsg}: unfocused window must have focused === false when boolean is present`);
  }
}

async function restAction(api, urlPath, body, { allowDelete = false } = {}) {
  let res = await api.post(urlPath, body);
  if (res.status === 404 || res.status === 405) {
    res = await api.put(urlPath, body);
  }
  if (res.status === 404 || res.status === 405) {
    res = await api.patch(urlPath, body);
  }
  if (allowDelete && (res.status === 404 || res.status === 405)) {
    res = await api.delete(urlPath);
  }
  return res;
}

async function launchSystemWindowApp(api) {
  let launchRes = await api.post('/api/v1/packages/sys.notes/launch', {});
  let appId = 'sys.notes';
  if (!launchRes.ok) {
    appId = 'sys.terminal';
    launchRes = await api.post('/api/v1/packages/sys.terminal/launch', {});
  }
  if (!launchRes.ok) {
    const pkgRes = await api.get('/api/v1/packages');
    const pkgs = [
      ...unwrapList(pkgRes.json, ['packages', 'windows', 'items', 'data']),
      ...unwrapList(pkgRes.json, ['systemApps']),
    ];
    const sysPkg = pkgs.find((p) => String(p.appId ?? p.id).startsWith('sys.')) ?? pkgs[0];
    assert.ok(sysPkg, 'Expected at least one built-in system app in /api/v1/packages');
    appId = sysPkg.appId ?? sysPkg.id;
    launchRes = await api.post(`/api/v1/packages/${encodeURIComponent(appId)}/launch`, {});
  }
  assert.ok(launchRes.ok, `Failed launching built-in system app ${appId} (${launchRes.status}): ${launchRes.text}`);
  const body = launchRes.json?.data ?? launchRes.json;
  return { appId, pid: body?.pid, windowIds: body?.windowIds ?? [] };
}

describe('Tier 1 — FA-08: Headless Window Compositor, Dual Surfaces & Input Routing', () => {
  test('T1 [F-029]: Compositor window lifecycle createWindow, moveWindow, resizeWindow, getSnapshot & closeWindow', async () => {
    const os = await loadPublicOmniOS();
    try {
      const comp = os.require('compositor');
      const tok = makeToken();

      const win = comp.createWindow(1, {
        appId: `com.test.w.${tok}`,
        platform: 'windows',
        title: `Title ${tok}`,
        icon: 'doc',
        width: 640,
        height: 400,
        x: 50,
        y: 70,
        chromeStyle: 'windows',
        uiTree: { type: 'window', id: 'root', children: [] },
        drawOps: [],
      });
      const winId = getWinId(win);

      comp.moveWindow(winId, 180, 125);
      const snapAfterMove = comp.getSnapshot();
      const movedWin = findWindow(snapAfterMove, winId);
      assert.ok(movedWin, 'Created window must appear in compositor.getSnapshot().windows');
      assert.equal(getBounds(movedWin).x, 180);
      assert.equal(getBounds(movedWin).y, 125);

      comp.resizeWindow(winId, 860, 540);
      const snapAfterResize = comp.getSnapshot();
      const resizedWin = findWindow(snapAfterResize, winId);
      assert.equal(getBounds(resizedWin).width, 860);
      assert.equal(getBounds(resizedWin).height, 540);

      // Snapshot shape validation per Contract 6
      assert.equal(typeof snapAfterResize.shellMode, 'string');
      assert.ok('focusedWindowId' in snapAfterResize, 'Snapshot must include focusedWindowId');
      assert.ok('activeMenuBar' in snapAfterResize, 'Snapshot must include activeMenuBar');
      assert.ok(Array.isArray(snapAfterResize.windows), 'Snapshot must include windows array');

      comp.closeWindow(winId);
      assert.equal(findWindow(comp.getSnapshot(), winId), null, 'Closed window must be removed from compositor snapshot');
    } finally {
      await os.shutdown();
    }
  });

  test('T2 [F-029]: Multi-window focusWindow z-order raising and active Global Menu Bar switching', async () => {
    const os = await loadPublicOmniOS();
    try {
      const comp = os.require('compositor');
      const tok = makeToken();

      const winMac = comp.createWindow(1, {
        appId: `com.mac.studio.${tok}`,
        platform: 'macos',
        title: `MacStudio ${tok}`,
        width: 600,
        height: 400,
        x: 20,
        y: 40,
        chromeStyle: 'macos',
        menuBar: [{ id: 'studio', label: `MacMenu-${tok}`, items: [{ id: 'm.new', label: 'New' }] }],
        uiTree: { type: 'window', id: 'mac-root', children: [] },
        drawOps: [],
      });
      const winWin = comp.createWindow(1, {
        appId: `com.win.pad.${tok}`,
        platform: 'windows',
        title: `WinPad ${tok}`,
        width: 600,
        height: 400,
        x: 80,
        y: 90,
        chromeStyle: 'windows',
        menuBar: [{ id: 'file', label: `WinMenu-${tok}`, items: [{ id: 'w.open', label: 'Open' }] }],
        uiTree: { type: 'window', id: 'win-root', children: [] },
        drawOps: [],
      });
      const idMac = getWinId(winMac);
      const idWin = getWinId(winWin);

      // Focus macOS window -> raised above Windows window & Global Menu Bar updates
      comp.focusWindow(idMac);
      const snap1 = comp.getSnapshot();
      assert.equal(snap1.focusedWindowId, idMac, 'Snapshot focusedWindowId must update to macOS window');
      assertWindowRaisedAbove(snap1, idMac, idWin, 'After focusing macOS window');
      assert.ok(
        JSON.stringify(snap1.activeMenuBar).includes(`MacMenu-${tok}`),
        `activeMenuBar must switch to MacMenu-${tok}, got ${JSON.stringify(snap1.activeMenuBar)}`
      );

      // Focus Windows window -> raised above macOS window & Global Menu Bar updates
      comp.focusWindow(idWin);
      const snap2 = comp.getSnapshot();
      assert.equal(snap2.focusedWindowId, idWin, 'Snapshot focusedWindowId must update to Windows window');
      assertWindowRaisedAbove(snap2, idWin, idMac, 'After focusing Windows window');
      assert.ok(
        JSON.stringify(snap2.activeMenuBar).includes(`WinMenu-${tok}`),
        `activeMenuBar must switch to WinMenu-${tok}, got ${JSON.stringify(snap2.activeMenuBar)}`
      );

      comp.closeWindow(idMac);
      comp.closeWindow(idWin);
    } finally {
      await os.shutdown();
    }
  });

  test('T3 [F-029]: Window states & all 6 Windows Snap Layouts (snapped-left/right/tl/tr/bl/br)', async () => {
    const os = await loadPublicOmniOS();
    try {
      const comp = os.require('compositor');
      const tok = makeToken();

      const win = comp.createWindow(1, {
        appId: `com.snap.test.${tok}`,
        platform: 'windows',
        title: `Snap ${tok}`,
        width: 500,
        height: 350,
        x: 40,
        y: 40,
        uiTree: { type: 'window', id: 'snap-root', children: [] },
        drawOps: [],
      });
      const winId = getWinId(win);

      const states = [
        'minimized',
        'maximized',
        'normal',
        'snapped-left',
        'snapped-right',
        'snapped-tl',
        'snapped-tr',
        'snapped-bl',
        'snapped-br',
        'fullscreen',
        'normal',
      ];

      const recorded = new Map();
      for (const st of states) {
        comp.setWindowState(winId, st);
        const w = findWindow(comp.getSnapshot(), winId);
        assert.ok(w, `Window disappeared after setWindowState("${st}")`);
        assert.equal(w.state, st, `Expected window state "${st}", got "${w.state}"`);
        const b = getBounds(w);
        assert.ok(
          Number.isFinite(b.x) && Number.isFinite(b.y) && Number.isFinite(b.width) && Number.isFinite(b.height),
          `Window bounds must remain finite in state "${st}": ${JSON.stringify(b)}`
        );
        recorded.set(st, b);
      }

      // Strict snap geometry checks (non-moving compositor must fail)
      const leftB = recorded.get('snapped-left');
      const rightB = recorded.get('snapped-right');
      assert.ok(rightB.x > leftB.x, `snapped-right.x (${rightB.x}) must be strictly > snapped-left.x (${leftB.x})`);

      const tlB = recorded.get('snapped-tl');
      const trB = recorded.get('snapped-tr');
      const blB = recorded.get('snapped-bl');
      const brB = recorded.get('snapped-br');
      assert.ok(trB.x > tlB.x, `snapped-tr.x (${trB.x}) must be strictly > snapped-tl.x (${tlB.x})`);
      assert.ok(blB.y > tlB.y, `snapped-bl.y (${blB.y}) must be strictly > snapped-tl.y (${tlB.y})`);
      assert.ok(
        brB.x > tlB.x && brB.y > tlB.y,
        `snapped-br (${brB.x},${brB.y}) must be strictly > snapped-tl (${tlB.x},${tlB.y})`
      );
      assert.ok(
        brB.x > blB.x && brB.y > trB.y,
        `snapped-br (${brB.x},${brB.y}) must be right of snapped-bl (${blB.x}) and below snapped-tr (${trB.y})`
      );
      const quadrantOrigins = new Set([tlB, trB, blB, brB].map((b) => `${b.x},${b.y}`));
      assert.equal(
        quadrantOrigins.size,
        4,
        `All 4 snap quadrants must resolve to 4 distinct (x,y) coordinates, got ${JSON.stringify([tlB, trB, blB, brB])}`
      );

      comp.closeWindow(winId);
    } finally {
      await os.shutdown();
    }
  });

  test('T4 [F-030]: Dual-mode surface engine (uiTree + drawOps + appendDrawOps) and monotonic surfaceRevision', async () => {
    const os = await loadPublicOmniOS();
    try {
      const comp = os.require('compositor');
      const tok = makeToken();

      const win = comp.createWindow(1, {
        appId: `com.surface.test.${tok}`,
        platform: 'universal',
        title: `SurfaceInit ${tok}`,
        width: 500,
        height: 400,
        x: 30,
        y: 30,
        uiTree: { type: 'vstack', id: 'root', children: [{ type: 'text', id: 't0', text: 'Init' }] },
        drawOps: [{ op: 'clear', color: '#111111' }],
      });
      const winId = getWinId(win);

      const getSurfaceRev = (w) => w?.surfaceRevision ?? w?.surface?.surfaceRevision ?? w?.surface?.revision;

      const rev0 = getSurfaceRev(findWindow(comp.getSnapshot(), winId)) ?? 0;
      assert.equal(typeof rev0, 'number');

      // 1. Update title + retained semantic uiTree
      comp.updateSurface(winId, {
        title: `Updated ${tok}`,
        uiTree: {
          type: 'vstack',
          id: 'v',
          children: [{ type: 'heading', id: 'h', text: `Tree-${tok}` }],
        },
      });
      const w1 = findWindow(comp.getSnapshot(), winId);
      const rev1 = getSurfaceRev(w1);
      assert.equal(typeof rev1, 'number', `Expected numeric surfaceRevision after uiTree update, got ${JSON.stringify(rev1)}`);
      assert.ok(rev1 > rev0, `surfaceRevision must strictly increase after uiTree update (${rev0} -> ${rev1})`);
      assert.equal(w1.title, `Updated ${tok}`);

      // 2. Replace drawOps
      comp.updateSurface(winId, {
        drawOps: [{ op: 'fillRect', x: 0, y: 0, w: 120, h: 60, color: '#2255ff' }],
      });
      const w2 = findWindow(comp.getSnapshot(), winId);
      const rev2 = getSurfaceRev(w2);
      assert.equal(typeof rev2, 'number', `Expected numeric surfaceRevision after drawOps update, got ${JSON.stringify(rev2)}`);
      assert.ok(rev2 > rev1, `surfaceRevision must strictly increase after drawOps update (${rev1} -> ${rev2})`);

      // 3. Append additional drawOps while retaining uiTree and previous drawOps
      comp.updateSurface(winId, {
        appendDrawOps: [
          { op: 'drawText', x: 8, y: 20, text: `Op-${tok}`, color: '#ffffff' },
          { op: 'fillCircle', cx: 40, cy: 40, r: 10, color: '#00ff00' },
        ],
      });
      const w3 = findWindow(comp.getSnapshot(), winId);
      const rev3 = getSurfaceRev(w3);
      assert.equal(typeof rev3, 'number', `Expected numeric surfaceRevision after appendDrawOps, got ${JSON.stringify(rev3)}`);
      assert.ok(rev3 > rev2, `surfaceRevision must strictly increase after appendDrawOps (${rev2} -> ${rev3})`);

      const uiTree = w3.uiTree ?? w3.surface?.uiTree;
      const drawOps = w3.drawOps ?? w3.surface?.drawOps;
      assert.ok(
        uiTree && typeof uiTree === 'object',
        `Window must expose retained uiTree (flat or under window.surface), got ${JSON.stringify(w3)}`
      );
      assert.ok(
        JSON.stringify(uiTree).includes(`Tree-${tok}`),
        'Retained uiTree must be preserved across drawOps updates'
      );
      assert.ok(
        Array.isArray(drawOps) && drawOps.length === 3,
        `Expected 3 ordered drawOps (flat or under window.surface), got ${JSON.stringify(drawOps)}`
      );
      assert.equal(drawOps[0].op, 'fillRect');
      assert.equal(drawOps[1].op, 'drawText');
      assert.equal(drawOps[1].text, `Op-${tok}`);
      assert.equal(drawOps[2].op, 'fillCircle');

      comp.closeWindow(winId);
    } finally {
      await os.shutdown();
    }
  });

  test('T5 [F-031]: Input Event Router delivering all 6 event types to owning process ExecutionContext.deliverEvent()', async () => {
    const os = await loadPublicOmniOS();
    try {
      const pm = os.require('processManager');
      const comp = os.require('compositor');
      os.require('scheduler').stop?.();
      const tok = makeToken();

      const received = [];
      const execCtx = {
        step() {
          return { status: 'YIELD', instructionsExecuted: 1 };
        },
        deliverEvent(ev) {
          received.push(ev);
        },
        getDebugState() {
          return { arch: 'test', pc: 0, sp: 0x1000, registers: {}, instructionsExecuted: 0, lastSyscall: null, stackTop: 0x1000 };
        },
        dispose() {},
      };

      const pcb = pm.spawn({
        name: `input-target-${tok}`,
        appId: `com.input.test.${tok}`,
        platform: 'universal',
        arch: 'wasm',
        uid: 1000,
        gid: 1000,
        executionContext: execCtx,
      });

      const win = comp.createWindow(pcb.pid, {
        appId: `com.input.test.${tok}`,
        platform: 'universal',
        title: `InputWin ${tok}`,
        width: 480,
        height: 320,
        x: 50,
        y: 50,
        uiTree: { type: 'window', id: 'root', children: [] },
        drawOps: [],
      });
      const winId = getWinId(win);

      const eventsToSend = [
        { type: 'click', nodeId: 'btn1' },
        { type: 'action', nodeId: 'act1', value: tok },
        { type: 'input', nodeId: 'inp1', value: `txt-${tok}` },
        { type: 'keydown', key: 'Enter' },
        { type: 'canvas_pointer', x: 75, y: 42 },
        { type: 'menu_action', menuItemId: 'file.save' },
      ];

      for (const ev of eventsToSend) {
        await comp.dispatchInput(winId, ev);
      }

      assert.ok(received.length >= 6, `Expected >= 6 routed input events, received ${received.length}`);
      const hasMatch = (pred) => received.some((r) => pred(r?.event ?? r));

      assert.ok(hasMatch((e) => e?.type === 'click' && e?.nodeId === 'btn1'), 'click event must arrive with nodeId');
      assert.ok(hasMatch((e) => e?.type === 'action' && e?.nodeId === 'act1' && e?.value === tok), 'action event must arrive with value');
      assert.ok(hasMatch((e) => e?.type === 'input' && e?.nodeId === 'inp1' && e?.value === `txt-${tok}`), 'input event must arrive with text');
      assert.ok(hasMatch((e) => e?.type === 'keydown' && e?.key === 'Enter'), 'keydown event must arrive with key');
      assert.ok(hasMatch((e) => e?.type === 'canvas_pointer' && e?.x === 75 && e?.y === 42), 'canvas_pointer must arrive with coordinates');
      assert.ok(hasMatch((e) => e?.type === 'menu_action' && e?.menuItemId === 'file.save'), 'menu_action must arrive with menuItemId');

      comp.closeWindow(winId);
      pm.kill(pcb.pid, 'SIGTERM');
    } finally {
      await os.shutdown();
    }
  });

  test('T6 [F-029, F-031, Contract 7]: Live HTTP REST /api/v1/compositor/* (snapshot, shell-mode, move, resize, state, focus, input, close)', async () => {
    const srv = await startOmniServer();
    try {
      const launched = await launchSystemWindowApp(srv.api);

      const winId = await waitUntil(async () => {
        const snapRes = await srv.api.get('/api/v1/compositor/snapshot');
        if (snapRes.status !== 200) return null;
        const snap = unwrapSnapshot(snapRes.json);
        const wins = snap?.windows ?? [];
        const match =
          wins.find((w) => launched.windowIds.includes(w.windowId ?? w.id)) ??
          wins.find((w) => w.pid === launched.pid || w.appId === launched.appId) ??
          wins[wins.length - 1];
        return match ? (match.windowId ?? match.id) : null;
      }, { label: 'launched system app window in compositor snapshot' });

      // 1. Switch shell mode
      const modeRes = await restAction(srv.api, '/api/v1/compositor/shell-mode', { mode: 'macos', shellMode: 'macos' });
      assert.ok(modeRes.ok, `Updating /api/v1/compositor/shell-mode failed (${modeRes.status}): ${modeRes.text}`);
      const snapMode = unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot')).json);
      assert.equal(snapMode.shellMode, 'macos');

      // 2. Move window
      const moveRes = await restAction(srv.api, `/api/v1/compositor/windows/${encodeURIComponent(winId)}/move`, { x: 140, y: 110 });
      assert.ok(moveRes.ok, `move failed (${moveRes.status}): ${moveRes.text}`);
      const movedWin = findWindow(unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot')).json), winId);
      assert.equal(getBounds(movedWin).x, 140);
      assert.equal(getBounds(movedWin).y, 110);

      // 3. Resize window
      const resizeRes = await restAction(srv.api, `/api/v1/compositor/windows/${encodeURIComponent(winId)}/resize`, { width: 720, height: 460 });
      assert.ok(resizeRes.ok, `resize failed (${resizeRes.status}): ${resizeRes.text}`);
      const resizedWin = findWindow(unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot')).json), winId);
      assert.equal(getBounds(resizedWin).width, 720);
      assert.equal(getBounds(resizedWin).height, 460);

      // 4. Snap state
      const stateRes = await restAction(srv.api, `/api/v1/compositor/windows/${encodeURIComponent(winId)}/state`, { state: 'snapped-right' });
      assert.ok(stateRes.ok, `state failed (${stateRes.status}): ${stateRes.text}`);
      const snappedWin = findWindow(unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot')).json), winId);
      assert.equal(snappedWin.state, 'snapped-right');

      // 5. Focus window
      const focusRes = await restAction(srv.api, `/api/v1/compositor/windows/${encodeURIComponent(winId)}/focus`, {});
      assert.ok(focusRes.ok, `focus failed (${focusRes.status}): ${focusRes.text}`);
      const focusedSnap = unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot')).json);
      assert.equal(focusedSnap.focusedWindowId, winId);

      // 6. Dispatch input
      const inputRes = await restAction(srv.api, `/api/v1/compositor/windows/${encodeURIComponent(winId)}/input`, {
        type: 'keydown',
        key: 'x',
      });
      assert.ok(inputRes.ok, `input failed (${inputRes.status}): ${inputRes.text}`);

      // 7. Close window
      let closeRes = await restAction(srv.api, `/api/v1/compositor/windows/${encodeURIComponent(winId)}/close`, {}, { allowDelete: true });
      if (closeRes.status === 404 || closeRes.status === 405) {
        closeRes = await srv.api.delete(`/api/v1/compositor/windows/${encodeURIComponent(winId)}`);
      }
      assert.ok(closeRes.ok, `close failed (${closeRes.status}): ${closeRes.text}`);
      const afterCloseSnap = unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot')).json);
      assert.equal(findWindow(afterCloseSnap, winId), null, 'Closed window must be removed from REST snapshot');
    } finally {
      await srv.stop();
    }
  });

  test('T7 [F-029, F-030, F-031, Contract 7]: Live RFC 6455 WebSocket /ws compositor event stream and client control commands', async () => {
    const srv = await startOmniServer();
    let ws = null;
    try {
      ws = await srv.connectWs();

      // Initial compositor:snapshot arrives upon connection
      const initSnap = await ws.waitForType('compositor:snapshot', { since: 0, timeoutMs: 5000 });
      assert.equal(initSnap.type, 'compositor:snapshot');

      // Launching a system app emits compositor:window_created
      const m1 = ws.mark();
      await launchSystemWindowApp(srv.api);
      const createdEv = await ws.waitForType('compositor:window_created', { since: m1, timeoutMs: 5000 });
      const createdPayload = createdEv.payload?.window ?? createdEv.payload ?? createdEv;
      const winId = getWinId(createdPayload);

      // Client -> Server compositor:move updates window position
      const m2 = ws.mark();
      ws.send({
        type: 'compositor:move',
        payload: { windowId: winId, x: 220, y: 160 },
      });

      const updatedEv = await ws.waitForType('compositor:window_updated', { since: m2, timeoutMs: 5000 });
      assert.equal(updatedEv.type, 'compositor:window_updated');

      const snapAfterMove = unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot')).json);
      const moved = findWindow(snapAfterMove, winId);
      assert.ok(moved, 'Window must still exist after compositor:move');
      assert.equal(getBounds(moved).x, 220);
      assert.equal(getBounds(moved).y, 160);

      // Client -> Server compositor:close emits compositor:window_closed and removes window
      const m3 = ws.mark();
      ws.send({
        type: 'compositor:close',
        payload: { windowId: winId },
      });

      const closedEv = await ws.waitForType('compositor:window_closed', { since: m3, timeoutMs: 5000 });
      assert.equal(closedEv.type, 'compositor:window_closed');
      assert.ok(JSON.stringify(closedEv).includes(winId), 'compositor:window_closed must identify the closed windowId');

      const snapAfterClose = unwrapSnapshot((await srv.api.get('/api/v1/compositor/snapshot')).json);
      assert.equal(findWindow(snapAfterClose, winId), null, 'Window closed via WS must disappear from snapshot');
    } finally {
      await ws?.close();
      await srv.stop();
    }
  });
});
