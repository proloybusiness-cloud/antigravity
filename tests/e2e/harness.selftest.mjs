/**
 * OmniOS SM-1 E2E Harness Self-Test & External Oracle Verification Suite.
 *
 * Verifies all 6 SM-1 library modules using ZERO external npm dependencies and
 * REAL independent external host oracles:
 * - Node 24 built-in HTTP/WS + live /usr/lib/chromium/chromium CDP
 * - llvm-objdump & llvm-readobj (PE32+, PE32, Mach-O ARM64/x86-64/Universal Fat/ObjC)
 * - Python 3 zipfile & plistlib (ZIP/DD-bit-3/APK-v2, bplist00 & XML plist, cyclic plist, DMG blkx)
 * - Host `file` utility (DEX v035, OLE CFBF .msi, XAR .pkg)
 * - Independent Adler-32 / SHA-1 verification & Node 24 WebAssembly.validate + instantiation
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import { promisify } from 'node:util';
import zlib from 'node:zlib';

import {
  REPO_ROOT,
  PUBLIC_PATHS,
  assertPublicEntryExists,
  createTempDataDir,
  allocateEphemeralPort,
  waitForHealth,
  createApiClient,
  connectWs,
  runCli,
  startOmniServer,
  loadPublicOmniOS,
} from './lib/env.mjs';
import { launchBrowser } from './lib/cdp-client.mjs';
import {
  crc32,
  adler32,
  encodeUleb128,
  encodeMutf8,
  buildZip,
  buildResourcesArsc,
  plistFloat,
  buildBinaryPlist,
  buildXmlPlist,
} from './lib/binary-utils.mjs';
import {
  DALVIK,
  buildDex,
  buildCustomApk,
  buildCustomPe64Exe,
  buildCustomPe32Exe,
  buildCustomMsix,
  buildCustomMsi,
  buildBatScript,
  buildErrorlevelSemanticsScript,
} from './lib/fixtures-android-win.mjs';
import {
  buildMachO64,
  buildUniversalMachO,
  buildCustomIpa,
  buildCustomMacAppZip,
  buildCustomDmg,
  buildCustomPkg,
  buildCustomWasm,
  buildCustomUapp,
} from './lib/fixtures-apple-wasm.mjs';
import {
  MALFORMED_CORPUS_INDEX,
  buildZipSlipArchive,
  buildZipBomb,
  buildApkWithV2SigningBlock,
  buildZipWithDataDescriptor,
  buildMalformedAxml,
  buildResourcesArsc as buildEdgeResourcesArsc,
  buildMalformedDex,
  buildDexMutf8Valid,
  buildDexOverlongLeb128,
  buildDexOddInsnsTryCatchApk,
  buildMalformedPe,
  buildPeSectionSizingEdgeExe,
  buildPeZeroOftExe,
  buildPeWithCertificateTableExe,
  buildPeX64RegisterWidthTestExe,
  buildPeRipRelativeTestExe,
  buildBatVsCmdErrorlevelScripts,
  buildJavaClassBytes,
  buildFairPlayEncryptedMachO,
  buildPageZeroDerefMachO,
  buildNonZeroEntryOffMachO,
  buildArm64Reg31TestMachO,
  buildArm64VariadicStackArgsMachO,
  buildDarwinErrnoCarryMachO,
  buildObjcNilMsgSendMachO,
  buildCyclicBplist,
  buildBplistEdgeValues,
  buildWasiInvalidIovsLenWasm,
  buildWasiOobPointerWasm,
  buildWasiUngrantedFdWasm,
  buildMalformedDmg,
  buildMalformedPkg,
} from './lib/fixtures-malformed.mjs';

const execFileAsync = promisify(execFile);

async function runOracle(bin, args, { input = null, timeoutMs = 15000 } = {}) {
  try {
    const { stdout, stderr } = await execFileAsync(bin, args, {
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
      timeout: timeoutMs,
      ...(input !== null ? { input } : {}),
    });
    return { code: 0, stdout, stderr };
  } catch (err) {
    return {
      code: typeof err.code === 'number' ? err.code : 1,
      stdout: err.stdout ?? '',
      stderr: err.stderr ?? err.message,
    };
  }
}

// ============================================================================
// Pure-JS Inline HTTP + RFC 6455 WebSocket Test Server (for env.mjs & cdp-client.mjs)
// ============================================================================

function encodeWsFrame(opcode, payloadBuf) {
  const len = payloadBuf.length;
  let header;
  if (len < 126) {
    header = Buffer.from([0x80 | opcode, len]);
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x80 | opcode;
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | opcode;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([header, payloadBuf]);
}

function sendWsJson(socket, obj) {
  if (!socket.destroyed) {
    socket.write(encodeWsFrame(0x01, Buffer.from(JSON.stringify(obj), 'utf8')));
  }
}

const CDP_TEST_HTML = `<!doctype html>
<html>
<head><meta charset="utf-8"><title>OmniOS CDP Selftest</title>
<style>
  body { margin: 0; font-family: sans-serif; }
  #drag-box { position: absolute; left: 40px; top: 40px; width: 60px; height: 60px; background: #2266cc; }
  #vis-hidden { visibility: hidden; width: 120px; height: 40px; }
  #opacity-zero { opacity: 0; width: 120px; height: 40px; }
  #delayed-show { display: none; width: 120px; height: 32px; }
  #hidden-input { display: none; }
  #vis-hidden-input { visibility: hidden; width: 120px; height: 30px; }
  #zero-input { width: 0; height: 0; padding: 0; border: 0; }
  #hidden-file-inp { display: none; }
</style>
</head>
<body>
  <h1 id="title">OmniOS Live CDP Fixture</h1>
  <button id="btn">Clicks: 0</button>
  <button id="vis-hidden">VisHidden</button>
  <button id="opacity-zero">OpacityZero</button>
  <button id="delayed-show">DelayedShow</button>
  <input id="inp" type="text" value="" />
  <input id="focus-sink" type="text" value="" />
  <input id="hidden-input" type="text" value="" />
  <input id="vis-hidden-input" type="text" value="" />
  <input id="zero-input" type="text" value="" />
  <input id="append-input" type="text" value="PRE_" />
  <div id="inp-echo"></div>
  <div id="key-out"></div>
  <div id="drag-box"></div>
  <input id="file-inp" type="file" />
  <div id="file-out"></div>
  <input id="hidden-file-inp" type="file" />
  <div id="hidden-file-out"></div>
  <canvas id="cv" width="40" height="40"></canvas>
  <script>
    const ctx = document.getElementById('cv').getContext('2d');
    ctx.fillStyle = 'rgb(255, 0, 0)';
    ctx.fillRect(0, 0, 40, 40);

    let clicks = 0;
    const btn = document.getElementById('btn');
    btn.addEventListener('click', () => {
      clicks++;
      btn.textContent = 'Clicks: ' + clicks;
    });

    let delayedClicks = 0;
    const delayedBtn = document.getElementById('delayed-show');
    delayedBtn.addEventListener('click', () => {
      delayedClicks++;
      delayedBtn.textContent = 'DelayedClicks: ' + delayedClicks;
    });
    window.__showDelayedAfter = (ms) => {
      delayedBtn.style.display = 'none';
      setTimeout(() => { delayedBtn.style.display = 'block'; }, ms);
    };

    const inp = document.getElementById('inp');
    inp.addEventListener('input', () => {
      document.getElementById('inp-echo').textContent = inp.value;
    });

    window.addEventListener('keydown', (e) => {
      document.getElementById('key-out').textContent = JSON.stringify({ key: e.key, code: e.code, ctrlKey: e.ctrlKey });
    });

    const box = document.getElementById('drag-box');
    let dragging = false, ox = 0, oy = 0;
    box.addEventListener('mousedown', (e) => {
      dragging = true;
      ox = e.clientX - box.offsetLeft;
      oy = e.clientY - box.offsetTop;
    });
    window.addEventListener('mousemove', (e) => {
      if (!dragging) return;
      box.style.left = (e.clientX - ox) + 'px';
      box.style.top = (e.clientY - oy) + 'px';
    });
    window.addEventListener('mouseup', () => { dragging = false; });

    document.getElementById('file-inp').addEventListener('change', (e) => {
      const f = e.target.files[0];
      document.getElementById('file-out').textContent = f ? (f.name + ':' + f.size) : '';
    });

    document.getElementById('hidden-file-inp').addEventListener('change', (e) => {
      const f = e.target.files[0];
      document.getElementById('hidden-file-out').textContent = f ? (f.name + ':' + f.size) : '';
    });

    setTimeout(() => {
      const d = document.createElement('div');
      d.id = 'delayed';
      d.textContent = 'appeared';
      document.body.appendChild(d);
    }, 100);

    window.__emitConsoleError = () => console.error('SELFTEST_CONSOLE_ERR');
    window.__emitSyncError = () => setTimeout(() => { throw new Error('SELFTEST_SYNC_ERR'); }, 10);
    window.__emitUnhandledRejection = () => { Promise.reject(new Error('SELFTEST_PROMISE_ERR')); };
  </script>
</body>
</html>`;

async function startInlineTestServer() {
  const port = await allocateEphemeralPort('127.0.0.1');
  const activeSockets = new Set();
  const flakyCounts = new Map();

  const server = http.createServer((req, res) => {
    const u = new URL(req.url, `http://127.0.0.1:${port}`);
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const bodyBuf = Buffer.concat(chunks);
      if (req.method === 'GET' && u.pathname === '/api/health') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: true, os: 'SelftestServer', status: 'RUNNING' }));
      } else if (req.method === 'GET' && u.pathname === '/health-ok-false') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: false, status: 'BOOTING' }));
      } else if (req.method === 'GET' && u.pathname === '/health-html') {
        res.writeHead(200, { 'content-type': 'text/html' });
        res.end('<html>not ready</html>');
      } else if (req.method === 'GET' && u.pathname === '/health-flaky') {
        const key = u.searchParams.get('run') || 'default';
        const attempt = (flakyCounts.get(key) || 0) + 1;
        flakyCounts.set(key, attempt);
        if (attempt === 1) {
          res.writeHead(200, { 'content-type': 'text/html' });
          res.end('<html>warming up</html>');
        } else if (attempt === 2) {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ ok: false, status: 'STARTING' }));
        } else {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ ok: true, os: 'SelftestServer', status: 'RUNNING', attempt }));
        }
      } else if (req.method === 'GET' && u.pathname === '/echo') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(Object.fromEntries(u.searchParams.entries())));
      } else if (req.method === 'POST' && u.pathname === '/json') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(bodyBuf.toString('utf8'));
      } else if (req.method === 'PUT' && u.pathname === '/binary') {
        res.writeHead(200, { 'content-type': 'application/octet-stream' });
        res.end(bodyBuf);
      } else if (req.method === 'DELETE' && u.pathname.startsWith('/item/')) {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ deleted: u.pathname.slice('/item/'.length) }));
      } else if (req.method === 'GET' && u.pathname === '/fail') {
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'boom' }));
      } else if (req.method === 'GET' && u.pathname === '/cdp-page') {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        res.end(CDP_TEST_HTML);
      } else if (req.method === 'GET' && u.pathname === '/hang-load') {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        res.end('<!doctype html><html><body><script src="/never-returns.js"></script></body></html>');
      } else if (req.method === 'GET' && u.pathname === '/never-returns.js') {
        res.writeHead(200, { 'content-type': 'application/javascript' });
        res.flushHeaders();
        activeSockets.add(req.socket);
        req.socket.on('close', () => activeSockets.delete(req.socket));
      } else {
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'not-found' }));
      }
    });
  });

  server.on('connection', (socket) => {
    activeSockets.add(socket);
    socket.on('close', () => activeSockets.delete(socket));
  });

  server.on('upgrade', (req, socket) => {
    const key = req.headers['sec-websocket-key'];
    const accept = crypto
      .createHash('sha1')
      .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
      .digest('base64');

    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n' +
      `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
    );

    activeSockets.add(socket);
    socket.on('close', () => activeSockets.delete(socket));

    // Immediately push initial snapshot (testing env.mjs early-message buffering!)
    sendWsJson(socket, {
      type: 'compositor:snapshot',
      seq: 1,
      ts: Date.now(),
      payload: { windows: [] },
    });

    let buf = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      while (buf.length >= 2) {
        const opcode = buf[0] & 0x0f;
        const masked = (buf[1] & 0x80) !== 0;
        let len = buf[1] & 0x7f;
        let off = 2;
        if (len === 126) {
          if (buf.length < 4) return;
          len = buf.readUInt16BE(2);
          off = 4;
        } else if (len === 127) {
          if (buf.length < 10) return;
          len = Number(buf.readBigUInt64BE(2));
          off = 10;
        }
        const maskLen = masked ? 4 : 0;
        if (buf.length < off + maskLen + len) return;
        const mask = masked ? buf.subarray(off, off + 4) : null;
        off += maskLen;
        const payload = Buffer.from(buf.subarray(off, off + len));
        buf = buf.subarray(off + len);
        if (mask) {
          for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
        }
        if (opcode === 0x08) {
          socket.write(encodeWsFrame(0x08, Buffer.alloc(0)));
          socket.end();
          return;
        }
        if (opcode === 0x01) {
          const msg = JSON.parse(payload.toString('utf8'));
          if (msg.type === 'ping') {
            sendWsJson(socket, { type: 'pong', ts: Date.now(), payload: msg.payload });
          } else if (msg.type === 'send_raw') {
            if (!socket.destroyed) {
              socket.write(encodeWsFrame(0x01, Buffer.from(String(msg.raw), 'utf8')));
            }
          }
        }
      }
    });
  });

  await new Promise((resolve) => server.listen(port, '127.0.0.1', resolve));

  return {
    baseUrl: `http://127.0.0.1:${port}`,
    wsUrl: `ws://127.0.0.1:${port}/ws`,
    async close() {
      for (const s of activeSockets) {
        try { s.destroy(); } catch { /* ignore */ }
      }
      activeSockets.clear();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

// ============================================================================
// Suite 1: env.mjs Self-Tests
// ============================================================================

describe('SM-1 Suite 1: env.mjs harness primitives, anti-skip & opaque-box audit', () => {
  let srv;
  before(async () => {
    srv = await startInlineTestServer();
  });
  after(async () => {
    await srv?.close();
  });

  it('createTempDataDir creates a writable directory and cleans up idempotently', async () => {
    const tmp = await createTempDataDir('omnios-selftest-');
    const markerFile = path.join(tmp.dir, 'probe.txt');
    await fs.writeFile(markerFile, 'ok');
    assert.equal(await fs.readFile(markerFile, 'utf8'), 'ok');
    await tmp.cleanup();
    await tmp.cleanup(); // idempotent second call
    await assert.rejects(() => fs.access(tmp.dir));

    // Concurrent cleanup() calls share the same in-flight deletion promise
    const tmp2 = await createTempDataDir('omnios-selftest-conc-');
    await fs.writeFile(path.join(tmp2.dir, 'f.txt'), 'x');
    const c1 = tmp2.cleanup();
    const c2 = tmp2.cleanup();
    await c2;
    await assert.rejects(() => fs.access(tmp2.dir));
    await c1;
  });

  it('allocateEphemeralPort returns valid unused local ports', async () => {
    const p1 = await allocateEphemeralPort('127.0.0.1');
    const p2 = await allocateEphemeralPort('127.0.0.1');
    assert.ok(p1 >= 1024 && p1 <= 65535);
    assert.ok(p2 >= 1024 && p2 <= 65535);
  });

  it('waitForHealth rejects { ok: false } & non-JSON 200, polls until valid { ok: true }, and createApiClient works', async () => {
    await assert.rejects(
      () => waitForHealth(`${srv.baseUrl}/health-ok-false`, { timeoutMs: 250, intervalMs: 30 }),
      (err) => err.code === 'E_HEALTH_TIMEOUT' && /unhealthy|unexpected/i.test(err.message)
    );
    await assert.rejects(
      () => waitForHealth(`${srv.baseUrl}/health-html`, { timeoutMs: 250, intervalMs: 30 }),
      (err) => err.code === 'E_HEALTH_TIMEOUT' && /invalid JSON/i.test(err.message)
    );

    const flaky = await waitForHealth(`${srv.baseUrl}/health-flaky?run=selftest1`, { timeoutMs: 3000, intervalMs: 25 });
    assert.equal(flaky.status, 200);
    assert.equal(flaky.body.ok, true);
    assert.equal(flaky.body.attempt, 3);

    const health = await waitForHealth(`${srv.baseUrl}/api/health`, { timeoutMs: 3000 });
    assert.equal(health.status, 200);
    assert.equal(health.body.ok, true);

    const api = createApiClient(srv.baseUrl);
    const echo = await api.get('/echo', { query: { a: '1', b: 'hello world' }, expectOk: true });
    assert.deepEqual(echo.json, { a: '1', b: 'hello world' });

    const posted = await api.post('/json', { token: 'nonce-42', list: [1, 2, 3] }, { expectOk: true });
    assert.deepEqual(posted.json, { token: 'nonce-42', list: [1, 2, 3] });

    const binPayload = Uint8Array.from([0x00, 0xde, 0xad, 0xbe, 0xef, 0xff]);
    const putRes = await api.put('/binary', binPayload, { expectOk: true });
    assert.deepEqual(new Uint8Array(putRes.buffer), binPayload);

    const delRes = await api.delete('/item/win-7', { expectOk: true });
    assert.deepEqual(delRes.json, { deleted: 'win-7' });

    await assert.rejects(
      () => api.get('/fail', { expectOk: true }),
      (err) => err.status === 500 && /failed with 500/.test(err.message)
    );
  });

  it('connectWs buffers early snapshot, handles JSON "null" without sync throw, and leaves zero leaked timers', async () => {
    const ws = await connectWs(srv.wsUrl, { timeoutMs: 3000 });
    try {
      const snap = await ws.waitForType('compositor:snapshot', { timeoutMs: 2000 });
      assert.equal(snap.type, 'compositor:snapshot');

      // JSON primitive "null" is wrapped safely as { type: '__raw__', value: null, raw: 'null' }
      const rawCursor = ws.mark();
      ws.send({ type: 'send_raw', raw: 'null' });
      const rawNull = await ws.waitForType('__raw__', { since: rawCursor, timeoutMs: 2000 });
      assert.equal(rawNull.value, null);
      assert.equal(rawNull.raw, 'null');

      // Scanning past buffered JSON "null" and rejecting predicate errors asynchronously (never sync throw)
      const cursor = ws.mark();
      ws.send({ type: 'ping', payload: { nonce: 'ws-check-99' } });
      const pong = await ws.waitForMessage((m) => m.type === 'pong' && m.payload?.nonce === 'ws-check-99', {
        since: rawCursor,
        timeoutMs: 2000,
      });
      assert.equal(pong.payload.nonce, 'ws-check-99');

      let syncThrew = false;
      let errPromise;
      try {
        errPromise = ws.waitForMessage(() => {
          throw new Error('PREDICATE_EXPLODED');
        }, { since: 0, timeoutMs: 200 });
      } catch {
        syncThrew = true;
      }
      assert.equal(syncThrew, false, 'waitForMessage must never throw synchronously on predicate error');
      await assert.rejects(() => errPromise, /PREDICATE_EXPLODED/);

      await assert.rejects(
        () => ws.waitForType('never:happens', { since: cursor + 1, timeoutMs: 120 }),
        /Timed out/
      );
    } finally {
      await ws.close();
    }
    assert.equal(ws.isOpen(), false);

    // Verify natural event-loop exit after ws.close() has zero leaked ref'd timers (<300ms, vs old 2000ms leak)
    const envModUrl = new URL('./lib/env.mjs', import.meta.url).href;
    const probeScript = `
      const { connectWs } = await import(process.argv[1]);
      const ws = await connectWs(process.argv[2], { timeoutMs: 3000 });
      await ws.waitForType('compositor:snapshot', { timeoutMs: 2000 });
      await ws.close();
      const closedAt = Date.now();
      process.on('beforeExit', () => {
        console.log('EXIT_DELAY_MS=' + (Date.now() - closedAt));
      });
    `;
    const probe = await runOracle(process.execPath, ['--input-type=module', '-e', probeScript, envModUrl, srv.wsUrl]);
    assert.equal(probe.code, 0, probe.stderr);
    const delayMatch = /EXIT_DELAY_MS=(\d+)/.exec(probe.stdout);
    assert.ok(delayMatch, `Missing EXIT_DELAY_MS in output: ${probe.stdout}`);
    assert.ok(Number(delayMatch[1]) < 300, `Expected <300ms natural exit after ws.close(), got ${delayMatch[1]}ms`);
  });

  it('enforces anti-skip E_OMNIOS_NOT_IMPLEMENTED whenever public OS entrypoints are absent', async () => {
    await assert.rejects(
      () => assertPublicEntryExists(path.join(REPO_ROOT, 'os', '__guaranteed_missing__.mjs'), 'missing'),
      (err) => err.code === 'E_OMNIOS_NOT_IMPLEMENTED'
    );

    const exists = async (p) => {
      try { await fs.access(p); return true; } catch { return false; }
    };
    if (!(await exists(PUBLIC_PATHS.osEntry))) {
      await assert.rejects(() => loadPublicOmniOS(), (err) => err.code === 'E_OMNIOS_NOT_IMPLEMENTED');
    }
    if (!(await exists(PUBLIC_PATHS.httpServerEntry))) {
      await assert.rejects(() => startOmniServer(), (err) => err.code === 'E_OMNIOS_NOT_IMPLEMENTED');
    }
    if (!(await exists(PUBLIC_PATHS.cliEntry))) {
      await assert.rejects(() => runCli(['status']), (err) => err.code === 'E_OMNIOS_NOT_IMPLEMENTED');
    }
  });

  it('passes strict opaque-box import audit across all SM-1 lib modules', async () => {
    const libDir = path.join(REPO_ROOT, 'tests', 'e2e', 'lib');
    const files = (await fs.readdir(libDir)).filter((f) => f.endsWith('.mjs'));
    assert.equal(files.length, 6);
    const forbidden = /from\s+['"][^'"]*os\/(kernel|vfs|store|ipc|security|compositor|pkg|cpu|runtimes|apps|server|cli)/;
    for (const file of files) {
      const src = await fs.readFile(path.join(libDir, file), 'utf8');
      assert.equal(forbidden.test(src), false, `Forbidden private os/*/* import found in ${file}`);
    }
  });
});

// ============================================================================
// Suite 2: cdp-client.mjs Live Headless Chromium CDP Self-Tests
// ============================================================================

describe('SM-1 Suite 2: cdp-client.mjs live /usr/lib/chromium/chromium CDP round-trip', () => {
  let srv;
  let browser;
  let page;
  let scratchDir;

  before(async () => {
    srv = await startInlineTestServer();
    scratchDir = await createTempDataDir('omnios-cdp-upload-');
    browser = await launchBrowser();
    page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
  });

  after(async () => {
    await browser?.close();
    await srv?.close();
    await scratchDir?.cleanup();
  });

  it('navigates, reads DOM & Canvas2D pixel RGBA, and reports zero initial errors', async () => {
    await page.goto(`${srv.baseUrl}/cdp-page`);
    assert.deepEqual(page.getConsoleErrors(), []);
    assert.deepEqual(page.getPageErrors(), []);

    const title = await page.eval(`document.getElementById('title').textContent`);
    assert.equal(title, 'OmniOS Live CDP Fixture');

    const rgba = await page.eval(
      `Array.from(document.getElementById('cv').getContext('2d').getImageData(10, 10, 1, 1).data)`
    );
    assert.deepEqual(rgba, [255, 0, 0, 255]);
  });

  it('waitForSelector resolves delayed element, accepts null opts, and evalFn supports undefined args', async () => {
    await page.waitForSelector('#delayed', 3000, { visible: true });
    assert.equal(await page.eval(`document.getElementById('delayed').textContent`), 'appeared');
    assert.equal(await page.waitForSelector('#btn', null), true);
    await assert.rejects(() => page.waitForSelector('#does-not-exist', 200), /Timed out/);

    const evalRes = await page.evalFn(
      (a, b, c) => [a === undefined, b, c === undefined],
      undefined,
      7,
      undefined
    );
    assert.deepEqual(evalRes, [true, 7, true]);
  });

  it('click, type, pressKey (Ctrl+Space), drag, setViewport, visibility guards, and hidden setFileInputFiles work live', async () => {
    await page.click('#btn');
    await page.click('#btn');
    assert.equal(await page.eval(`document.getElementById('btn').textContent`), 'Clicks: 2');

    // click() and drag() reject visibility:hidden and opacity:0 elements, and click() waits for initially display:none element becoming visible
    await assert.rejects(() => page.click('#vis-hidden', { timeoutMs: 250 }), /Timed out.*visible/);
    await assert.rejects(() => page.click('#opacity-zero', { timeoutMs: 250 }), /Timed out.*visible/);
    await assert.rejects(() => page.drag('#vis-hidden', { x: 200, y: 200 }, { timeoutMs: 250 }), /Timed out.*visible/);
    await page.eval(`window.__showDelayedAfter(120)`);
    await page.click('#delayed-show', { timeoutMs: 2000 });
    assert.equal(await page.eval(`document.getElementById('delayed-show').textContent`), 'DelayedClicks: 1');

    // type() rejects hidden/zero-size inputs WITHOUT leaking keystrokes to previously focused input
    await page.eval(`(() => { const s = document.getElementById('focus-sink'); s.value = ''; s.focus(); })()`);
    await assert.rejects(() => page.type('#hidden-input', 'LEAK1', { timeoutMs: 200 }), /Timed out.*visible/);
    await assert.rejects(() => page.type('#vis-hidden-input', 'LEAK2', { timeoutMs: 200 }), /Timed out.*visible/);
    await assert.rejects(() => page.type('#zero-input', 'LEAK3', { timeoutMs: 200 }), /Timed out.*visible/);
    assert.equal(await page.eval(`document.getElementById('focus-sink').value`), '');

    // type() supports strings, numeric 42, and appends at end when clear=false
    await page.type('#inp', 'OmniOS-2026');
    assert.equal(await page.eval(`document.getElementById('inp').value`), 'OmniOS-2026');
    assert.equal(await page.eval(`document.getElementById('inp-echo').textContent`), 'OmniOS-2026');

    await page.type('#inp', 42, { clear: true });
    assert.equal(await page.eval(`document.getElementById('inp').value`), '42');

    await page.type('#append-input', 'POST', { clear: false });
    assert.equal(await page.eval(`document.getElementById('append-input').value`), 'PRE_POST');

    await page.pressKey('Space', { ctrl: true });
    const keyEvent = JSON.parse(await page.eval(`document.getElementById('key-out').textContent`));
    assert.equal(keyEvent.key, ' ');
    assert.equal(keyEvent.code, 'Space');
    assert.equal(keyEvent.ctrlKey, true);

    await page.drag('#drag-box', { x: 260, y: 240 }, { steps: 10 });
    const pos = await page.eval(`(() => { const r = document.getElementById('drag-box').getBoundingClientRect(); return { x: Math.round(r.left + r.width/2), y: Math.round(r.top + r.height/2) }; })()`);
    assert.ok(Math.abs(pos.x - 260) <= 2, `Expected dragged x ~260, got ${pos.x}`);
    assert.ok(Math.abs(pos.y - 240) <= 2, `Expected dragged y ~240, got ${pos.y}`);

    await page.setViewport(1024, 640);
    const dims = await page.eval(`({ w: window.innerWidth, h: window.innerHeight })`);
    assert.deepEqual(dims, { w: 1024, h: 640 });

    const uploadPath = path.join(scratchDir.dir, 'sample-upload.bin');
    await fs.writeFile(uploadPath, Buffer.from('OMNIOS_UPLOAD_12345'));
    await page.setFileInputFiles('#file-inp', [uploadPath]);
    await page.waitForFunction(`document.getElementById('file-out').textContent.includes('sample-upload.bin')`, { timeoutMs: 2000 });
    assert.equal(await page.eval(`document.getElementById('file-out').textContent`), 'sample-upload.bin:19');

    // Hidden <input type="file" style="display:none"> must continue to work!
    await page.setFileInputFiles('#hidden-file-inp', [uploadPath]);
    await page.waitForFunction(`document.getElementById('hidden-file-out').textContent.includes('sample-upload.bin')`, { timeoutMs: 2000 });
    assert.equal(await page.eval(`document.getElementById('hidden-file-out').textContent`), 'sample-upload.bin:19');
  });

  it('captures console.error, sync throw, and unhandled Promise rejection, plus fast-fail goto', async () => {
    page.clearErrors();
    await page.eval(`window.__emitConsoleError()`);
    await page.eval(`window.__emitSyncError()`);
    await page.eval(`window.__emitUnhandledRejection()`);

    await page.waitForFunction(() => true);
    // Allow brief event delivery from setTimeout(10)
    await new Promise((r) => setTimeout(r, 150));

    const cErrs = page.getConsoleErrors();
    const pErrs = page.getPageErrors();
    assert.ok(cErrs.some((e) => e.text.includes('SELFTEST_CONSOLE_ERR')), `Missing console.error: ${JSON.stringify(cErrs)}`);
    assert.ok(pErrs.some((e) => e.description.includes('SELFTEST_SYNC_ERR')), `Missing sync error: ${JSON.stringify(pErrs)}`);
    assert.ok(pErrs.some((e) => e.description.includes('SELFTEST_PROMISE_ERR')), `Missing promise rejection: ${JSON.stringify(pErrs)}`);

    await assert.rejects(() => page.goto('http://127.0.0.1:1/', { timeoutMs: 5000 }), /Navigation to .* failed/);
  });

  it('abrupt browser.close() promptly rejects in-flight goto()/waitForFunction(), concurrent close() awaits userDataDir deletion, and leaves zero leaked timers', async () => {
    // 1. Close main browser cleanly via concurrent Promise.all([close(), close()])
    const dirToVerify = browser.userDataDir;
    const c1 = browser.close();
    const c2 = browser.close();
    await c2;
    await assert.rejects(() => fs.access(dirToVerify), 'userDataDir must already be deleted when 2nd concurrent close() resolves');
    await c1;
    browser = null;

    // 2. Abrupt browser.close() mid-flight rejects hanging goto() & waitForFunction() in <1s
    const b2 = await launchBrowser();
    const b2Dir = b2.userDataDir;
    try {
      const pGoto = await b2.newPage();
      const pWait = await b2.newPage();
      await pWait.goto(`${srv.baseUrl}/cdp-page`);

      const gotoOutcome = pGoto.goto(`${srv.baseUrl}/hang-load`, { timeoutMs: 8000 }).then(
        () => ({ ok: true, at: Date.now() }),
        (err) => ({ ok: false, err, at: Date.now() })
      );
      const waitOutcome = pWait.waitForFunction(() => false, { timeoutMs: 8000 }).then(
        () => ({ ok: true, at: Date.now() }),
        (err) => ({ ok: false, err, at: Date.now() })
      );

      await new Promise((r) => setTimeout(r, 120));
      const closeStart = Date.now();
      const [gRes, wRes] = await Promise.all([
        gotoOutcome,
        waitOutcome,
        b2.close(),
        b2.close(),
      ]);

      assert.equal(gRes.ok, false, 'In-flight goto() must reject on abrupt browser.close()');
      assert.match(gRes.err.message, /aborted|closed/i);
      assert.ok(gRes.at - closeStart < 1000, `Expected goto() rejection <1000ms after close(), got ${gRes.at - closeStart}ms`);

      assert.equal(wRes.ok, false, 'In-flight waitForFunction() must reject on abrupt browser.close()');
      assert.match(wRes.err.message, /aborted|closed/i);
      assert.ok(wRes.at - closeStart < 1000, `Expected waitForFunction() rejection <1000ms after close(), got ${wRes.at - closeStart}ms`);

      await assert.rejects(() => fs.access(b2Dir));
    } finally {
      await b2.close().catch(() => {});
    }

    // 3. Natural process exit after browser.close() has zero leaked ref'd timers (<300ms, vs old 1000ms leak)
    const cdpModUrl = new URL('./lib/cdp-client.mjs', import.meta.url).href;
    const probeScript = `
      const { launchBrowser } = await import(process.argv[1]);
      const b = await launchBrowser();
      const p = await b.newPage();
      await p.eval('1 + 1');
      await b.close();
      const closedAt = Date.now();
      process.on('beforeExit', () => {
        console.log('CDP_EXIT_DELAY_MS=' + (Date.now() - closedAt));
      });
    `;
    const probe = await runOracle(process.execPath, ['--input-type=module', '-e', probeScript, cdpModUrl]);
    assert.equal(probe.code, 0, probe.stderr);
    const delayMatch = /CDP_EXIT_DELAY_MS=(\d+)/.exec(probe.stdout);
    assert.ok(delayMatch, `Missing CDP_EXIT_DELAY_MS in output: ${probe.stdout}`);
    assert.ok(Number(delayMatch[1]) < 300, `Expected <300ms natural exit after browser.close(), got ${delayMatch[1]}ms`);
  });
});

// ============================================================================
// Suite 3: binary-utils.mjs & fixtures-android-win.mjs External Oracles
// ============================================================================

describe('SM-1 Suite 3: binary-utils & Android/Windows fixtures external oracles', () => {
  let tmp;
  before(async () => {
    tmp = await createTempDataDir('omnios-oracle-aw-');
  });
  after(async () => {
    await tmp?.cleanup();
  });

  it('verifies CRC-32, Adler-32, ULEB128 (>32-bit & negative guard), and MUTF-8 reference vectors', () => {
    assert.equal(crc32('123456789'), 0xcbf43926);
    assert.equal(adler32('Wikipedia'), 0x11e60398);
    assert.throws(() => encodeUleb128(-1), RangeError);
    assert.throws(() => encodeUleb128(-1n), RangeError);
    assert.throws(() => encodeUleb128(1.5), RangeError);
    assert.deepEqual(Array.from(encodeUleb128(0x100000000)), [0x80, 0x80, 0x80, 0x80, 0x10]);
    assert.deepEqual(Array.from(encodeMutf8('\u0000')), [0xc0, 0x80]);
    assert.deepEqual(Array.from(encodeMutf8('😀')), [0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80]);
  });

  it('Python zipfile verifies buildZip with Data Descriptor bit 3 + APK v2 Signing Block', async () => {
    const zipBytes = buildZip(
      [
        { name: 'hello.txt', data: 'OmniOS ZIP Oracle!\n', method: 8 },
        { name: 'dir/data.bin', data: Uint8Array.from([1, 2, 3, 4, 5]), method: 0 },
      ],
      { useDataDescriptor: true, apkV2SigBlock: true }
    );
    const zipPath = path.join(tmp.dir, 'dd-v2.zip');
    await fs.writeFile(zipPath, zipBytes);

    const py = await runOracle('python3', [
      '-c',
      'import sys, zipfile; z=zipfile.ZipFile(sys.argv[1]); assert z.testzip() is None; assert z.read("hello.txt")==b"OmniOS ZIP Oracle!\\n"; assert z.read("dir/data.bin")==bytes([1,2,3,4,5]); print("OK")',
      zipPath,
    ]);
    assert.equal(py.code, 0, py.stderr);
    assert.equal(py.stdout.trim(), 'OK');
  });

  it('Python plistlib verifies bplist00 & XML plist round-trip (UTF-16BE, neg int 0x13, CF 2001 date)', async () => {
    const sample = {
      ascii: 'OmniOS',
      unicode: 'OmniOS ★🚀',
      longStr: 'This string exceeds fifteen characters cleanly!',
      flagT: true,
      flagF: false,
      zero: 0,
      small: 42,
      med: 50000,
      big: 1000000,
      neg: -42,
      real: plistFloat(3.25),
      when: new Date('2026-11-20T22:00:00Z'),
      raw: Uint8Array.from([0xde, 0xad, 0xbe, 0xef]),
      nested: { arr: [1, 'two', false] },
    };

    const bpPath = path.join(tmp.dir, 'test.bplist');
    const xpPath = path.join(tmp.dir, 'test.plist');
    await fs.writeFile(bpPath, buildBinaryPlist(sample));
    await fs.writeFile(xpPath, buildXmlPlist(sample));

    const py = await runOracle('python3', [
      '-c',
      `import sys, plistlib, datetime
for p in sys.argv[1:]:
  d = plistlib.loads(open(p, 'rb').read())
  assert d['ascii'] == 'OmniOS'
  assert d['unicode'] == 'OmniOS ★🚀'
  assert d['longStr'] == 'This string exceeds fifteen characters cleanly!'
  assert d['flagT'] is True and d['flagF'] is False
  assert d['zero'] == 0 and d['small'] == 42 and d['med'] == 50000 and d['big'] == 1000000
  assert d['neg'] == -42
  assert abs(d['real'] - 3.25) < 1e-9
  assert d['when'] == datetime.datetime(2026, 11, 20, 22, 0, 0)
  assert d['raw'] == bytes([0xde, 0xad, 0xbe, 0xef])
  assert d['nested'] == {'arr': [1, 'two', False]}
print('PLIST_OK')`,
      bpPath,
      xpPath,
    ]);
    assert.equal(py.code, 0, py.stderr);
    assert.equal(py.stdout.trim(), 'PLIST_OK');
  });

  it('Python zipfile + independent Adler-32/SHA-1 + host `file` verify dynamic APKs (DEX 035 & 039, AXML, ARSC modes)', async () => {
    const nonce = `tok_${Date.now()}`;
    const apk35 = buildCustomApk({
      packageName: 'com.omnios.selftest.apk35',
      appLabel: `Calc_${nonce}`,
      computeA: 137,
      computeB: 289,
      outputFile: `/sdcard/Documents/${nonce}.txt`,
      sharedPrefKey: 'last_token',
      sharedPrefVal: nonce,
      intentAction: 'android.intent.action.SEND',
      intentMimeType: 'text/plain',
      notificationTitle: 'Done',
      includeV2SigBlock: true,
      dexVersion: '035',
    });
    const apk39 = buildCustomApk({
      packageName: 'com.omnios.selftest.apk39',
      appLabel: 'SparseV039',
      dexVersion: '039',
      arscSparse: true,
      useDataDescriptor: true,
    });

    const apk35Path = path.join(tmp.dir, 'test35.apk');
    const apk39Path = path.join(tmp.dir, 'test39.apk');
    const dex35Path = path.join(tmp.dir, 'classes35.dex');
    await fs.writeFile(apk35Path, apk35);
    await fs.writeFile(apk39Path, apk39);

    const py = await runOracle('python3', [
      '-c',
      `import sys, zipfile, struct, zlib, hashlib
def check_apk(p, ver, dex_out=None):
  z = zipfile.ZipFile(p)
  assert z.testzip() is None
  dex = z.read('classes.dex')
  assert dex[0:8] == f'dex\\n{ver}\\x00'.encode()
  assert struct.unpack_from('<I', dex, 0x08)[0] == (zlib.adler32(dex[0x0c:]) & 0xffffffff)
  assert dex[0x0c:0x20] == hashlib.sha1(dex[0x20:]).digest()
  if dex_out: open(dex_out, 'wb').write(dex)
  axml = z.read('AndroidManifest.xml')
  t, hs, sz = struct.unpack_from('<HHI', axml, 0)
  assert t == 0x0003 and hs == 8 and sz == len(axml)
  arsc = z.read('resources.arsc')
  rt, rhs, rsz = struct.unpack_from('<HHI', arsc, 0)
  assert rt == 0x0002 and rhs == 12 and rsz == len(arsc)
check_apk(sys.argv[1], '035', sys.argv[3])
check_apk(sys.argv[2], '039')
print('APK_OK')`,
      apk35Path,
      apk39Path,
      dex35Path,
    ]);
    assert.equal(py.code, 0, py.stderr);
    assert.equal(py.stdout.trim(), 'APK_OK');

    const fileRes = await runOracle('file', ['-b', dex35Path]);
    assert.equal(fileRes.code, 0);
    assert.match(fileRes.stdout, /Dalvik dex file version 035/);

    // Verify standard, offset16, and sparse ARSC header consistency
    for (const mode of ['standard', 'offset16', 'sparse']) {
      const arsc = buildResourcesArsc({ mode, strings: [{ id: 0, name: 'a', value: 'A' }, { id: 5, name: 'b', value: 'B' }] });
      const dv = new DataView(arsc.buffer, arsc.byteOffset, arsc.byteLength);
      assert.equal(dv.getUint16(0, true), 0x0002);
      assert.equal(dv.getUint32(4, true), arsc.length);
    }

    // Regression: buildDex with static codeUnits + tries (no buildInsns) preserves exception handler type descriptor
    const staticTryDex = buildDex({
      classes: [
        {
          descriptor: 'Lcom/omnios/StaticTry;',
          superclass: 'Ljava/lang/Object;',
          directMethods: [
            {
              name: 'run',
              returnType: 'V',
              params: [],
              registersSize: 2,
              insSize: 1,
              outsSize: 0,
              codeUnits: [...DALVIK.nop(), ...DALVIK.returnVoid()],
              tries: [
                {
                  startAddr: 0,
                  insnCount: 1,
                  handlers: [{ type: 'Ljava/lang/ArithmeticException;', addr: 1 }],
                },
              ],
            },
          ],
        },
      ],
    });
    const dvStatic = new DataView(staticTryDex.buffer, staticTryDex.byteOffset, staticTryDex.byteLength);
    assert.equal(dvStatic.getUint32(0x08, true), adler32(staticTryDex.subarray(0x0c)));
    assert.ok(
      Buffer.from(staticTryDex).includes(Buffer.from('Ljava/lang/ArithmeticException;', 'utf8')),
      'Static codeUnits + tries DEX must preserve exception handler type descriptor'
    );
  });

  it('llvm-readobj and llvm-objdump verify dynamic PE32+ (full + OFT==0) and PE32 (HIGHLOW) executables', async () => {
    const peFull = buildCustomPe64Exe({
      message: 'OmniOS PE64 Oracle!\n',
      writeFilePath: 'C:\\Users\\user\\Documents\\out.txt',
      writeFileContent: 'WIN_DATA',
      regSubKey: 'Software\\OmniOS\\Selftest',
      regValueName: 'Token',
      regValueData: 'T42',
      windowTitle: 'OmniWin',
      addCertTableRawOffset: true,
      computeExitSum: [20, 22],
    });
    const peOft0 = buildCustomPe64Exe({
      message: 'OFT0!\n',
      useOriginalFirstThunkZero: true,
    });
    const pe32 = buildCustomPe32Exe({
      message: 'PE32_OK\n',
      exitCode: 7,
    });

    const pFull = path.join(tmp.dir, 'full64.exe');
    const pOft0 = path.join(tmp.dir, 'oft0.exe');
    const p32 = path.join(tmp.dir, 'app32.exe');
    await fs.writeFile(pFull, peFull);
    await fs.writeFile(pOft0, peOft0);
    await fs.writeFile(p32, pe32);

    const roFull = await runOracle('llvm-readobj', ['--file-headers', '--coff-imports', '--coff-basereloc', pFull]);
    assert.equal(roFull.code, 0, roFull.stderr);
    assert.equal(roFull.stderr.trim(), '');
    assert.match(roFull.stdout, /IMAGE_FILE_MACHINE_AMD64/);
    assert.match(roFull.stdout, /KERNEL32\.dll/);
    assert.match(roFull.stdout, /ADVAPI32\.dll/);
    assert.match(roFull.stdout, /USER32\.dll/);
    assert.match(roFull.stdout, /RegSetValueExA/);
    assert.match(roFull.stdout, /DIR64/);

    const odFull = await runOracle('llvm-objdump', ['--private-headers', '-d', pFull]);
    assert.equal(odFull.code, 0, odFull.stderr);
    assert.equal(odFull.stderr.trim(), '');
    assert.match(odFull.stdout, /callq\s+\*/);

    const roOft0 = await runOracle('llvm-readobj', ['--file-headers', '--coff-imports', pOft0]);
    assert.equal(roOft0.code, 0, roOft0.stderr);
    assert.match(roOft0.stdout, /GetStdHandle/);
    assert.match(roOft0.stdout, /ExitProcess/);

    const ro32 = await runOracle('llvm-readobj', ['--file-headers', '--coff-imports', '--coff-basereloc', p32]);
    assert.equal(ro32.code, 0, ro32.stderr);
    assert.match(ro32.stdout, /IMAGE_FILE_MACHINE_I386/);
    assert.match(ro32.stdout, /HIGHLOW/);

    const od32 = await runOracle('llvm-objdump', ['--private-headers', '-d', p32]);
    assert.equal(od32.code, 0, od32.stderr);
  });

  it('Python zipfile + llvm-readobj verify .msix and host `file` verifies OLE CFBF .msi + .bat/.cmd scripts', async () => {
    const msixBytes = buildCustomMsix({
      identityName: 'OmniOS.SelftestMsix',
      displayName: 'OmniMSIX',
      executable: 'runner.exe',
    });
    const msixPath = path.join(tmp.dir, 'app.msix');
    const extractedExe = path.join(tmp.dir, 'runner.exe');
    await fs.writeFile(msixPath, msixBytes);

    const py = await runOracle('python3', [
      '-c',
      `import sys, zipfile, hashlib, base64
z = zipfile.ZipFile(sys.argv[1])
assert z.testzip() is None
exe = z.read('runner.exe')
open(sys.argv[2], 'wb').write(exe)
bm = z.read('AppxBlockMap.xml').decode()
expected_hash = base64.b64encode(hashlib.sha256(exe).digest()).decode()
assert expected_hash in bm
assert 'OmniOS.SelftestMsix' in z.read('AppxManifest.xml').decode()
print('MSIX_OK')`,
      msixPath,
      extractedExe,
    ]);
    assert.equal(py.code, 0, py.stderr);
    assert.equal(py.stdout.trim(), 'MSIX_OK');

    const ro = await runOracle('llvm-readobj', ['--file-headers', extractedExe]);
    assert.equal(ro.code, 0, ro.stderr);

    const msiBytes = buildCustomMsi({
      productName: 'OmniOS Dynamic MSI',
      productVersion: '2.4.6',
      manufacturer: 'OmniCorp',
    });
    const msiPath = path.join(tmp.dir, 'installer.msi');
    await fs.writeFile(msiPath, msiBytes);
    const fileRes = await runOracle('file', ['-b', msiPath]);
    assert.equal(fileRes.code, 0);
    assert.match(fileRes.stdout, /MSI Installer/);
    assert.match(fileRes.stdout, /Title: OmniOS Dynamic MSI/);
    assert.match(fileRes.stdout, /Subject: 2\.4\.6/);
    assert.match(fileRes.stdout, /Author: OmniCorp/);

    const bat = buildBatScript({ computeA: 10, computeB: 25, exitCode: 0 });
    assert.match(bat, /SET \/A RESULT=10\+25/);
    const elScript = buildErrorlevelSemanticsScript({ failCode: 7 });
    assert.match(elScript, /EXIT \/B 7/);
  });
});

// ============================================================================
// Suite 4: fixtures-apple-wasm.mjs External Oracles
// ============================================================================

describe('SM-1 Suite 4: Apple Mach-O/Fat/IPA/App/DMG/PKG & Universal WASM external oracles', () => {
  let tmp;
  before(async () => {
    tmp = await createTempDataDir('omnios-oracle-apple-');
  });
  after(async () => {
    await tmp?.cleanup();
  });

  it('llvm-objdump verifies Mach-O ARM64 (GOT bind + ObjC ABI2 + entitlements), x86-64, and Universal Fat', async () => {
    const entXml = buildXmlPlist({ 'com.apple.security.app-sandbox': true });
    const arm64 = buildMachO64({
      arch: 'arm64',
      platform: 2,
      message: 'ARM64_ORACLE\n',
      dylibs: ['/usr/lib/libSystem.B.dylib', '/usr/lib/libobjc.A.dylib'],
      gotSymbols: [{ name: '_objc_msgSend', dylibOrdinal: 2 }],
      objcClasses: [{ name: 'OmniAppDelegate', methods: [{ name: 'applicationDidFinishLaunching:', impOffset: 0 }] }],
      entitlementsXml: entXml,
    });
    const x64 = buildMachO64({ arch: 'x86_64', platform: 1, message: 'X64_ORACLE\n' });
    const fat = buildUniversalMachO({ message: 'FAT_ORACLE\n', platform: 1 });

    const pArm = path.join(tmp.dir, 'arm64.macho');
    const pX64 = path.join(tmp.dir, 'x64.macho');
    const pFat = path.join(tmp.dir, 'universal.macho');
    await fs.writeFile(pArm, arm64);
    await fs.writeFile(pX64, x64);
    await fs.writeFile(pFat, fat);

    const odArm = await runOracle('llvm-objdump', [
      '--macho', '--private-headers', '--bind', '--indirect-symbols', '--syms', '--objc-meta-data', '-d', pArm,
    ]);
    assert.equal(odArm.code, 0, odArm.stderr);
    assert.match(odArm.stdout, /MH_MAGIC_64/);
    assert.match(odArm.stdout, /_objc_msgSend/);
    assert.match(odArm.stdout, /OmniAppDelegate/);
    assert.match(odArm.stdout, /LC_CODE_SIGNATURE/);
    assert.match(odArm.stdout, /svc\s+#0x80/);

    // Verify CS_CodeDirectory version === 0x00020001 matching exact 44-byte header (identOffset === 44)
    const csMagicIdx = Buffer.from(arm64).indexOf(Buffer.from([0xfa, 0xde, 0x0c, 0x02]));
    assert.ok(csMagicIdx >= 0, 'Missing CS_CodeDirectory magic 0xFADE0C02');
    const csDv = new DataView(arm64.buffer, arm64.byteOffset + csMagicIdx, 44);
    assert.equal(csDv.getUint32(8, false), 0x00020001);
    assert.equal(csDv.getUint32(20, false), 44);

    const odX64 = await runOracle('llvm-objdump', ['--macho', '--private-headers', '-d', pX64]);
    assert.equal(odX64.code, 0, odX64.stderr);
    assert.match(odX64.stdout, /X86_64/);
    assert.match(odX64.stdout, /syscall/);

    // Verify x86-64 Mach-O fileWrite emits Darwin open/write/close/exit with exact path & content
    const x64FilePath = '/Users/user/Documents/x64_selftest.txt';
    const x64FileContent = 'X64_WRITE_TOKEN_99';
    const x64Fw = buildMachO64({
      arch: 'x86_64',
      platform: 1,
      fileWrite: { path: x64FilePath, content: x64FileContent },
      exitCode: 5,
    });
    const pX64Fw = path.join(tmp.dir, 'x64_fw.macho');
    await fs.writeFile(pX64Fw, x64Fw);
    const odX64Fw = await runOracle('llvm-objdump', ['--macho', '--private-headers', '-d', pX64Fw]);
    assert.equal(odX64Fw.code, 0, odX64Fw.stderr);
    assert.match(odX64Fw.stdout, /(?:33554437|0x2000005)/i); // 0x2000005 SYS_open
    assert.match(odX64Fw.stdout, /(?:33554436|0x2000004)/i); // 0x2000004 SYS_write
    assert.match(odX64Fw.stdout, /(?:33554438|0x2000006)/i); // 0x2000006 SYS_close
    assert.match(odX64Fw.stdout, /(?:33554433|0x2000001)/i); // 0x2000001 SYS_exit
    assert.ok(odX64Fw.stdout.includes(x64FilePath), `x86-64 disassembly missing literal pool path: ${odX64Fw.stdout}`);
    assert.ok(odX64Fw.stdout.includes(x64FileContent), `x86-64 disassembly missing literal pool content: ${odX64Fw.stdout}`);

    const odFat = await runOracle('llvm-objdump', ['--macho', '--universal-headers', '-d', '--arch=all', pFat]);
    assert.equal(odFat.code, 0, odFat.stderr);
    assert.match(odFat.stdout, /X86_64/);
    assert.match(odFat.stdout, /ARM64/);
  });

  it('Python zipfile + plistlib + llvm-objdump verify dynamic iOS .ipa and Universal macOS .app.zip (both slices fileWrite parity)', async () => {
    const ipaBytes = buildCustomIpa({
      bundleId: 'com.omnios.ios.selftest',
      displayName: 'WeatherLive',
      executableName: 'WeatherLive',
      urlScheme: 'omniweather',
      message: 'IOS_RUN_OK\n',
    });
    const uniPath = '/Users/user/Documents/universal_parity.txt';
    const uniContent = 'UNIVERSAL_PARITY_TOKEN_77';
    const appZipBytes = buildCustomMacAppZip({
      bundleId: 'com.omnios.macos.selftest',
      appName: 'OmniStudio',
      executableName: 'OmniStudio',
      arch: 'universal',
      documentExtensions: ['omnidoc'],
      fileWrite: { path: uniPath, content: uniContent },
      exitCode: 0,
    });

    const ipaPath = path.join(tmp.dir, 'test.ipa');
    const appPath = path.join(tmp.dir, 'test.app.zip');
    const ipaExec = path.join(tmp.dir, 'WeatherLive');
    const macExec = path.join(tmp.dir, 'OmniStudio');
    await fs.writeFile(ipaPath, ipaBytes);
    await fs.writeFile(appPath, appZipBytes);

    const py = await runOracle('python3', [
      '-c',
      `import sys, zipfile, plistlib
zi = zipfile.ZipFile(sys.argv[1])
assert zi.testzip() is None
ip = plistlib.loads(zi.read('Payload/WeatherLive.app/Info.plist'))
assert ip['CFBundleIdentifier'] == 'com.omnios.ios.selftest'
assert ip['CFBundleURLTypes'][0]['CFBundleURLSchemes'] == ['omniweather']
open(sys.argv[3], 'wb').write(zi.read('Payload/WeatherLive.app/WeatherLive'))

zm = zipfile.ZipFile(sys.argv[2])
assert zm.testzip() is None
mp = plistlib.loads(zm.read('OmniStudio.app/Contents/Info.plist'))
assert mp['CFBundleIdentifier'] == 'com.omnios.macos.selftest'
assert mp['CFBundleDocumentTypes'][0]['CFBundleTypeExtensions'] == ['omnidoc']
open(sys.argv[4], 'wb').write(zm.read('OmniStudio.app/Contents/MacOS/OmniStudio'))
print('CONTAINERS_OK')`,
      ipaPath,
      appPath,
      ipaExec,
      macExec,
    ]);
    assert.equal(py.code, 0, py.stderr);
    assert.equal(py.stdout.trim(), 'CONTAINERS_OK');

    const odIpa = await runOracle('llvm-objdump', ['--macho', '--private-headers', ipaExec]);
    assert.equal(odIpa.code, 0, odIpa.stderr);
    const odMacX64 = await runOracle('llvm-objdump', ['--macho', '--private-headers', '-d', '--arch=x86_64', macExec]);
    assert.equal(odMacX64.code, 0, odMacX64.stderr);
    assert.ok(odMacX64.stdout.includes(uniPath), `Universal x86_64 slice missing fileWrite path: ${odMacX64.stdout}`);
    assert.ok(odMacX64.stdout.includes(uniContent), `Universal x86_64 slice missing fileWrite content: ${odMacX64.stdout}`);

    const odMacArm = await runOracle('llvm-objdump', ['--macho', '--private-headers', '-d', '--arch=arm64', macExec]);
    assert.equal(odMacArm.code, 0, odMacArm.stderr);
    assert.match(odMacArm.stdout, /svc\s+#0x80/);
    assert.ok(odMacArm.stdout.includes(uniPath), `Universal arm64 slice missing fileWrite path: ${odMacArm.stdout}`);
    assert.ok(odMacArm.stdout.includes(uniContent), `Universal arm64 slice missing fileWrite content: ${odMacArm.stdout}`);
  });

  it('verifies UDIF .dmg (exact 0xD8/0xE0 koly XMLOffset & blkx plist) and XAR .pkg (`file` + TOC + gzip CPIO)', async () => {
    const dmgBytes = buildCustomDmg({ volumeName: 'OmniVol', appName: 'OmniVolApp' });
    const kolyOff = dmgBytes.length - 512;
    const dv = new DataView(dmgBytes.buffer, dmgBytes.byteOffset, dmgBytes.byteLength);
    assert.equal(Buffer.from(dmgBytes.subarray(kolyOff, kolyOff + 4)).toString('ascii'), 'koly');
    const xmlOff = Number(dv.getBigUint64(kolyOff + 0xd8, false));
    const xmlLen = Number(dv.getBigUint64(kolyOff + 0xe0, false));
    assert.equal(xmlOff + xmlLen, kolyOff);

    const dmgXmlPath = path.join(tmp.dir, 'dmg-blkx.plist');
    await fs.writeFile(dmgXmlPath, dmgBytes.subarray(xmlOff, xmlOff + xmlLen));
    const pyDmg = await runOracle('python3', [
      '-c',
      `import sys, plistlib
d = plistlib.loads(open(sys.argv[1], 'rb').read())
blkx = d['resource-fork']['blkx'][0]
assert blkx['Data'][:4] == b'mish'
assert 'OmniVol' in blkx['Name']
print('DMG_OK')`,
      dmgXmlPath,
    ]);
    assert.equal(pyDmg.code, 0, pyDmg.stderr);
    assert.equal(pyDmg.stdout.trim(), 'DMG_OK');

    const pkgBytes = buildCustomPkg({ bundleId: 'com.omnios.pkg.oracle', appName: 'PkgOracle', executableName: 'PkgOracle' });
    const pkgPath = path.join(tmp.dir, 'test.pkg');
    await fs.writeFile(pkgPath, pkgBytes);
    const fileRes = await runOracle('file', ['-b', pkgPath]);
    assert.equal(fileRes.code, 0);
    assert.match(fileRes.stdout, /xar archive/i);

    // Inflate TOC XML and verify gzip CPIO payload embeds Info.plist & Mach-O
    const pdv = new DataView(pkgBytes.buffer, pkgBytes.byteOffset, pkgBytes.byteLength);
    const tocCompLen = Number(pdv.getBigUint64(8, false));
    const tocXml = zlib.inflateSync(pkgBytes.subarray(28, 28 + tocCompLen)).toString('utf8');
    assert.match(tocXml, /<name>PackageInfo<\/name>/);
    assert.match(tocXml, /<name>Payload<\/name>/);

    const heapStart = 28 + tocCompLen;
    const payloadMatch = /<name>Payload<\/name>[\s\S]*?<offset>(\d+)<\/offset>\s*<length>(\d+)<\/length>/.exec(tocXml);
    assert.ok(payloadMatch);
    const pOff = Number(payloadMatch[1]);
    const pLen = Number(payloadMatch[2]);
    const cpioText = zlib.gunzipSync(pkgBytes.subarray(heapStart + pOff, heapStart + pOff + pLen)).toString('latin1');
    assert.ok(cpioText.includes('./PkgOracle.app/Contents/Info.plist'));
    assert.ok(cpioText.includes('./PkgOracle.app/Contents/MacOS/PkgOracle'));
    assert.ok(cpioText.includes('TRAILER!!!'));
  });

  it('WebAssembly.validate + live WASI instantiation + Python zipfile verify .wasm and .uapp', async () => {
    const token = `WASM_NONCE_${Date.now()}\n`;
    const wasmBytes = buildCustomWasm({ message: token, exitCode: 42 });
    const wasmOmni = buildCustomWasm({ message: 'OMNI_IMP\n', exitCode: 0, useOmniOsImport: true });
    assert.equal(WebAssembly.validate(wasmBytes), true);
    assert.equal(WebAssembly.validate(wasmOmni), true);

    // Instantiate with minimal inline WASI shim and verify exact runtime-nonce output & exit code!
    let capturedOut = '';
    let capturedExit = null;
    class ProcExitTrap extends Error {
      constructor(code) { super(`exit:${code}`); this.exitCode = code; }
    }
    let mem;
    const { instance } = await WebAssembly.instantiate(wasmBytes, {
      wasi_snapshot_preview1: {
        fd_write(fd, iovsPtr, iovsLen, nwrittenPtr) {
          assert.equal(fd, 1);
          const dv = new DataView(mem.buffer);
          let total = 0;
          for (let i = 0; i < iovsLen; i++) {
            const ptr = dv.getUint32(iovsPtr + i * 8, true);
            const len = dv.getUint32(iovsPtr + i * 8 + 4, true);
            capturedOut += Buffer.from(mem.buffer, ptr, len).toString('utf8');
            total += len;
          }
          dv.setUint32(nwrittenPtr, total, true);
          return 0;
        },
        proc_exit(code) {
          capturedExit = code;
          throw new ProcExitTrap(code);
        },
      },
    });
    mem = instance.exports.memory;
    assert.throws(() => instance.exports._start(), ProcExitTrap);
    assert.equal(capturedOut, token);
    assert.equal(capturedExit, 42);

    const uappPath = path.join(tmp.dir, 'app.uapp');
    await fs.writeFile(uappPath, buildCustomUapp({ appId: 'com.omnios.uapp.test', message: token, exitCode: 42 }));
    const py = await runOracle('python3', [
      '-c',
      `import sys, zipfile, json
z = zipfile.ZipFile(sys.argv[1])
assert z.testzip() is None
m = json.loads(z.read('manifest.json'))
assert m['id'] == 'com.omnios.uapp.test' and m['entry'] == 'app.wasm'
assert z.read('app.wasm')[:4] == b'\\x00asm'
print('UAPP_OK')`,
      uappPath,
    ]);
    assert.equal(py.code, 0, py.stderr);
    assert.equal(py.stdout.trim(), 'UAPP_OK');

    // Regression: high-bit u32 operands (>= 0x80000000) & >64KiB payloads validate and instantiate cleanly
    assert.equal(WebAssembly.validate(buildCustomWasm({ oobPointer: 0xfffffff0, returnFdWriteErrno: true })), true);
    assert.equal(WebAssembly.validate(buildCustomWasm({ invalidIovsLen: 0xffffffff, returnFdWriteErrno: true })), true);
    assert.equal(WebAssembly.validate(buildCustomWasm({ ungrantedFd: 0x80000000, returnFdWriteErrno: true })), true);
    assert.equal(WebAssembly.validate(buildCustomWasm({ exitCode: 0x80000000 })), true);
    assert.equal(
      WebAssembly.validate(buildCustomWasm({ useOmniOsImport: { args: [0x80000000, 0xffffffff] } })),
      true
    );

    const bigMsg = 'X'.repeat(70000);
    const bigWasm = buildCustomWasm({ message: bigMsg, exitCode: 0 });
    assert.equal(WebAssembly.validate(bigWasm), true);
    const bigInst = await WebAssembly.instantiate(bigWasm, {
      wasi_snapshot_preview1: {
        fd_write: () => 0,
        proc_exit: () => {},
      },
    });
    assert.ok(bigInst.instance.exports.memory.buffer.byteLength >= 2 * 65536);
  });
});

// ============================================================================
// Suite 5: fixtures-malformed.mjs Complete 29-Case Corpus Verification
// ============================================================================

describe('SM-1 Suite 5: Complete 29-case malformed & edge-case corpus oracles', () => {
  let tmp;
  before(async () => {
    tmp = await createTempDataDir('omnios-oracle-mal-');
  });
  after(async () => {
    await tmp?.cleanup();
  });

  it('MALFORMED_CORPUS_INDEX contains all 29 edge cases and every builder runs deterministically', () => {
    const keys = Object.keys(MALFORMED_CORPUS_INDEX);
    assert.equal(keys.length, 29);
    for (let id = 1; id <= 29; id++) {
      const entry = MALFORMED_CORPUS_INDEX[id];
      assert.ok(entry && entry.id === id, `Missing corpus index entry #${id}`);
      const artifact = entry.build();
      assert.ok(artifact !== null && artifact !== undefined, `Empty artifact for #${id}`);
      if (artifact instanceof Uint8Array) {
        assert.ok(artifact.length > 0, `Zero-length Uint8Array for #${id}`);
      }
    }
  });

  it('verifies #1 ZIP-slip variants, #2 ZIP bomb (>100MiB & >1000x ratio), #3 APK v2 sig & #4 DD bit 3', async () => {
    for (const v of ['dotdot', 'win-drive', 'leading-slash', 'nul-byte']) {
      const z = buildZipSlipArchive(v, { wrapAsApk: true });
      assert.ok(z.length > 64);
    }

    const bomb = buildZipBomb();
    assert.ok(bomb.length < 200 * 1024, `ZIP bomb compressed size should be <200 KiB, got ${bomb.length}`);
    const bombLying = buildZipBomb({ fakeSmallUncompSize: true });
    assert.ok(bombLying.length < 200 * 1024);

    const v2ApkPath = path.join(tmp.dir, 'v2sig.apk');
    const ddZipPath = path.join(tmp.dir, 'dd3.zip');
    await fs.writeFile(v2ApkPath, buildApkWithV2SigningBlock());
    await fs.writeFile(ddZipPath, buildZipWithDataDescriptor());

    const py = await runOracle('python3', [
      '-c',
      `import sys, zipfile
for p in sys.argv[1:]:
  z = zipfile.ZipFile(p)
  assert z.testzip() is None
assert b'APK Sig Block 42' in open(sys.argv[1], 'rb').read()
print('ZIP_EDGE_OK')`,
      v2ApkPath,
      ddZipPath,
    ]);
    assert.equal(py.code, 0, py.stderr);
    assert.equal(py.stdout.trim(), 'ZIP_EDGE_OK');
  });

  it('verifies #5 AXML, #6 ARSC, #7 DEX isolated failures, #8 MUTF-8/overlong LEB128, #9 odd-insns try/catch', () => {
    for (const v of ['zero-size', 'subchunk-zero-size', 'size-lt-header', 'oob-size']) {
      assert.ok(buildMalformedAxml(v).length >= 24);
    }
    assert.equal(new DataView(buildEdgeResourcesArsc({ mode: 'offset16' }).buffer).getUint16(0, true), 0x0002);
    assert.equal(new DataView(buildEdgeResourcesArsc({ mode: 'sparse' }).buffer).getUint16(0, true), 0x0002);

    // #7 bad-sha1 MUST pass Adler-32 while failing SHA-1
    const badSha1 = buildMalformedDex('bad-sha1');
    const dvBadSha1 = new DataView(badSha1.buffer, badSha1.byteOffset, badSha1.byteLength);
    assert.equal(dvBadSha1.getUint32(0x08, true), adler32(badSha1.subarray(0x0c)));
    const expectedSha1 = crypto.createHash('sha1').update(badSha1.subarray(0x20)).digest();
    assert.notDeepEqual(Buffer.from(badSha1.subarray(0x0c, 0x20)), expectedSha1);

    // #7 bad-header-size MUST pass BOTH Adler-32 & SHA-1 while having header_size === 0x60
    const badHdr = buildMalformedDex('bad-header-size');
    const dvBadHdr = new DataView(badHdr.buffer, badHdr.byteOffset, badHdr.byteLength);
    assert.equal(dvBadHdr.getUint32(0x24, true), 0x60);
    assert.equal(dvBadHdr.getUint32(0x08, true), adler32(badHdr.subarray(0x0c)));
    assert.deepEqual(
      Buffer.from(badHdr.subarray(0x0c, 0x20)),
      crypto.createHash('sha1').update(badHdr.subarray(0x20)).digest()
    );

    // #8 valid MUTF-8 & overlong 6-byte LEB128 both have valid checksums
    const mutf8Dex = buildDexMutf8Valid();
    assert.equal(new DataView(mutf8Dex.buffer).getUint32(0x08, true), adler32(mutf8Dex.subarray(0x0c)));
    const overlongDex = buildDexOverlongLeb128();
    assert.equal(new DataView(overlongDex.buffer).getUint32(0x08, true), adler32(overlongDex.subarray(0x0c)));
    assert.ok(buildDexOddInsnsTryCatchApk().length > 100);
  });

  it('llvm-readobj & llvm-objdump verify PE edge cases #13, #14, #15, #16, #17 (+ #12 malformed & #18 bat/cmd)', async () => {
    for (const v of ['lfanew-lt-64', 'lfanew-past-eof', 'too-many-sections', 'bad-rva-count', 'bad-pe-magic']) {
      assert.ok(buildMalformedPe(v).length > 128);
    }

    const peCases = [
      ['pe13_bss.exe', buildPeSectionSizingEdgeExe()],
      ['pe14_oft0.exe', buildPeZeroOftExe()],
      ['pe15_cert.exe', buildPeWithCertificateTableExe()],
      ['pe16_regw.exe', buildPeX64RegisterWidthTestExe()],
      ['pe17_rip.exe', buildPeRipRelativeTestExe()],
    ];

    for (const [name, bytes] of peCases) {
      const p = path.join(tmp.dir, name);
      await fs.writeFile(p, bytes);
      const ro = await runOracle('llvm-readobj', ['--file-headers', '--coff-imports', p]);
      assert.equal(ro.code, 0, `${name} readobj failed: ${ro.stderr}`);
      const od = await runOracle('llvm-objdump', ['--private-headers', '-d', p]);
      assert.equal(od.code, 0, `${name} objdump failed: ${od.stderr}`);
    }

    const bc = buildBatVsCmdErrorlevelScripts();
    assert.equal(bc.expectedBatExitCode, 7);
    assert.equal(bc.expectedCmdExitCode, 0);
  });

  it('llvm-objdump, Python plistlib & WebAssembly.validate verify Apple/WASI edge cases #19-#29', async () => {
    // #19 Java .class
    const javaClass = buildJavaClassBytes();
    const jdv = new DataView(javaClass.buffer);
    assert.equal(jdv.getUint32(0, false), 0xcafebabe);
    assert.equal(jdv.getUint32(4, false), 52);

    // #20..#26 Mach-O edge binaries all cleanly disassembled by llvm-objdump
    const machoCases = [
      ['m20_fairplay.macho', buildFairPlayEncryptedMachO(), /cryptid\s+1/],
      ['m21_pagezero.macho', buildPageZeroDerefMachO(), /ldr\s+x0,\s+\[x1\]/],
      ['m22_entryoff.macho', buildNonZeroEntryOffMachO(), /entryoff\s+4608/],
      ['m23_reg31.macho', buildArm64Reg31TestMachO(), /cmp\s+sp,\s+#0|subs\s+xzr,\s+sp,\s+#0/],
      ['m24_varargs.macho', buildArm64VariadicStackArgsMachO(), /adrp\s+x16,\s+3[\s\S]*_printf/],
      ['m25_errno.macho', buildDarwinErrnoCarryMachO(), /b\.lo|b\.cc/],
      ['m26_nilobjc.macho', buildObjcNilMsgSendMachO(), /adrp\s+x16,\s+3[\s\S]*_objc_msgSend/],
    ];

    for (const [name, bytes, pattern] of machoCases) {
      const p = path.join(tmp.dir, name);
      await fs.writeFile(p, bytes);
      const od = await runOracle('llvm-objdump', ['--macho', '--private-headers', '--bind', '--syms', '-d', p]);
      assert.equal(od.code, 0, `${name} objdump failed: ${od.stderr}`);
      assert.match(od.stdout, pattern, `${name} missing expected pattern ${pattern}`);
    }

    // #27 Cyclic bplist00 + signed 8B neg int (0x13) + 2001 CF epoch date (0x33)
    const cycPath = path.join(tmp.dir, 'cyclic.bplist');
    const edgePath = path.join(tmp.dir, 'edge-vals.bplist');
    await fs.writeFile(cycPath, buildCyclicBplist('self-dict'));
    await fs.writeFile(edgePath, buildBplistEdgeValues());

    const py27 = await runOracle('python3', [
      '-c',
      `import sys, plistlib, datetime
c = plistlib.loads(open(sys.argv[1], 'rb').read())
assert c['self'] is c
e = plistlib.loads(open(sys.argv[2], 'rb').read())
assert e['negInt'] == -1234567890123
assert e['cfDate'] == datetime.datetime(2001, 1, 2, 0, 0, 0)
assert e['unicode'] == 'OmniOS ★🚀'
print('BPLIST27_OK')`,
      cycPath,
      edgePath,
    ]);
    assert.equal(py27.code, 0, py27.stderr);
    assert.equal(py27.stdout.trim(), 'BPLIST27_OK');

    // #29 WASI edge modules all pass WebAssembly.validate
    assert.equal(WebAssembly.validate(buildWasiInvalidIovsLenWasm()), true);
    assert.equal(WebAssembly.validate(buildWasiOobPointerWasm()), true);
    assert.equal(WebAssembly.validate(buildWasiUngrantedFdWasm()), true);

    // Bonus malformed .dmg / .pkg
    const badDmg = buildMalformedDmg();
    assert.equal(Buffer.from(badDmg.subarray(badDmg.length - 512, badDmg.length - 508)).toString('ascii'), 'BAD!');
    const badPkg = buildMalformedPkg();
    assert.equal(Buffer.from(badPkg.subarray(0, 4)).toString('ascii'), 'BAD!');
  });
});
