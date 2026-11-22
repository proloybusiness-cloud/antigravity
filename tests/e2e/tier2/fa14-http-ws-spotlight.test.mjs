/**
 * OmniOS Tier 2 E2E Suite — FA-14: HTTP REST API v1, RFC 6455 WebSocket & Spotlight Search
 * Boundary, Corner & Negative Cases.
 * Covers PROJECT.md Features: F-061, F-062, F-063, F-064, Contract 7.
 *
 * STRICT INVARIANTS:
 * - Opaque-box only: imports ONLY Node 24 built-ins and ../lib/*.mjs.
 * - Zero skips, zero stubs, zero vacuous assertions.
 * - Clean try/finally teardown on every test.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';

import { startOmniServer } from '../lib/env.mjs';
import { buildCustomUapp } from '../lib/fixtures-apple-wasm.mjs';
import {
  buildMalformedPe,
  buildZipBomb,
  buildZipSlipArchive,
} from '../lib/fixtures-malformed.mjs';

function makeNonce() {
  return crypto.randomBytes(4).toString('hex');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function extractArrayStrict(payload, keys = ['packages', 'items', 'data', 'entries', 'results']) {
  if (Array.isArray(payload)) return payload;
  if (payload && typeof payload === 'object') {
    for (const k of keys) {
      if (Array.isArray(payload[k])) return payload[k];
    }
  }
  return null;
}

/**
 * Extracts matched items from Spotlight /api/v1/search across flat array, { results: [...] },
 * or categorized { apps, files, processes, settings, actions } response shapes.
 */
function extractSpotlightItems(json) {
  if (Array.isArray(json)) return json;
  if (!json || typeof json !== 'object') return [];
  if (Array.isArray(json.results)) return json.results;
  if (Array.isArray(json.items)) return json.items;
  if (Array.isArray(json.hits)) return json.hits;
  const out = [];
  for (const key of ['apps', 'packages', 'files', 'processes', 'settings', 'actions', 'matches']) {
    if (Array.isArray(json[key])) {
      out.push(...json[key]);
    }
  }
  return out;
}

/**
 * Sends a raw HTTP/1.1 request via node:http without WHATWG URL path normalization
 * (so literal `/../` traversal segments are transmitted verbatim on the wire).
 */
function rawHttpRequest({ host, port, method = 'GET', path: rawPath, headers = {}, body = null, timeoutMs = 5000 }) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host,
      port,
      method,
      path: rawPath,
      headers,
      timeout: timeoutMs,
    });

    req.once('response', (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.once('end', () => {
        const buf = Buffer.concat(chunks);
        resolve({
          upgraded: false,
          status: res.statusCode ?? 0,
          headers: res.headers,
          body: buf.toString('utf8'),
          buffer: buf,
        });
      });
    });

    req.once('upgrade', (res, socket) => {
      try { socket.destroy(); } catch { /* ignore */ }
      resolve({
        upgraded: true,
        status: res.statusCode ?? 101,
        headers: res.headers,
        body: '',
        buffer: Buffer.alloc(0),
      });
    });

    req.once('timeout', () => {
      req.destroy(new Error(`Raw HTTP request ${method} ${rawPath} timed out after ${timeoutMs}ms`));
    });

    req.once('error', (err) => reject(err));

    if (body !== null && body !== undefined) {
      req.write(body);
    }
    req.end();
  });
}

async function postPackagePayload(api, bytes, filename) {
  const b64 = Buffer.from(bytes).toString('base64');
  let res = await api.post('/api/v1/packages/install', {
    base64: b64,
    data: b64,
    filename,
  });
  if (res.status === 415) {
    res = await api.post('/api/v1/packages/install', bytes, {
      query: { filename },
      headers: {
        'content-type': 'application/octet-stream',
        'x-filename': filename,
      },
    });
  }
  return res;
}

describe('Tier 2 — FA-14: HTTP REST API v1, RFC 6455 WebSocket & Spotlight Search (Boundary & Negative)', () => {
  it('T2-FA14-01 [F-062]: HTTP REST invalid JSON bodies rejected with 400 without crashing server', async () => {
    let srv = null;
    try {
      srv = await startOmniServer();

      const targets = [
        '/api/v1/shell/exec',
        '/api/v1/ipc/notifications',
        '/api/v1/vfs/mkdir',
      ];
      const malformedBodies = ['{broken-json', '{"unclosed": [1, 2'];

      for (const endpoint of targets) {
        for (const badBody of malformedBodies) {
          const res = await srv.api.post(endpoint, badBody, {
            headers: { 'content-type': 'application/json' },
          });
          assert.equal(
            res.status,
            400,
            `Expected HTTP 400 for malformed JSON on POST ${endpoint}, got ${res.status}: ${res.text}`
          );
          assert.ok(
            res.text.trim().length > 0,
            `Expected non-empty structured error body on 400 for POST ${endpoint}`
          );
        }
      }

      // Empty body with application/json content-type -> clean 4xx (never 500)
      const emptyRes = await srv.api.post('/api/v1/shell/exec', '', {
        headers: { 'content-type': 'application/json' },
      });
      assert.ok(
        emptyRes.status >= 400 && emptyRes.status < 500,
        `Expected HTTP 4xx for empty JSON body on /api/v1/shell/exec, got ${emptyRes.status}: ${emptyRes.text}`
      );

      // Server remains completely healthy
      const health = await srv.api.get('/api/health', { expectOk: true });
      assert.equal(health.status, 200);
      assert.equal(health.json?.ok, true);
    } finally {
      if (srv) await srv.stop().catch(() => {});
    }
  });

  it('T2-FA14-02 [F-062]: Unknown REST endpoints return 404 (non-HTML) & unsupported HTTP methods return 405/404', async () => {
    let srv = null;
    try {
      srv = await startOmniServer();
      const nonce = makeNonce();

      const missingRoutes = [
        { method: 'GET', url: '/api/v1/nonexistent-endpoint' },
        { method: 'POST', url: '/api/v1/does-not-exist/subpath', body: {} },
        { method: 'GET', url: '/api/v1/processes/999999' },
        { method: 'GET', url: `/api/v1/packages/com.does.not.exist.${nonce}` },
      ];

      for (const route of missingRoutes) {
        const res = await srv.api.request(route.method, route.url, { body: route.body });
        assert.equal(
          res.status,
          404,
          `Expected HTTP 404 for ${route.method} ${route.url}, got ${res.status}: ${res.text.slice(0, 200)}`
        );
        assert.ok(
          !res.text.toLowerCase().includes('<!doctype html'),
          `API 404 on ${route.method} ${route.url} must not return HTML SPA fallback`
        );
      }

      const badMethods = [
        { method: 'DELETE', url: '/api/health' },
        { method: 'PUT', url: '/api/v1/health', body: {} },
        { method: 'DELETE', url: '/api/v1/kernel/status' },
        { method: 'PATCH', url: '/api/v1/search', body: { q: 'x' } },
      ];

      for (const route of badMethods) {
        const res = await srv.api.request(route.method, route.url, { body: route.body });
        assert.ok(
          res.status === 404 || res.status === 405,
          `Expected HTTP 404 or 405 for unsupported ${route.method} ${route.url}, got ${res.status}: ${res.text.slice(0, 200)}`
        );
      }

      const health = await srv.api.get('/api/health', { expectOk: true });
      assert.equal(health.status, 200);
      assert.equal(health.json?.ok, true);
    } finally {
      if (srv) await srv.stop().catch(() => {});
    }
  });

  it('T2-FA14-03 [F-062]: Corrupt, malicious & oversized /api/v1/packages/install payloads rejected cleanly without corrupting catalog', async () => {
    let srv = null;
    try {
      srv = await startOmniServer();
      const nonce = makeNonce();

      const beforeListRes = await srv.api.get('/api/v1/packages', { expectOk: true });
      const beforePkgs = extractArrayStrict(beforeListRes.json);
      assert.ok(Array.isArray(beforePkgs), `Expected package array from GET /api/v1/packages, got: ${beforeListRes.text}`);
      const beforeIds = beforePkgs.map((p) => p?.appId ?? p?.id).filter(Boolean).sort();

      // (a) Garbage bytes, (b) Malformed PE, (c) ZIP-slip APK, (d) ZIP bomb
      const badPayloads = [
        { label: 'garbage bytes', bytes: Buffer.from(`GARBAGE_NOT_A_PACKAGE_${nonce}`), filename: `bogus-${nonce}.apk` },
        { label: 'malformed PE', bytes: buildMalformedPe('bad-pe-magic'), filename: `badpe-${nonce}.exe` },
        { label: 'ZIP-slip APK', bytes: buildZipSlipArchive('dotdot', { wrapAsApk: true }), filename: `slip-${nonce}.apk` },
        { label: 'ZIP bomb', bytes: buildZipBomb(), filename: `bomb-${nonce}.zip` },
      ];

      for (const item of badPayloads) {
        const res = await postPackagePayload(srv.api, item.bytes, item.filename);
        assert.ok(
          res.status >= 400 && res.status < 500,
          `Expected HTTP 4xx rejecting ${item.label} on /api/v1/packages/install, got ${res.status}: ${res.text.slice(0, 200)}`
        );
      }

      // (e) Oversized 12 MiB garbage payload -> clean 4xx (413/400/422) OR early socket reset, followed by live 200 /api/health
      const oversized = Buffer.alloc(12 * 1024 * 1024, 0x41);
      let oversizedStatus = null;
      let oversizedSocketAbort = false;
      try {
        const overRes = await srv.api.post('/api/v1/packages/install', oversized, {
          query: { filename: `huge-${nonce}.bin` },
          headers: {
            'content-type': 'application/octet-stream',
            'x-filename': `huge-${nonce}.bin`,
          },
          timeoutMs: 10000,
        });
        oversizedStatus = overRes.status;
      } catch (err) {
        const msg = String(err?.message ?? err?.cause?.code ?? '');
        if (/ECONNRESET|EPIPE|fetch failed|socket|abort|closed/i.test(msg)) {
          oversizedSocketAbort = true;
        } else {
          throw err;
        }
      }
      if (!oversizedSocketAbort) {
        assert.ok(
          oversizedStatus >= 400 && oversizedStatus < 500,
          `Expected HTTP 4xx (413/400/422) for 12 MiB oversized garbage upload, got ${oversizedStatus}`
        );
      }

      // Immediately confirm server is alive and package list matches baseline verbatim
      const health = await srv.api.get('/api/health', { expectOk: true });
      assert.equal(health.status, 200);
      assert.equal(health.json?.ok, true);

      const afterListRes = await srv.api.get('/api/v1/packages', { expectOk: true });
      const afterPkgs = extractArrayStrict(afterListRes.json);
      assert.ok(Array.isArray(afterPkgs));
      const afterIds = afterPkgs.map((p) => p?.appId ?? p?.id).filter(Boolean).sort();
      assert.deepEqual(afterIds, beforeIds, 'Malicious/corrupt package uploads must not modify installed packages');

      // Confirm a valid dynamic .uapp installs cleanly right afterward
      const validAppId = `com.omnios.uapp.afterbad.${nonce}`;
      const validUapp = buildCustomUapp({
        appId: validAppId,
        name: `AfterBad_${nonce}`,
        message: `AFTER_BAD_${nonce}\n`,
      });
      let okRes = await postPackagePayload(srv.api, validUapp, `valid-${nonce}.uapp`);
      if (okRes.status === 400 || okRes.status === 415) {
        okRes = await srv.api.post('/api/v1/packages/install', validUapp, {
          query: { filename: `valid-${nonce}.uapp` },
          headers: {
            'content-type': 'application/octet-stream',
            'x-filename': `valid-${nonce}.uapp`,
          },
        });
      }
      assert.ok(okRes.ok, `Expected valid follow-up .uapp install to succeed (2xx), got ${okRes.status}: ${okRes.text}`);
    } finally {
      if (srv) await srv.stop().catch(() => {});
    }
  });

  it('T2-FA14-04 [F-064]: Spotlight GET /api/v1/search handles empty, whitespace, regex metacharacters, SQLi chars & non-matching queries safely', async () => {
    let srv = null;
    try {
      srv = await startOmniServer();
      const nonce = makeNonce();

      const queries = [
        { label: 'empty q=', query: { q: '' }, expectZero: false },
        { label: 'missing q', query: {}, expectZero: false },
        { label: 'whitespace q', query: { q: '   ' }, expectZero: false },
        { label: 'regex metachars', query: { q: '.*([?+' }, expectZero: true },
        { label: 'ReDoS pattern', query: { q: '(a+)+$' }, expectZero: false },
        { label: 'unclosed bracket', query: { q: '[unclosed\\' }, expectZero: true },
        { label: 'SQLi probe', query: { q: "'; DROP TABLE inodes; --" }, expectZero: false },
        { label: 'unique non-match', query: { q: `zz_nomatch_${nonce}_9999` }, expectZero: true },
      ];

      for (const tc of queries) {
        const t0 = Date.now();
        const res = await srv.api.get('/api/v1/search', { query: tc.query });
        assert.equal(
          res.status,
          200,
          `Spotlight query "${tc.label}" must return HTTP 200 (never 500), got ${res.status}: ${res.text}`
        );
        assert.ok(Date.now() - t0 < 3000, `Spotlight query "${tc.label}" took too long (possible ReDoS)`);
        assert.notEqual(res.json, null, `Spotlight query "${tc.label}" must return valid JSON`);

        if (tc.expectZero) {
          const items = extractSpotlightItems(res.json);
          assert.equal(
            items.length,
            0,
            `Spotlight query "${tc.label}" expected 0 matched items, got ${items.length}: ${res.text}`
          );
        }
      }

      // Verify VFS DB and Spotlight indexing remain completely intact after SQLi/regex probes
      const fileName = `spot-ok-${nonce}.txt`;
      const filePath = `/home/user/Documents/${fileName}`;
      let writeRes = await srv.api.put('/api/v1/vfs/file', { path: filePath, content: `SPOT_${nonce}`, data: `SPOT_${nonce}` });
      if (writeRes.status === 404 || writeRes.status === 405) {
        writeRes = await srv.api.post('/api/v1/vfs/file', { path: filePath, content: `SPOT_${nonce}`, data: `SPOT_${nonce}` });
      }
      assert.ok(writeRes.ok, `Failed writing test file for Spotlight integrity check: ${writeRes.status} ${writeRes.text}`);

      const hitRes = await srv.api.get('/api/v1/search', { query: { q: `spot-ok-${nonce}` }, expectOk: true });
      assert.equal(hitRes.status, 200);
      assert.ok(
        JSON.stringify(hitRes.json).includes(fileName),
        `Expected Spotlight to still index and find "${fileName}", got: ${hitRes.text}`
      );
    } finally {
      if (srv) await srv.stop().catch(() => {});
    }
  });

  it('T2-FA14-05 [F-063]: RFC 6455 /ws malformed JSON text frames & non-object JSON envelopes keep server & sibling WS clients healthy', async () => {
    let srv = null;
    let wsBad = null;
    let wsSibling = null;
    let wsFresh = null;
    try {
      srv = await startOmniServer();
      const nonce = makeNonce();

      wsBad = await srv.connectWs();
      wsSibling = await srv.connectWs();

      await wsBad.waitForType('compositor:snapshot', { timeoutMs: 5000 });
      await wsSibling.waitForType('compositor:snapshot', { timeoutMs: 5000 });

      // Send malformed JSON & non-object JSON envelopes on wsBad
      const badFrames = [
        '{not-valid-json',
        '',
        'null',
        '42',
        '"str"',
        '[1,2,3]',
        '{"payload":{"missingType":true}}',
      ];
      for (const frame of badFrames) {
        if (!wsBad.isOpen()) break;
        try {
          wsBad.send(frame);
        } catch {
          // server may choose to close the misbehaving client; sibling MUST remain healthy
          break;
        }
        await sleep(25);
      }

      // Sibling WS client MUST remain open, respond to ping -> pong, and receive live broadcasts
      assert.equal(wsSibling.isOpen(), true, 'Sibling WS client must remain open after peer sent malformed JSON');
      const pingMark = wsSibling.mark();
      wsSibling.send({ type: 'ping' });
      const pong = await wsSibling.waitForMessage((m) => /pong/i.test(String(m?.type ?? '')), {
        since: pingMark,
        timeoutMs: 4000,
      });
      assert.ok(pong, 'Expected sibling WS to receive pong');

      const notifMark = wsSibling.mark();
      const notifTitle = `WS_ALIVE_${nonce}`;
      const notifRes = await srv.api.post('/api/v1/ipc/notifications', {
        appId: `com.omnios.ws.${nonce}`,
        platform: 'universal',
        title: notifTitle,
        body: 'Sibling WS health probe',
        priority: 'normal',
      });
      assert.ok(notifRes.ok, `Expected notification POST to succeed, got ${notifRes.status}: ${notifRes.text}`);

      const notifEvt = await wsSibling.waitForMessage(
        (m) => m?.type === 'notification:posted' && JSON.stringify(m).includes(notifTitle),
        { since: notifMark, timeoutMs: 5000 }
      );
      assert.ok(notifEvt, 'Expected sibling WS to receive notification:posted');

      // Fresh 3rd WS client connects and receives compositor:snapshot cleanly
      wsFresh = await srv.connectWs();
      const snap = await wsFresh.waitForType('compositor:snapshot', { timeoutMs: 5000 });
      assert.ok(snap && snap.type === 'compositor:snapshot');

      const health = await srv.api.get('/api/health', { expectOk: true });
      assert.equal(health.status, 200);
      assert.equal(health.json?.ok, true);
    } finally {
      if (wsFresh) await wsFresh.close().catch(() => {});
      if (wsSibling) await wsSibling.close().catch(() => {});
      if (wsBad) await wsBad.close().catch(() => {});
      if (srv) await srv.stop().catch(() => {});
    }
  });

  it('T2-FA14-06 [F-063]: RFC 6455 /ws unknown message { type: "unknown:op" } & malformed control payloads do not corrupt compositor state', async () => {
    let srv = null;
    let ws1 = null;
    let wsSibling = null;
    try {
      srv = await startOmniServer();
      const nonce = makeNonce();

      ws1 = await srv.connectWs();
      wsSibling = await srv.connectWs();

      await ws1.waitForType('compositor:snapshot', { timeoutMs: 5000 });
      await wsSibling.waitForType('compositor:snapshot', { timeoutMs: 5000 });

      const baseSnapRes = await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true });
      const baseShellMode = baseSnapRes.json?.shellMode ?? baseSnapRes.json?.snapshot?.shellMode;
      assert.ok(typeof baseShellMode === 'string' && baseShellMode.length > 0, `Expected baseline shellMode, got: ${baseSnapRes.text}`);

      const badMessages = [
        { type: 'unknown:op', payload: { x: 1 } },
        { type: 'compositor:move', payload: { windowId: `no-such-win-${nonce}`, x: 'NaN', y: null } },
        { type: 'shell:mode', payload: { mode: 'invalid-mode-xyz' } },
        { type: 'compositor:input', payload: { windowId: `no-such-win-${nonce}`, event: null } },
      ];

      for (const msg of badMessages) {
        if (!ws1.isOpen()) break;
        ws1.send(msg);
        await sleep(30);
      }

      // Backend shellMode MUST NOT be corrupted to 'invalid-mode-xyz'
      const afterSnapRes = await srv.api.get('/api/v1/compositor/snapshot', { expectOk: true });
      const afterShellMode = afterSnapRes.json?.shellMode ?? afterSnapRes.json?.snapshot?.shellMode;
      assert.notEqual(afterShellMode, 'invalid-mode-xyz', 'WS shell:mode accepted invalid mode!');
      assert.equal(afterShellMode, baseShellMode, `Expected shellMode to remain "${baseShellMode}", got "${afterShellMode}"`);

      // Sibling client receives live broadcast cleanly
      assert.equal(wsSibling.isOpen(), true);
      const mark = wsSibling.mark();
      const notifTitle = `WS_UNK_${nonce}`;
      await srv.api.post('/api/v1/ipc/notifications', {
        appId: `com.omnios.wsunk.${nonce}`,
        platform: 'universal',
        title: notifTitle,
        body: 'Post-unknown-op verification',
        priority: 'normal',
      }, { expectOk: true });
      const evt = await wsSibling.waitForMessage(
        (m) => m?.type === 'notification:posted' && JSON.stringify(m).includes(notifTitle),
        { since: mark, timeoutMs: 5000 }
      );
      assert.ok(evt);

      // If ws1 is still open, ping/pong still works cleanly
      if (ws1.isOpen()) {
        const pMark = ws1.mark();
        ws1.send({ type: 'ping' });
        const pong = await ws1.waitForMessage((m) => /pong/i.test(String(m?.type ?? '')), {
          since: pMark,
          timeoutMs: 4000,
        });
        assert.ok(pong);
      }
    } finally {
      if (wsSibling) await wsSibling.close().catch(() => {});
      if (ws1) await ws1.close().catch(() => {});
      if (srv) await srv.stop().catch(() => {});
    }
  });

  it('T2-FA14-07 [F-062/F-063]: Static ui/ path traversal defense (raw HTTP /../package.json & /%2e%2e/) & malformed /ws upgrade rejection', async () => {
    let srv = null;
    let wsValid = null;
    try {
      srv = await startOmniServer();

      // 1. Send literal unnormalized path traversal probes over raw node:http
      const traversalPaths = [
        '/../package.json',
        '/%2e%2e/package.json',
        '/..%2f..%2fetc/passwd',
      ];
      for (const p of traversalPaths) {
        const res = await rawHttpRequest({ host: srv.host, port: srv.port, method: 'GET', path: p });
        assert.ok(res.status < 500, `Path traversal probe "${p}" crashed server with HTTP ${res.status}`);
        assert.ok(
          !res.body.includes('"dependencies"') && !res.body.includes('"scripts"'),
          `Path traversal probe "${p}" leaked repository package.json!`
        );
        assert.ok(
          !res.body.includes('root:x:0:0'),
          `Path traversal probe "${p}" leaked /etc/passwd!`
        );
        assert.ok(
          res.status >= 400 || /<!doctype html|<html/i.test(res.body),
          `Path traversal probe "${p}" must return HTTP 4xx (or strictly safe ui/index.html fallback), got ${res.status}: ${res.body.slice(0, 120)}`
        );
      }

      // 2. Malformed /ws HTTP Upgrade omitting required Sec-WebSocket-Key header
      let upgRes = null;
      let upgErr = null;
      try {
        upgRes = await rawHttpRequest({
          host: srv.host,
          port: srv.port,
          method: 'GET',
          path: '/ws',
          headers: {
            Connection: 'Upgrade',
            Upgrade: 'websocket',
            'Sec-WebSocket-Version': '13',
            // Intentionally omit Sec-WebSocket-Key!
          },
        });
      } catch (err) {
        upgErr = err;
      }

      if (upgErr) {
        if (upgErr.code === 'ERR_ASSERTION') throw upgErr;
        // Server closing the raw TCP socket immediately on malformed upgrade is also RFC 6455 compliant
        const errText = String(upgErr?.message ?? upgErr?.code ?? '');
        assert.ok(
          /ECONNRESET|socket hang up|EPIPE|closed/i.test(errText),
          `Expected clean 4xx or TCP socket close rejecting malformed /ws upgrade, got unexpected error: ${errText}`
        );
      } else {
        assert.ok(upgRes, 'Expected HTTP response or TCP close for malformed /ws upgrade');
        assert.equal(upgRes.upgraded, false, 'Malformed /ws upgrade missing Sec-WebSocket-Key must NOT upgrade to 101');
        assert.ok(
          upgRes.status >= 400 && upgRes.status < 500,
          `Expected HTTP 4xx rejecting malformed /ws upgrade, got ${upgRes.status}`
        );
      }

      // 3. Server and valid WebSocket upgrades remain completely healthy
      const health = await srv.api.get('/api/health', { expectOk: true });
      assert.equal(health.status, 200);
      assert.equal(health.json?.ok, true);

      wsValid = await srv.connectWs();
      const snap = await wsValid.waitForType('compositor:snapshot', { timeoutMs: 5000 });
      assert.ok(snap && snap.type === 'compositor:snapshot');
    } finally {
      if (wsValid) await wsValid.close().catch(() => {});
      if (srv) await srv.stop().catch(() => {});
    }
  });
});
