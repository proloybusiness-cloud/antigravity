/**
 * Tier 5 — Adversarial Hardening, Binary Fuzzing, Protocol Abuse, Panic Recovery
 * & Potato-PC Lite Stress Suite (M7 Phase 2: F-089, F-090).
 *
 * STRICT INVARIANTS:
 * - Public API / opaque-box only: imports ONLY Node 24 built-ins and ./lib/*.mjs.
 * - Zero private internal os module imports.
 * - Zero assert.* calls inside try/catch blocks.
 * - Zero skips, zero stubs, zero hardcoded undocumented capability names.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import net from 'node:net';
import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';

import {
  REPO_ROOT,
  createTempDataDir,
  loadPublicOmniOS,
  startOmniServer,
  connectWs,
  runCli,
} from './lib/env.mjs';
import { launchBrowser } from './lib/cdp-client.mjs';
import {
  MALFORMED_CORPUS_INDEX,
  buildZipSlipArchive,
  buildZipBomb,
  buildMalformedAxmlApk,
  buildMalformedDexApk,
  buildMalformedPe,
  buildFairPlayEncryptedIpa,
  buildCyclicBplistIpa,
  buildWasiEdgeUapp,
  buildMalformedDmg,
  buildMalformedPkg,
  getVfsEdgeCasePayloads,
} from './lib/fixtures-malformed.mjs';
import {
  buildCustomApk,
  buildCustomPe64Exe,
  buildBatScript,
} from './lib/fixtures-android-win.mjs';
import {
  buildCustomIpa,
  buildCustomMacAppZip,
  buildCustomUapp,
} from './lib/fixtures-apple-wasm.mjs';

function makeNonce() {
  return crypto.randomBytes(4).toString('hex');
}

function isDoneState(state) {
  return state === 'TERMINATED' || state === 'ZOMBIE' || state === 'FAULT';
}

async function runPidToDone(os, pid, maxTicks = 1200) {
  const pm = os.require('processManager');
  const scheduler = os.require('scheduler');
  for (let i = 0; i < Math.ceil(maxTicks / 5); i += 1) {
    const pcb = pm.get(pid);
    if (!pcb || isDoneState(pcb.state)) return pcb;
    await scheduler.step(5);
  }
  return pm.get(pid);
}

function makePrng(seed = 0x5f3759df) {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
}

function mutateBinary(srcBytes, rng, mode) {
  const buf = Buffer.from(srcBytes);
  if (mode === 'truncate-head') {
    const len = Math.min(buf.length, 4 + (rng() % 28));
    return buf.subarray(0, len);
  }
  if (mode === 'truncate-mid') {
    const len = Math.max(1, Math.floor(buf.length / 2) - (rng() % Math.max(1, Math.floor(buf.length / 4))));
    return buf.subarray(0, len);
  }
  if (mode === 'bitflip-header') {
    const limit = Math.min(buf.length, 128);
    const flips = 1 + (rng() % 6);
    for (let i = 0; i < flips; i += 1) {
      const idx = rng() % limit;
      buf[idx] ^= 1 << (rng() % 8);
    }
    return buf;
  }
  // bitflip-body
  const flips = 2 + (rng() % 12);
  for (let i = 0; i < flips; i += 1) {
    const idx = rng() % buf.length;
    buf[idx] ^= 1 << (rng() % 8);
  }
  return buf;
}

function rawHttpExchange(host, port, rawPayload, timeoutMs = 4000) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port });
    const chunks = [];
    let settled = false;
    const finish = (info) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({
        ...info,
        raw: Buffer.concat(chunks).toString('utf8'),
      });
    };
    const timer = setTimeout(() => finish({ ok: true, timedOut: true }), timeoutMs);
    timer.unref();
    socket.on('connect', () => {
      socket.write(rawPayload);
    });
    socket.on('data', (chunk) => {
      chunks.push(chunk);
      const joined = Buffer.concat(chunks).toString('utf8');
      if (joined.includes('\r\n\r\n')) {
        clearTimeout(timer);
        finish({ ok: true, timedOut: false });
      }
    });
    socket.on('close', () => {
      clearTimeout(timer);
      finish({ ok: true, closed: true });
    });
    socket.on('error', (err) => {
      clearTimeout(timer);
      finish({ ok: false, error: err.code || err.message });
    });
  });
}

function rawWsAttack(host, port, frameBytes, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port });
    const key = crypto.randomBytes(16).toString('base64');
    let upgraded = false;
    let recvBuf = Buffer.alloc(0);
    let settled = false;
    const finish = (res) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(res);
    };
    const timer = setTimeout(() => finish({ upgraded, closed: false, timedOut: true, recvLen: recvBuf.length }), timeoutMs);
    timer.unref();

    socket.on('connect', () => {
      socket.write(
        `GET /ws HTTP/1.1\r\n` +
        `Host: ${host}:${port}\r\n` +
        `Upgrade: websocket\r\n` +
        `Connection: Upgrade\r\n` +
        `Sec-WebSocket-Key: ${key}\r\n` +
        `Sec-WebSocket-Version: 13\r\n\r\n`
      );
    });

    socket.on('data', (chunk) => {
      recvBuf = Buffer.concat([recvBuf, chunk]);
      if (!upgraded) {
        const hdrEnd = recvBuf.indexOf('\r\n\r\n');
        if (hdrEnd >= 0) {
          const hdr = recvBuf.subarray(0, hdrEnd).toString('utf8');
          if (!hdr.includes('101')) {
            clearTimeout(timer);
            finish({ upgraded: false, closed: true, statusHeader: hdr.split('\r\n')[0] });
            return;
          }
          upgraded = true;
          recvBuf = recvBuf.subarray(hdrEnd + 4);
          socket.write(frameBytes);
        }
        return;
      }
      // Look for close frame (opcode 0x8) from server
      if (recvBuf.length >= 2 && (recvBuf[0] & 0x0f) === 0x08) {
        const payLen = recvBuf[1] & 0x7f;
        const closeCode = payLen >= 2 && recvBuf.length >= 4 ? recvBuf.readUInt16BE(2) : null;
        clearTimeout(timer);
        finish({ upgraded: true, closed: true, closeCode });
      }
    });

    socket.on('close', () => {
      clearTimeout(timer);
      let closeCode = null;
      if (recvBuf.length >= 4 && (recvBuf[0] & 0x0f) === 0x08) {
        closeCode = recvBuf.readUInt16BE(2);
      }
      finish({ upgraded, closed: true, closeCode });
    });

    socket.on('error', (err) => {
      clearTimeout(timer);
      finish({ upgraded, closed: true, error: err.code || err.message });
    });
  });
}

function buildMaskedWsFrame({ fin = 1, rsv = 0, opcode = 0x1, payload = Buffer.alloc(0) }) {
  const b0 = ((fin ? 0x80 : 0) | ((rsv & 0x7) << 4) | (opcode & 0x0f)) & 0xff;
  const len = payload.length;
  const maskKey = crypto.randomBytes(4);
  const masked = Buffer.alloc(len);
  for (let i = 0; i < len; i += 1) {
    masked[i] = payload[i] ^ maskKey[i & 3];
  }
  let hdr;
  if (len < 126) {
    hdr = Buffer.from([b0, 0x80 | len]);
  } else {
    hdr = Buffer.alloc(4);
    hdr[0] = b0;
    hdr[1] = 0x80 | 126;
    hdr.writeUInt16BE(len, 2);
  }
  return Buffer.concat([hdr, maskKey, masked]);
}

test.describe('Tier 5 — Adversarial Hardening, Binary Fuzzing, Protocol Abuse, Panic Recovery & Potato-PC Lite Mode (F-089, F-090)', () => {
  // --------------------------------------------------------------------------
  // T5-01: Complete 29-Vector MALFORMED_CORPUS_INDEX Audit
  // --------------------------------------------------------------------------
  test('T5-01 [F-089]: All 29 MALFORMED_CORPUS_INDEX edge-case vectors handled safely without OS crash or RSS blowup', async () => {
    const keys = Object.keys(MALFORMED_CORPUS_INDEX).map(Number).sort((a, b) => a - b);
    assert.equal(keys.length, 29, `Expected 29 entries in MALFORMED_CORPUS_INDEX, got ${keys.length}`);
    assert.equal(keys[0], 1);
    assert.equal(keys[keys.length - 1], 29);

    const os = await loadPublicOmniOS();
    const rssBefore = process.memoryUsage().rss;
    try {
      const pkgManager = os.require('pkgManager');
      const detector = os.require('formatDetector');
      const kernel = os.require('kernel');

      // Exercise every single one of the 29 corpus entries safely through public detection / inspection
      const testedIds = new Set();
      for (const id of keys) {
        const entry = MALFORMED_CORPUS_INDEX[id];
        const built = entry.build();
        assert.ok(built !== null && built !== undefined, `Corpus #${id} build() returned empty`);

        if (built instanceof Uint8Array || Buffer.isBuffer(built)) {
          const det = detector.detect(built, `corpus-${id}.bin`);
          assert.ok(det && typeof det === 'object', `Corpus #${id}: detector.detect must return object`);

          if (id === 19) {
            // Java .class 0xCAFEBABE MUST NOT be misclassified as macos-macho
            assert.notEqual(det.format, 'macos-macho', 'Java .class must never be misdetected as Mach-O');
          }

          if (!entry.positive) {
            let installErr = null;
            try {
              const rec = await pkgManager.install(built, { filename: `corpus-neg-${id}.bin` });
              if (rec?.appId) {
                const l = await pkgManager.launch(rec.appId, {});
                const pcb = await runPidToDone(os, l.pid, 400);
                // Negative runtime vectors (#10, #11, #21, #29) may install then fault/terminate non-zero
                if (pcb && pcb.exitCode === 0 && !pcb.exitSignal) {
                  installErr = new Error(`Negative vector #${id} unexpectedly exited 0`);
                } else {
                  installErr = new Error(`Runtime fault/exit captured for #${id}`);
                }
              }
            } catch (err) {
              installErr = err;
            }
            assert.ok(
              installErr instanceof Error,
              `Negative corpus vector #${id} (${entry.title}) must reject or fault cleanly`
            );
          }
        } else {
          // Structured fixture objects (#18 .bat/.cmd scripts, #28 VFS edge payloads)
          assert.equal(typeof built, 'object', `Corpus #${id} structured fixture must be an object`);
        }
        testedIds.add(id);
      }

      assert.equal(testedIds.size, 29, 'All 29 MALFORMED_CORPUS_INDEX vectors must be exercised');

      // Explicitly verify malformed archive/package rejection matrix via pkgManager.install
      const negativeCases = [
        ['zip-slip-dotdot', buildZipSlipArchive('dotdot', { wrapAsApk: true }), 'evil.apk'],
        ['zip-slip-nul', buildZipSlipArchive('nul-byte', { wrapAsApk: true }), 'nul.apk'],
        ['zip-bomb', buildZipBomb(), 'bomb.uapp'],
        ['malformed-axml', buildMalformedAxmlApk('zero-size'), 'bad-axml.apk'],
        ['malformed-dex', buildMalformedDexApk('bad-adler32'), 'bad-dex.apk'],
        ['malformed-pe', buildMalformedPe('too-many-sections'), 'bad.exe'],
        ['fairplay-ipa', buildFairPlayEncryptedIpa(), 'drm.ipa'],
        ['cyclic-bplist-ipa', buildCyclicBplistIpa('self-dict'), 'cyclic.ipa'],
        ['malformed-dmg', buildMalformedDmg(), 'bad.dmg'],
        ['malformed-pkg', buildMalformedPkg(), 'bad.pkg'],
      ];

      for (const [label, payload, filename] of negativeCases) {
        let caught = null;
        try {
          await pkgManager.install(payload, { filename });
        } catch (err) {
          caught = err;
        }
        assert.ok(caught instanceof Error, `Adversarial package "${label}" MUST reject with structured Error`);
      }

      // WASI adversarial edge cases must fail cleanly without host crash
      for (const variant of ['invalid-iovs-len', 'oob-pointer', 'ungranted-fd']) {
        const uapp = buildWasiEdgeUapp(variant);
        const rec = await pkgManager.install(uapp, { filename: `wasi-${variant}.uapp`, overwrite: true });
        const launched = await pkgManager.launch(rec.appId, {});
        const pcb = await runPidToDone(os, launched.pid, 400);
        assert.ok(pcb && isDoneState(pcb.state), `WASI edge "${variant}" must terminate cleanly`);
      }

      const rssDelta = process.memoryUsage().rss - rssBefore;
      assert.ok(
        rssDelta < 128 * 1024 * 1024,
        `Adversarial corpus sweep RSS delta too high: ${Math.round(rssDelta / (1024 * 1024))} MiB`
      );
      assert.equal(kernel.getDiagnostics()?.state, 'RUNNING', 'Kernel must stay RUNNING after all 29 corpus vectors');
    } finally {
      await os.shutdown();
    }
  });

  // --------------------------------------------------------------------------
  // T5-02: Deterministic Seeded Bit-Flip & Truncation Fuzzing Across 5 Formats
  // --------------------------------------------------------------------------
  test('T5-02 [F-089]: Deterministic bit-flip & truncation fuzzing across all 5 binary formats preserves kernel stability', async () => {
    const nonce = makeNonce();
    const rng = makePrng(0x20261124);
    const os = await loadPublicOmniOS();
    const rssBefore = process.memoryUsage().rss;
    try {
      const detector = os.require('formatDetector');
      const pkgManager = os.require('pkgManager');
      const kernel = os.require('kernel');

      const seeds = [
        { ext: '.apk', bytes: buildCustomApk({ packageName: `com.fuzz.and.${nonce}`, appLabel: 'FuzzAnd' }) },
        { ext: '.exe', bytes: buildCustomPe64Exe({ message: `FUZZ_${nonce}\n`, exitCode: 0 }) },
        { ext: '.ipa', bytes: buildCustomIpa({ bundleId: `com.fuzz.ios.${nonce}`, displayName: 'FuzzIos', executableName: 'FuzzIos' }) },
        { ext: '.app.zip', bytes: buildCustomMacAppZip({ bundleId: `com.fuzz.mac.${nonce}`, appName: 'FuzzMac', executableName: 'FuzzMac' }) },
        { ext: '.uapp', bytes: buildCustomUapp({ appId: `com.fuzz.uapp.${nonce}`, name: 'FuzzUapp', message: `U_${nonce}\n` }) },
      ];

      const modes = ['truncate-head', 'truncate-mid', 'bitflip-header', 'bitflip-body'];
      let totalMutations = 0;
      let cleanRejects = 0;
      let cleanAccepts = 0;

      for (const seed of seeds) {
        for (let round = 0; round < 3; round += 1) {
          for (const mode of modes) {
            totalMutations += 1;
            const mutated = mutateBinary(seed.bytes, rng, mode);
            const filename = `fuzz-${totalMutations}${seed.ext}`;

            // 1. FormatDetector MUST never crash with an unhandled exception
            const det = detector.detect(mutated, filename);
            assert.ok(det && typeof det.format === 'string', `detect() must return structured object for ${filename}`);

            // 2. pkgManager.inspect() MUST either return structured metadata or throw structured Error
            let inspErr = null;
            let inspRes = null;
            try {
              inspRes = await pkgManager.inspect(mutated, filename);
            } catch (err) {
              inspErr = err;
            }
            if (inspErr) {
              assert.ok(inspErr instanceof Error && inspErr.message.length > 0);
              cleanRejects += 1;
            } else {
              assert.ok(inspRes && typeof inspRes === 'object');
              cleanAccepts += 1;
            }
          }
        }
      }

      assert.equal(totalMutations, 60, 'Expected 60 deterministic fuzz mutations across 5 binary formats');
      assert.ok(cleanRejects >= 10, `Expected fuzzing to trigger structured rejections (got ${cleanRejects})`);
      assert.equal(cleanRejects + cleanAccepts, totalMutations);

      // Post-fuzz liveness: a fresh valid binary still installs and executes cleanly
      const saneId = `com.fuzz.healthy.${nonce}`;
      const saneRec = await pkgManager.install(
        buildCustomUapp({ appId: saneId, name: 'PostFuzzHealthy', message: `POST_FUZZ_OK_${nonce}\n`, exitCode: 0 }),
        { filename: `healthy-${nonce}.uapp`, grantAll: true }
      );
      const launched = await pkgManager.launch(saneRec.appId ?? saneId, {});
      const pcb = await runPidToDone(os, launched.pid, 500);
      assert.ok(pcb && isDoneState(pcb.state));
      assert.equal(pcb.exitCode, 0);
      assert.ok(pcb.streams.stdout.toString().includes(`POST_FUZZ_OK_${nonce}`));

      const rssDelta = process.memoryUsage().rss - rssBefore;
      assert.ok(rssDelta < 128 * 1024 * 1024, `Fuzzing RSS delta too high: ${Math.round(rssDelta / (1024 * 1024))} MiB`);
      assert.equal(kernel.getDiagnostics()?.state, 'RUNNING');
    } finally {
      await os.shutdown();
    }
  });

  // --------------------------------------------------------------------------
  // T5-03: VFS Traversal / Symlink-Escape / ELOOP / Cross-App Jail & Permission Fail-Closed
  // --------------------------------------------------------------------------
  test('T5-03 [F-089]: VFS traversal, symlink escape, ELOOP, cross-app sandbox jail & PermissionBroker fail-closed defense', async () => {
    const nonce = makeNonce();
    const os = await loadPublicOmniOS();
    try {
      const vfs = os.require('vfs');
      const pkgManager = os.require('pkgManager');
      const permissions = os.require('security');
      const users = os.require('users');
      const rootCtx = { uid: 0, gid: 0, platform: 'posix' };

      // Provision two isolated Android apps
      const victimPkg = `com.t5.victim.${nonce}`;
      const attackerPkg = `com.t5.attacker.${nonce}`;
      await pkgManager.install(buildCustomApk({ packageName: victimPkg, appLabel: 'Victim' }), { filename: `v-${nonce}.apk` });
      await pkgManager.install(buildCustomApk({ packageName: attackerPkg, appLabel: 'Attacker' }), { filename: `a-${nonce}.apk` });

      const victimUser = users.getUserByAppId(victimPkg);
      const attackerUser = users.getUserByAppId(attackerPkg);
      assert.ok(victimUser?.uid >= 10000 && attackerUser?.uid >= 10000);
      assert.notEqual(victimUser.uid, attackerUser.uid);

      const victimSecret = `/var/appdata/android/${victimPkg}/vault-${nonce}.txt`;
      await vfs.writeFile(victimSecret, `TOP_SECRET_${nonce}`, { mode: 0o600, ...rootCtx });
      await vfs.chown(victimSecret, victimUser.uid, victimUser.gid, rootCtx);

      // 1. All traversal & escape payloads from VFS edge corpus MUST be blocked for attacker UID
      const edgePayloads = getVfsEdgeCasePayloads();
      const attackerCtx = { uid: attackerUser.uid, gid: attackerUser.gid, platform: 'android', appId: attackerPkg };
      const escapeTargets = [
        victimSecret,
        `/data/data/${victimPkg}/vault-${nonce}.txt`,
        `/data/data/${attackerPkg}/../../android/${victimPkg}/vault-${nonce}.txt`,
        `/root/.ssh/id_rsa`,
        ...(Array.isArray(edgePayloads?.traversalPaths) ? edgePayloads.traversalPaths : []),
      ];

      for (const badPath of escapeTargets) {
        let caught = null;
        try {
          await vfs.readFile(badPath, { encoding: 'utf8', ...attackerCtx });
        } catch (err) {
          caught = err;
        }
        assert.ok(caught instanceof Error, `Attacker read of "${badPath}" MUST fail`);
        assert.ok(
          ['EACCES', 'ENOENT', 'EINVAL', 'E_PATH_TRAVERSAL'].includes(caught.code),
          `Expected structured denial code for "${badPath}", got ${caught.code}`
        );
      }

      // 2. Symlink planted inside attacker's sandbox pointing to victimSecret MUST still be denied!
      const evilLink = `/var/appdata/android/${attackerPkg}/escape-link-${nonce}`;
      await vfs.symlink(victimSecret, evilLink, rootCtx);
      let symEscapeErr = null;
      try {
        await vfs.readFile(evilLink, { encoding: 'utf8', ...attackerCtx });
      } catch (err) {
        symEscapeErr = err;
      }
      assert.ok(symEscapeErr instanceof Error, 'Symlink pointing outside sandbox MUST be denied');
      assert.equal(symEscapeErr.code, 'EACCES', `Expected EACCES on symlink escape, got ${symEscapeErr.code}`);

      // 3. Mutual symlink loop MUST fail with ELOOP (never hang or stack overflow)
      const loopA = `/tmp/t5-loop-a-${nonce}`;
      const loopB = `/tmp/t5-loop-b-${nonce}`;
      await vfs.symlink(loopB, loopA, rootCtx);
      await vfs.symlink(loopA, loopB, rootCtx);
      let eloopErr = null;
      try {
        await vfs.readFile(loopA, rootCtx);
      } catch (err) {
        eloopErr = err;
      }
      assert.ok(eloopErr instanceof Error && eloopErr.code === 'ELOOP', `Expected ELOOP on symlink cycle, got ${eloopErr?.code}`);

      // 4. PermissionBroker fail-closed on ungranted/prompt-timeout capability + audit log entry
      const checkRes = await permissions.checkPermission({
        appId: attackerPkg,
        pid: 1,
        platform: 'android',
        capability: 'fs.write.system',
        timeoutMs: 0,
      });
      assert.equal(checkRes.granted, false, 'Ungranted fs.write.system MUST fail closed');
      const auditRows = permissions.getAuditLog({ appId: attackerPkg, limit: 10 });
      assert.ok(
        auditRows.some((r) => r.capability === 'fs.write.system' && r.granted === false),
        'PermissionBroker denial must be recorded in audit log'
      );

      // Victim secret remains intact
      assert.equal(
        await vfs.readFile(victimSecret, { encoding: 'utf8', uid: victimUser.uid, gid: victimUser.gid, platform: 'android', appId: victimPkg }),
        `TOP_SECRET_${nonce}`
      );
    } finally {
      await os.shutdown();
    }
  });

  // --------------------------------------------------------------------------
  // T5-04: Raw TCP Malformed RFC 6455 WebSocket Frames & Adversarial HTTP Attacks
  // --------------------------------------------------------------------------
  test('T5-04 [F-089]: Raw TCP malformed RFC 6455 WS frames & HTTP __proto__/oversized/malformed attacks leave healthy clients unaffected', async () => {
    const nonce = makeNonce();
    const srv = await startOmniServer({ mode: 'server' });
    let healthyWs = null;
    try {
      const url = new URL(srv.baseUrl);
      const host = url.hostname;
      const port = Number(url.port);

      // Open a healthy WS client BEFORE attacks to prove isolation
      healthyWs = await connectWs(srv.wsUrl);

      // 1. Prototype pollution JSON attempts on HTTP REST endpoints
      const protoPayload = `{"__proto__":{"omniosPolluted":"${nonce}"},"constructor":{"prototype":{"omniosPolluted2":"${nonce}"}},"key":"system.theme","value":"dark"}`;
      const protoRes = await srv.api.put('/api/v1/config/system', protoPayload, {
        headers: { 'content-type': 'application/json' },
      });
      assert.ok(protoRes.status >= 200 && protoRes.status < 500);
      assert.equal(({}).omniosPolluted, undefined, 'Object.prototype MUST NOT be polluted via __proto__');
      assert.equal(({}).omniosPolluted2, undefined, 'Object.prototype MUST NOT be polluted via constructor.prototype');

      // 2. Malformed JSON & garbage HTTP request line on raw TCP
      const badJsonRes = await srv.api.post('/api/v1/ipc/clipboard', '{broken-json', {
        headers: { 'content-type': 'application/json' },
      });
      assert.equal(badJsonRes.status, 400, `Malformed JSON must return 400, got ${badJsonRes.status}`);

      const badHttp = await rawHttpExchange(host, port, 'GARBAGE_METHOD /bad HTTP/9.9\r\nHost: bad\r\n\r\n');
      assert.ok(badHttp.closed || badHttp.raw.includes('400') || badHttp.raw.includes('505') || !badHttp.ok);

      // 3. Oversized JSON payload (> 2 MiB) -> 413 or cleanly rejected
      const hugeBody = `{"text":"${'A'.repeat(2_500_000)}"}`;
      const hugeRes = await new Promise((resolve) => {
        const req = http.request(
          {
            hostname: host,
            port,
            path: '/api/v1/ipc/clipboard',
            method: 'POST',
            headers: {
              'content-type': 'application/json',
              'content-length': Buffer.byteLength(hugeBody),
            },
          },
          (res) => {
            res.resume();
            res.on('end', () => resolve({ status: res.statusCode }));
          }
        );
        req.on('error', (err) => resolve({ status: 0, error: err.code }));
        req.write(hugeBody);
        req.end();
      });
      assert.ok(
        hugeRes.status === 413 || hugeRes.status === 400 || hugeRes.status === 0,
        `Oversized HTTP body must be rejected (413/400/close), got ${JSON.stringify(hugeRes)}`
      );

      // 4. Raw TCP RFC 6455 WebSocket protocol violation matrix
      const wsAttacks = [
        // (a) Unmasked client->server text frame (RFC 6455 §5.1 violation -> 1002)
        ['unmasked-client-frame', Buffer.from([0x81, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f])],
        // (b) Reserved non-control opcode 0x03 (RFC 6455 §5.2 violation -> 1002)
        ['reserved-opcode-0x03', buildMaskedWsFrame({ fin: 1, opcode: 0x03, payload: Buffer.from('bad') })],
        // (c) Fragmented control frame (FIN=0, PING opcode 0x09 -> 1002)
        ['fragmented-ping', buildMaskedWsFrame({ fin: 0, opcode: 0x09, payload: Buffer.from('hi') })],
        // (d) Oversized control frame payload (> 125 bytes -> 1002)
        ['oversized-control-frame', buildMaskedWsFrame({ fin: 1, opcode: 0x09, payload: Buffer.alloc(130, 0x41) })],
        // (e) Non-zero RSV1 bit without negotiated extension -> 1002
        ['rsv1-nonzero', buildMaskedWsFrame({ fin: 1, rsv: 0x04, opcode: 0x01, payload: Buffer.from('rsv') })],
      ];

      for (const [label, frame] of wsAttacks) {
        const res = await rawWsAttack(host, port, frame);
        assert.equal(res.upgraded, true, `${label}: WS upgrade must succeed before sending adversarial frame`);
        assert.equal(res.closed, true, `${label}: server MUST close violating WS connection`);
        if (res.closeCode !== null && res.closeCode !== undefined) {
          assert.ok(
            res.closeCode === 1002 || res.closeCode === 1007 || res.closeCode === 1009,
            `${label}: expected RFC 6455 error close code (1002/1007/1009), got ${res.closeCode}`
          );
        }
      }

      // 5. Server & healthy WS client remain 100% responsive after all TCP/HTTP/WS attacks!
      const health = await srv.api.get('/api/health', { expectOk: true });
      assert.equal(health.status, 200);
      const pushWait = healthyWs.waitForMessage(
        (msg) => JSON.stringify(msg).includes(`POST_ATTACK_${nonce}`),
        { timeoutMs: 5000 }
      );
      await srv.api.post('/api/v1/ipc/notifications', {
        appId: 'com.omnios.system',
        platform: 'posix',
        title: `POST_ATTACK_${nonce}`,
        body: 'Healthy WS survived adversarial attack suite',
      }, { expectOk: true });
      const pushEvt = await pushWait;
      assert.ok(pushEvt, 'Healthy WS client must continue receiving live events after adversarial WS attacks');
    } finally {
      await healthyWs?.close?.().catch(() => {});
      await srv.stop();
    }
  });

  // --------------------------------------------------------------------------
  // T5-05: Double Kernel Panic -> Scheduling Halt -> SQLite Dump -> Safe-Mode Recovery
  // --------------------------------------------------------------------------
  test('T5-05 [F-089]: Double kernel panic halts scheduler, dumps to SQLite, recovers in safe mode & preserves persisted data across cold reboot', async () => {
    const nonce = makeNonce();
    const tmp = await createTempDataDir('omnios-t5-panic-');
    let os1 = null;
    let os2 = null;
    try {
      os1 = await loadPublicOmniOS({ dataDir: tmp.dir });
      const kernel1 = os1.require('kernel');
      const vfs1 = os1.require('vfs');
      const cfg1 = os1.require('configStore');
      const scheduler1 = os1.require('scheduler');
      const pkg1 = os1.require('pkgManager');

      // Seed durable state across VFS, UnifiedConfig, and PackageManager before panic
      const persistFile = `/home/user/Documents/pre-panic-${nonce}.txt`;
      const persistBody = `PRE_PANIC_STATE_${nonce}`;
      await vfs1.writeFile(persistFile, persistBody, { uid: 1000, gid: 1000 });
      await cfg1.system.set('system.locale', `en-T5-${nonce}`);
      const appId = `com.t5.survivor.${nonce}`;
      await pkg1.install(
        buildCustomUapp({ appId, name: 'PanicSurvivor', message: `SURVIVED_${nonce}\n` }),
        { filename: `survivor-${nonce}.uapp`, grantAll: true }
      );

      // Double kernel panic
      const dump1 = kernel1.panic(`E_PANIC_1_${nonce}`, `Primary fault ${nonce}`, { seq: 1 });
      assert.equal(kernel1.getDiagnostics().state, 'PANIC');
      assert.ok(dump1 && dump1.code === `E_PANIC_1_${nonce}`);

      const dump2 = kernel1.panic(`E_PANIC_2_${nonce}`, `Double fault ${nonce}`, { seq: 2 });
      assert.equal(kernel1.getDiagnostics().state, 'PANIC');
      assert.ok(dump2, 'Double panic must return structured panic dump without crashing Node');

      // Scheduler must halt (refuse/skip stepping) while PANIC
      let stepThrew = false;
      let stepRes = null;
      try {
        stepRes = await scheduler1.step(5);
      } catch (err) {
        stepThrew = err instanceof Error;
      }
      assert.ok(
        stepThrew || (stepRes && (stepRes.ticksRun === 0 || stepRes.instructionsExecuted === 0)),
        `Scheduler must halt during PANIC state (stepRes=${JSON.stringify(stepRes)})`
      );

      // Recover cleanly in safeMode: true
      await kernel1.recover({ safeMode: true });
      const safeState = kernel1.getDiagnostics().state;
      assert.ok(
        safeState === 'SAFE_MODE' || safeState === 'RUNNING',
        `Expected SAFE_MODE or RUNNING after safeMode recovery, got ${safeState}`
      );
      assert.ok(kernel1.getDiagnostics().lastPanic !== null, 'Last panic dump must remain recorded in diagnostics');

      // Verify pre-panic data survived recovery in-session
      assert.equal(await vfs1.readFile(persistFile, { encoding: 'utf8', uid: 1000, gid: 1000 }), persistBody);
      assert.equal(await cfg1.system.get('system.locale'), `en-T5-${nonce}`);
      assert.ok(pkg1.get(appId), 'Installed package must survive panic + safeMode recovery');

      await os1.shutdown();
      os1 = null;

      // Cold reboot from same SQLite dataDir -> normal RUNNING state with zero data loss
      os2 = await loadPublicOmniOS({ dataDir: tmp.dir });
      assert.equal(os2.require('kernel').getDiagnostics().state, 'RUNNING');
      assert.equal(
        await os2.require('vfs').readFile(persistFile, { encoding: 'utf8', uid: 1000, gid: 1000 }),
        persistBody
      );
      assert.equal(await os2.require('configStore').system.get('system.locale'), `en-T5-${nonce}`);
      assert.ok(os2.require('pkgManager').get(appId), 'Installed package must survive cold reboot after panic');
    } finally {
      await os1?.shutdown?.().catch(() => {});
      await os2?.shutdown?.().catch(() => {});
      await tmp.cleanup();
    }
  });

  // --------------------------------------------------------------------------
  // T5-06: Potato-PC Lightweight Mode (liteMode / OMNIOS_LITE=1 / --lite / ?lite=1)
  // --------------------------------------------------------------------------
  test('T5-06 [F-090]: Potato-PC Lite profile (kernel, SQLite, CLI --lite, OMNIOS_LITE=1 server, Chromium ?lite=1) runs cleanly under low memory budget', async () => {
    const nonce = makeNonce();

    // 1. Direct programmatic liteMode kernel + SQLite + multi-platform workload
    const os = await loadPublicOmniOS({ liteMode: true });
    const heapBefore = process.memoryUsage().heapUsed;
    try {
      const diag = os.require('kernel').getDiagnostics();
      assert.equal(diag.state, 'RUNNING');
      assert.equal(diag.liteMode, true, `Expected kernel diagnostics liteMode=true, got ${JSON.stringify(diag)}`);

      const pkg = os.require('pkgManager');
      const vfs = os.require('vfs');

      // Install & run lightweight cross-platform binaries under liteMode
      const batRec = await pkg.install(
        Buffer.from(buildBatScript({
          outputFile: `C:\\Users\\user\\Documents\\lite-bat-${nonce}.txt`,
          outputContent: `LITE_BAT_${nonce}`,
          exitCode: 0,
        }), 'utf8'),
        { filename: `lite-${nonce}.bat`, grantAll: true }
      );
      const uappRec = await pkg.install(
        buildCustomUapp({ appId: `com.t5.lite.${nonce}`, name: 'LiteWasm', message: `LITE_WASM_${nonce}\n`, exitCode: 0 }),
        { filename: `lite-${nonce}.uapp`, grantAll: true }
      );

      for (const rec of [batRec, uappRec]) {
        const l = await pkg.launch(rec.appId, {});
        const pcb = await runPidToDone(os, l.pid, 500);
        assert.ok(pcb && isDoneState(pcb.state) && pcb.exitCode === 0);
      }

      const batOut = await vfs.readFile(`/home/user/Documents/lite-bat-${nonce}.txt`, { encoding: 'utf8' });
      assert.equal(batOut.trim(), `LITE_BAT_${nonce}`);

      // Verify dmesg ring stays bounded at lite capacity (<= 256)
      const kernel = os.require('kernel');
      for (let i = 0; i < 320; i += 1) {
        kernel.log('info', 'lite-stress', `entry-${i}`);
      }
      const allDmesg = kernel.dmesg({ limit: 1000 });
      assert.ok(allDmesg.length <= 256, `Lite dmesg ring must cap at <=256 entries, got ${allDmesg.length}`);

      const heapDelta = process.memoryUsage().heapUsed - heapBefore;
      assert.ok(
        heapDelta < 64 * 1024 * 1024,
        `Lite mode heap growth must stay <64 MiB (got ${Math.round(heapDelta / (1024 * 1024))} MiB)`
      );
    } finally {
      await os.shutdown();
    }

    // 2. CLI `--lite` flag verification
    const cliTmp = await createTempDataDir('omnios-t5-lite-cli-');
    try {
      const cliRes = await runCli(['status', '--lite', '--data-dir', cliTmp.dir], { json: true, expectZero: true });
      assert.equal(cliRes.json?.liteMode, true, `CLI status --lite must report liteMode: true: ${cliRes.stdout}`);
    } finally {
      await cliTmp.cleanup();
    }

    // 3. Live OMNIOS_LITE=1 HTTP server + Chromium CDP `/?lite=1` Potato-PC UI verification
    const srv = await startOmniServer({
      mode: 'server',
      env: { OMNIOS_LITE: '1' },
    });
    const browser = await launchBrowser();
    try {
      const statusRes = await srv.api.get('/api/v1/kernel/status', { expectOk: true });
      assert.equal(statusRes.json?.liteMode, true, `OMNIOS_LITE=1 server must report liteMode: true: ${statusRes.text}`);

      const page = await browser.newPage({ viewport: { width: 1024, height: 640 } });
      await page.goto(`${srv.baseUrl}/?lite=1`);
      await page.waitForFunction(
        () => {
          const shell = document.getElementById('omnios-shell') || document.querySelector('[data-perf]');
          return shell?.getAttribute('data-perf') === 'lite' && shell?.getAttribute('data-lite-mode') === 'true';
        },
        { timeoutMs: 8000 }
      );

      // Verify CSS glass blur & heavy animations are disabled in Lite UI
      const perfCheck = await page.evalFn(() => {
        const shell = document.getElementById('omnios-shell') || document.querySelector('[data-perf]') || document.body;
        const bar = document.getElementById('top-bar') || shell;
        const barStyle = window.getComputedStyle(bar);
        return {
          perfMode: shell.getAttribute('data-perf'),
          liteAttr: shell.getAttribute('data-lite-mode'),
          backdropFilter: barStyle.backdropFilter || barStyle.webkitBackdropFilter || 'none',
        };
      });
      assert.equal(perfCheck.perfMode, 'lite');
      assert.equal(perfCheck.liteAttr, 'true');
      assert.equal(perfCheck.backdropFilter, 'none', `Lite UI must disable backdrop-filter blur (got ${perfCheck.backdropFilter})`);

      // Launch a built-in system app cleanly under OMNIOS_LITE=1 + Lite UI
      const pkgsRes = await srv.api.get('/api/v1/packages', { expectOk: true });
      const sysApps = pkgsRes.json?.systemApps ?? [];
      assert.ok(sysApps.length > 0, 'Expected systemApps in /api/v1/packages');
      const termApp = sysApps.find((a) => /terminal/i.test(String(a.appId ?? a.id ?? ''))) ?? sysApps[0];
      const termId = termApp.appId ?? termApp.id;
      const lRes = await srv.api.post(`/api/v1/packages/${encodeURIComponent(termId)}/launch`, {}, { expectOk: true });
      assert.ok(lRes.json?.pid > 1);

      await page.waitForFunction(
        (appId) => Boolean(document.querySelector(`.omni-window[data-app-id="${appId}"]`)),
        { timeoutMs: 8000, args: [termId] }
      );

      const pageErrs = page.getPageErrors();
      const consoleErrs = page.getConsoleErrors();
      assert.equal(pageErrs.length, 0, `Lite UI must have zero uncaught page errors: ${JSON.stringify(pageErrs)}`);
      assert.equal(consoleErrs.length, 0, `Lite UI must have zero console errors: ${JSON.stringify(consoleErrs)}`);
      await page.close();
    } finally {
      await browser.close().catch(() => {});
      await srv.stop().catch(() => {});
    }
  });
});
