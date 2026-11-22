/**
 * OmniOS Milestone M5 Comprehensive Integration & Unit Test Suite (`F-061` – `F-072`)
 * Zero external dependencies (`node:test`, `node:assert/strict`, Node 24 built-ins only).
 * Zero mocks: boots real OmniOS microkernel, 6 daemons, 5 CPU architectures, 5 platform runtimes,
 * all 7 real pre-built sample binaries (incl. Universal Fat ARM64 + Intel x86-64 macOS slices),
 * live HTTP REST API v1, live RFC 6455 WebSocket server, Spotlight Search, Multi-Syntax Shell,
 * all 7 built-in kernel-backed System Apps, and real CLI subprocesses (local & --remote).
 */

import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fsp from 'node:fs/promises';
import net from 'node:net';
import osMod from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { createOmniOS, bootOmniOS, SAMPLE_PACKAGE_MANIFESTS } from '../../os/os.mjs';
import { createHttpServer, startOmniOSServer } from '../../os/server/http-server.mjs';
import { WS_GUID, WS_OPCODES, WS_CLOSE_CODES, encodeWsFrame } from '../../os/server/websocket.mjs';
import { SYSTEM_APP_IDS } from '../../os/apps/registry.mjs';
import { PROCESS_STATES } from '../../os/kernel/process.mjs';
import { CANONICAL_SYSTEM_KEYS } from '../../os/store/unified-config.mjs';
import { ALL_CAPABILITIES } from '../../os/security/permissions.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const PACKAGES_DIR = path.join(REPO_ROOT, 'packages');
const CLI_ENTRY = path.join(REPO_ROOT, 'os', 'cli', 'omnios-cli.mjs');

const tempDirs = new Set();

async function makeTempDir(prefix = 'omnios-m5-test-') {
  const dir = await fsp.mkdtemp(path.join(osMod.tmpdir(), prefix));
  tempDirs.add(dir);
  return dir;
}

async function cleanupTempDir(dir) {
  if (!dir) return;
  tempDirs.delete(dir);
  await fsp.rm(dir, { recursive: true, force: true });
}

after(async () => {
  for (const dir of Array.from(tempDirs)) {
    await fsp.rm(dir, { recursive: true, force: true });
    tempDirs.delete(dir);
  }
});

function collectUiTexts(node, out = []) {
  if (!node || typeof node !== 'object') return out;
  if (typeof node.text === 'string') out.push(node.text);
  if (typeof node.label === 'string') out.push(node.label);
  if (typeof node.value === 'string') out.push(node.value);
  if (node.props && typeof node.props === 'object') {
    if (typeof node.props.text === 'string') out.push(node.props.text);
    if (typeof node.props.label === 'string') out.push(node.props.label);
    if (typeof node.props.value === 'string') out.push(node.props.value);
  }
  if (Array.isArray(node.children)) {
    for (const child of node.children) {
      collectUiTexts(child, out);
    }
  }
  return out;
}

/**
 * Sends a raw HTTP/1.1 request over TCP without URL path normalization
 * (essential for testing traversal attacks like `/../package.json`).
 */
function rawTcpHttpRequest(host, port, rawRequest, timeoutMs = 4000) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port });
    const chunks = [];
    let settled = false;

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        socket.destroy();
        reject(new Error(`rawTcpHttpRequest timed out after ${timeoutMs}ms`));
      }
    }, timeoutMs);
    timer.unref?.();

    socket.on('connect', () => {
      socket.write(rawRequest);
    });
    socket.on('data', (chunk) => {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    });
    socket.on('error', (err) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        reject(err);
      }
    });
    socket.on('end', () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const raw = Buffer.concat(chunks).toString('utf8');
      const headerEnd = raw.indexOf('\r\n\r\n');
      const head = headerEnd >= 0 ? raw.slice(0, headerEnd) : raw;
      const body = headerEnd >= 0 ? raw.slice(headerEnd + 4) : '';
      const lines = head.split('\r\n');
      const statusMatch = /^HTTP\/1\.\d\s+(\d+)\s*(.*)$/.exec(lines[0] ?? '');
      const status = statusMatch ? Number(statusMatch[1]) : 0;
      const headers = {};
      for (let i = 1; i < lines.length; i += 1) {
        const idx = lines[i].indexOf(':');
        if (idx > 0) {
          headers[lines[i].slice(0, idx).trim().toLowerCase()] = lines[i].slice(idx + 1).trim();
        }
      }
      resolve({ status, headers, body, raw });
    });
  });
}

/**
 * Pure raw TCP RFC 6455 test client for verifying exact framing, masking, fragmentation,
 * interleaved control frames, and protocol violation close codes.
 */
class RawWsClient {
  constructor() {
    this.socket = null;
    this.buffer = Buffer.alloc(0);
    this.frames = [];
    this.waiters = [];
    this.closed = false;
    this.handshakeStatus = 0;
    this.handshakeHeaders = {};
  }

  async connect(host, port, { path: wsPath = '/ws', headers = {}, key = null } = {}) {
    const wsKey = key !== null ? key : crypto.randomBytes(16).toString('base64');
    const hdrs = {
      Host: `${host}:${port}`,
      Upgrade: 'websocket',
      Connection: 'Upgrade',
      'Sec-WebSocket-Version': '13',
      'Sec-WebSocket-Key': wsKey,
      ...headers,
    };

    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ host, port });
      this.socket = socket;
      let handshakeDone = false;
      let headBuf = Buffer.alloc(0);

      const timer = setTimeout(() => {
        if (!handshakeDone) {
          socket.destroy();
          reject(new Error('RawWsClient handshake timeout'));
        }
      }, 4000);
      timer.unref?.();

      socket.on('connect', () => {
        const reqLines = [`GET ${wsPath} HTTP/1.1`];
        for (const [k, v] of Object.entries(hdrs)) {
          if (v !== undefined && v !== null) reqLines.push(`${k}: ${v}`);
        }
        socket.write(`${reqLines.join('\r\n')}\r\n\r\n`);
      });

      socket.on('data', (chunk) => {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        if (!handshakeDone) {
          headBuf = Buffer.concat([headBuf, buf]);
          const sep = headBuf.indexOf('\r\n\r\n');
          if (sep === -1) return;
          handshakeDone = true;
          clearTimeout(timer);
          const headStr = headBuf.subarray(0, sep).toString('utf8');
          const trailing = headBuf.subarray(sep + 4);
          const lines = headStr.split('\r\n');
          const m = /^HTTP\/1\.\d\s+(\d+)/.exec(lines[0] ?? '');
          this.handshakeStatus = m ? Number(m[1]) : 0;
          for (let i = 1; i < lines.length; i += 1) {
            const idx = lines[i].indexOf(':');
            if (idx > 0) {
              this.handshakeHeaders[lines[i].slice(0, idx).trim().toLowerCase()] = lines[i]
                .slice(idx + 1)
                .trim();
            }
          }
          if (trailing.byteLength > 0 && this.handshakeStatus === 101) {
            this._pushData(trailing);
          }
          resolve({
            status: this.handshakeStatus,
            headers: this.handshakeHeaders,
            key: wsKey,
          });
          return;
        }
        this._pushData(buf);
      });

      socket.on('close', () => {
        this.closed = true;
        this._notifyWaiters();
      });

      socket.on('error', (err) => {
        if (!handshakeDone) {
          handshakeDone = true;
          clearTimeout(timer);
          reject(err);
        } else {
          this.closed = true;
          this._notifyWaiters();
        }
      });
    });
  }

  _pushData(chunk) {
    this.buffer = this.buffer.byteLength === 0 ? Buffer.from(chunk) : Buffer.concat([this.buffer, chunk]);
    while (this.buffer.byteLength >= 2) {
      const b0 = this.buffer[0];
      const b1 = this.buffer[1];
      const fin = (b0 & 0x80) !== 0;
      const rsv = b0 & 0x70;
      const opcode = b0 & 0x0f;
      const masked = (b1 & 0x80) !== 0;
      let len = b1 & 0x7f;
      let offset = 2;

      if (len === 126) {
        if (this.buffer.byteLength < 4) break;
        len = this.buffer.readUInt16BE(2);
        offset = 4;
      } else if (len === 127) {
        if (this.buffer.byteLength < 10) break;
        len = Number(this.buffer.readBigUInt64BE(2));
        offset = 10;
      }

      const maskLen = masked ? 4 : 0;
      if (this.buffer.byteLength < offset + maskLen + len) break;

      const payload = Buffer.allocUnsafe(len);
      if (masked) {
        const key = this.buffer.subarray(offset, offset + 4);
        offset += 4;
        for (let i = 0; i < len; i += 1) {
          payload[i] = this.buffer[offset + i] ^ key[i & 3];
        }
      } else if (len > 0) {
        this.buffer.copy(payload, 0, offset, offset + len);
      }

      this.buffer = this.buffer.subarray(offset + len);
      const frame = { fin, rsv, opcode, masked, payload };
      if (opcode === WS_OPCODES.TEXT) {
        frame.text = payload.toString('utf8');
        try {
          frame.json = JSON.parse(frame.text);
        } catch (parseErr) {
          frame.json = null;
          frame.parseError = parseErr.message;
        }
      } else if (opcode === WS_OPCODES.CLOSE && payload.byteLength >= 2) {
        frame.closeCode = payload.readUInt16BE(0);
        frame.closeReason = payload.subarray(2).toString('utf8');
      }
      this.frames.push(frame);
    }
    this._notifyWaiters();
  }

  _notifyWaiters() {
    for (let i = this.waiters.length - 1; i >= 0; i -= 1) {
      const waiter = this.waiters[i];
      const idx = this.frames.findIndex(waiter.predicate);
      if (idx !== -1) {
        const [matched] = this.frames.splice(idx, 1);
        clearTimeout(waiter.timer);
        this.waiters.splice(i, 1);
        waiter.resolve(matched);
      } else if (this.closed && waiter.failOnClose) {
        clearTimeout(waiter.timer);
        this.waiters.splice(i, 1);
        waiter.reject(new Error(`Socket closed while waiting for ${waiter.label}`));
      }
    }
  }

  waitForFrame(predicate, { timeoutMs = 4000, label = 'frame', failOnClose = true } = {}) {
    const existingIdx = this.frames.findIndex(predicate);
    if (existingIdx !== -1) {
      const [matched] = this.frames.splice(existingIdx, 1);
      return Promise.resolve(matched);
    }
    if (this.closed && failOnClose) {
      return Promise.reject(new Error(`Socket already closed while waiting for ${label}`));
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = this.waiters.indexOf(waiter);
        if (idx !== -1) this.waiters.splice(idx, 1);
        reject(new Error(`Timed out waiting for ${label}`));
      }, timeoutMs);
      timer.unref?.();
      const waiter = { predicate, resolve, reject, timer, label, failOnClose };
      this.waiters.push(waiter);
    });
  }

  waitForEnvelope(type, timeoutMs = 4000) {
    return this.waitForFrame(
      (f) => f.opcode === WS_OPCODES.TEXT && f.json && f.json.type === type,
      { timeoutMs, label: `envelope:${type}` }
    ).then((f) => f.json);
  }

  waitForClose(timeoutMs = 4000) {
    return this.waitForFrame((f) => f.opcode === WS_OPCODES.CLOSE, {
      timeoutMs,
      label: 'close-frame',
      failOnClose: false,
    });
  }

  sendRaw(buf) {
    this.socket.write(buf);
  }

  sendJson(obj) {
    const frame = encodeWsFrame(WS_OPCODES.TEXT, Buffer.from(JSON.stringify(obj), 'utf8'), {
      mask: true,
    });
    this.socket.write(frame);
  }

  close() {
    if (this.socket && !this.socket.destroyed) {
      this.socket.destroy();
    }
  }
}

/**
 * Spawns a real `node os/cli/omnios-cli.mjs` subprocess and verifies it terminates cleanly.
 */
function runCliSubprocess(args, { stdin = null, timeoutMs = 15000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI_ENTRY, ...args], {
      cwd: REPO_ROOT,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env },
    });

    const outChunks = [];
    const errChunks = [];
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, timeoutMs);
    timer.unref?.();

    child.stdout.on('data', (c) => outChunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
    child.stderr.on('data', (c) => errChunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({
        exitCode: code,
        signal,
        timedOut,
        stdout: Buffer.concat(outChunks).toString('utf8'),
        stderr: Buffer.concat(errChunks).toString('utf8'),
      });
    });

    if (stdin !== null) {
      child.stdin.write(stdin);
    }
    child.stdin.end();
  });
}

// ============================================================================
// SUITE 1 — Unified Runtime Bootstrapper (`os/os.mjs`, F-061) & Live 5-Platform
//           + Universal Fat Intel x86-64 Execution
// ============================================================================

describe('Suite 1 (F-061): Unified OmniOS Runtime Bootstrapper & Live 5-Platform + Intel x86-64 Execution', () => {
  it('boots 6 core daemons, all 5 CPU arches, all 5 runtimes, stages 7 sample packages, runs all 7 apps concurrently + macOS Intel x86-64 slice, and recovers from kernel panic', async () => {
    const dataDir = await makeTempDir('omnios-m5-suite1-');
    const os = createOmniOS({ dataDir, autoStartScheduler: false });

    try {
      const bootReport = await os.boot();
      assert.equal(bootReport.status, 'RUNNING');
      assert.equal(os.kernel.state, 'RUNNING');

      // 1. Verify exact 6 core daemons RUNNING
      const services = os.serviceManager.getStatus();
      const serviceNames = services.map((s) => s.name).sort();
      assert.deepEqual(serviceNames, [
        'compositord',
        'configd',
        'ipc-brokerd',
        'pkgd',
        'securityd',
        'vfsd',
      ]);
      for (const svc of services) {
        assert.equal(svc.state, 'RUNNING', `Daemon ${svc.name} must be RUNNING`);
      }

      // 2. Verify all 5 CPU architectures in cpuRegistry
      for (const arch of ['dalvik', 'x86_64', 'x86', 'arm64', 'wasm']) {
        assert.equal(os.cpuRegistry.has(arch), true, `CpuRegistry must contain ${arch}`);
      }

      // 3. Verify all 5 platform runtimes registered
      for (const plat of ['android', 'windows', 'ios', 'macos', 'universal']) {
        assert.ok(os.runtimes[plat], `Runtime ${plat} must exist`);
        assert.ok(os.pkgManager.getRuntime(plat), `PackageManager must have ${plat} runtime`);
      }

      // 4. Verify all 7 pre-built sample packages staged in VFS `/packages/` + App Hub catalog
      const vfsPkgEntries = os.vfs.readdir('/packages', { uid: 0, gid: 0 }).map((e) => e.name);
      for (const manifest of SAMPLE_PACKAGE_MANIFESTS) {
        assert.ok(
          vfsPkgEntries.includes(manifest.filename),
          `Sample package /packages/${manifest.filename} must be staged in VFS`
        );
      }
      const catalog = os.pkgManager.getCatalog();
      assert.equal(catalog.length, 7, 'All 7 sample packages must be in App Hub catalog');

      // Verify `com.omnios.notes` coexistence before installing android-notes-sharer.apk
      const preNotesLaunch = await os.launchApp('com.omnios.notes', { stepTicks: 2 });
      assert.equal(preNotesLaunch.platform, 'system');
      assert.equal(preNotesLaunch.appId, SYSTEM_APP_IDS.NOTES);
      os.stopApp(preNotesLaunch.pid);

      // 5. Install ALL 7 pre-built sample packages from VFS `/packages/`
      const installed = {};
      for (const manifest of SAMPLE_PACKAGE_MANIFESTS) {
        const rec = await os.pkgManager.install(`/packages/${manifest.filename}`, {
          filenameHint: manifest.filename,
          grantAll: true,
        });
        installed[manifest.filename] = rec;
      }

      // Launch all 7 apps concurrently!
      const calcLaunch = await os.launchApp(installed['android-calc.apk'].appId);
      const androidNotesLaunch = await os.launchApp(installed['android-notes-sharer.apk'].appId);
      const sysinfoLaunch = await os.launchApp(installed['win-sysinfo.exe'].appId);
      const notepadLaunch = await os.launchApp(installed['win-notepad.exe'].appId);
      const weatherLaunch = await os.launchApp(installed['ios-weather-island.ipa'].appId);
      const studioArmLaunch = await os.launchApp(installed['macos-studio.app.zip'].appId);
      const canvasLaunch = await os.launchApp(installed['universal-canvas.uapp'].appId);

      // Verify coexistence after installing android-notes-sharer.apk:
      // `com.omnios.notes` launched Android APK, while `{ preferSystem: true }` still launches OmniNotes!
      assert.equal(androidNotesLaunch.platform, 'android');
      const sysNotesCoexist = await os.launchApp('com.omnios.notes', { preferSystem: true });
      assert.equal(sysNotesCoexist.platform, 'system');
      os.stopApp(sysNotesCoexist.pid);

      // Pump scheduler concurrently so all 7 apps initialize under the live Kernel Scheduler
      os.scheduler.step(80);

      // --- Verify (1) android-calc.apk: real Dalvik arithmetic 7 * 6 = 42 ---
      const calcWin0 = os.compositor.listWindows({ pid: calcLaunch.pid })[0];
      assert.ok(calcWin0, 'android-calc.apk must create a CompositorWindow');
      const calcRev0 = calcWin0.surfaceRevision;
      const clickCalcBtn = (resId) => {
        os.compositor.dispatchInput(calcWin0.windowId, {
          type: 'click',
          targetId: `view-${resId.toString(16)}`,
          viewId: resId,
        });
        os.scheduler.step(15);
      };
      clickCalcBtn(0x7f030017); // 7
      clickCalcBtn(0x7f030022); // *
      clickCalcBtn(0x7f030016); // 6
      clickCalcBtn(0x7f030024); // =
      const calcWin1 = os.compositor.getWindow(calcWin0.windowId);
      assert.ok(calcWin1.surfaceRevision > calcRev0, 'android-calc surfaceRevision must advance');
      const calcTexts = collectUiTexts(calcWin1.surface.uiTree);
      assert.ok(calcTexts.includes('42'), `android-calc display must show 42, got: ${JSON.stringify(calcTexts)}`);

      // --- Verify (2) android-notes-sharer.apk: Dalvik note save, clipboard & SD export ---
      const notesWin0 = os.compositor.listWindows({ pid: androidNotesLaunch.pid })[0];
      assert.ok(notesWin0, 'android-notes-sharer.apk must create a CompositorWindow');
      const noteSecret = 'Dalvik-Live-Note-M5-Verify';
      os.compositor.dispatchInput(notesWin0.windowId, {
        type: 'input',
        viewId: 0x7f030001,
        value: noteSecret,
      });
      os.scheduler.step(10);
      os.compositor.dispatchInput(notesWin0.windowId, { type: 'click', viewId: 0x7f030010 }); // Save
      os.scheduler.step(15);
      os.compositor.dispatchInput(notesWin0.windowId, { type: 'click', viewId: 0x7f030012 }); // Copy
      os.scheduler.step(15);
      os.compositor.dispatchInput(notesWin0.windowId, { type: 'click', viewId: 0x7f030014 }); // Export SD
      os.scheduler.step(15);
      assert.equal(os.clipboard.get('text/plain'), noteSecret, 'android-notes-sharer must copy note to SharedClipboard');
      const exportedSdNote = os.vfs.readFile('/home/user/Documents/android-note.txt', {
        uid: 0,
        gid: 0,
        encoding: 'utf8',
      });
      assert.equal(exportedSdNote, noteSecret, 'android-notes-sharer must export note to /sdcard/Documents/android-note.txt');

      // --- Verify (3) win-sysinfo.exe: PE32+ x86-64 stdout banner, Documents file & HKCU Registry ---
      const sysinfoPcb = os.processManager.get(sysinfoLaunch.pid);
      assert.ok(
        sysinfoPcb.state === PROCESS_STATES.ZOMBIE || sysinfoPcb.state === PROCESS_STATES.TERMINATED,
        'win-sysinfo.exe console PE32+ should run to completion'
      );
      assert.equal(sysinfoPcb.stats.exitCode, 0);
      const sysinfoStdout = os.processManager.readStdout(sysinfoLaunch.pid, { consume: false });
      assert.match(sysinfoStdout, /OmniOS/i, 'win-sysinfo.exe must print stdout banner');
      const winDoc = os.vfs.readFile('/home/user/Documents/win-sysinfo.txt', {
        uid: 0,
        gid: 0,
        encoding: 'utf8',
      });
      assert.ok(winDoc.length > 0, 'win-sysinfo.exe must write /home/user/Documents/win-sysinfo.txt');
      const winRegVal = os.configStore.registry.getValue('HKCU', 'Software\\OmniOS\\WinSysInfo', 'Status');
      assert.ok(winRegVal && typeof winRegVal.data === 'string' && winRegVal.data.length > 0);

      // --- Verify (4) win-notepad.exe: PE32+ Win32 window + GDI drawOps + Save & Copy ---
      const notepadWin0 = os.compositor.listWindows({ pid: notepadLaunch.pid })[0];
      assert.ok(notepadWin0, 'win-notepad.exe must create a Win32 CompositorWindow');
      assert.ok(Array.isArray(notepadWin0.surface.drawOps) && notepadWin0.surface.drawOps.length > 0, 'win-notepad must emit GDI drawOps');
      const notepadText = 'Win32-Notepad-Live-M5';
      os.compositor.dispatchInput(notepadWin0.windowId, { type: 'input', controlId: 101, value: notepadText });
      os.scheduler.step(10);
      os.compositor.dispatchInput(notepadWin0.windowId, { type: 'click', controlId: 102 }); // Save
      os.scheduler.step(15);
      os.compositor.dispatchInput(notepadWin0.windowId, { type: 'click', controlId: 103 }); // Copy
      os.scheduler.step(15);
      const savedWinNote = os.vfs.readFile('/home/user/Documents/win-notepad.txt', {
        uid: 0,
        gid: 0,
        encoding: 'utf8',
      });
      assert.equal(savedWinNote, notepadText);
      assert.equal(os.clipboard.get('text/plain'), notepadText);

      // --- Verify (5) ios-weather-island.ipa: ARM64 Mach-O UIKit, Dynamic Island, NSUserDefaults, Container ---
      const weatherWin = os.compositor.listWindows({ pid: weatherLaunch.pid })[0];
      assert.ok(weatherWin, 'ios-weather-island.ipa must create a UIKit CompositorWindow');
      const liveActivities = os.notifications.getLiveActivities();
      assert.ok(
        liveActivities.some((a) => a.appId === 'com.omnios.ios.weather-island'),
        'ios-weather-island.ipa must post a Dynamic Island Live Activity'
      );
      assert.equal(
        os.configStore.defaults.get('com.omnios.ios.weather-island', 'weather_city'),
        'Cupertino, CA'
      );
      const weatherAppRec = os.pkgManager.get('com.omnios.ios.weather-island');
      const forecastText = os.vfs.readFile(`${weatherAppRec.dataDir}/Documents/forecast.txt`, {
        uid: 0,
        gid: 0,
        encoding: 'utf8',
      });
      assert.match(forecastText, /Weather Island Forecast/i);

      // --- Verify (6A) macos-studio.app.zip: ARM64 slice (Global Menu Bar, Spotlight, NSUserDefaults) ---
      const studioArmPcb = os.processManager.get(studioArmLaunch.pid);
      const studioArmDebug = studioArmPcb.executionContext.getDebugState();
      assert.equal(studioArmDebug.arch, 'arm64');
      assert.ok(studioArmDebug.availableArchs.includes('x86_64'));
      const studioArmWin = os.compositor.listWindows({ pid: studioArmLaunch.pid })[0];
      assert.ok(studioArmWin, 'macOS ARM64 slice must create an AppKit NSWindow');
      os.compositor.focusWindow(studioArmWin.windowId);
      const armSnap = os.compositor.getSnapshot();
      assert.ok(Array.isArray(armSnap.activeMenuBar) && armSnap.activeMenuBar.length > 0);
      assert.ok(studioArmDebug.spotlight?.kMDItemDisplayName, 'macOS Spotlight metadata must be indexed');
      assert.equal(
        os.configStore.defaults.get('com.omnios.macos.studio', 'studio.theme'),
        'graphite-pro'
      );

      // --- Verify (6B) macos-studio.app.zip: LIVE Intel x86-64 slice via os.runtimes.macos + os.cpuRegistry ---
      os.configStore.defaults.remove('com.omnios.macos.studio', 'studio.theme');
      const studioRecord = os.pkgManager.get('com.omnios.macos.studio');
      const x64Pcb = os.processManager.spawn({
        name: `${studioRecord.name}-x86_64`,
        appId: studioRecord.appId,
        platform: 'macos',
        arch: 'x86_64',
        uid: studioRecord.uid,
        gid: studioRecord.gid,
        cwd: studioRecord.dataDir,
        autoReady: false,
      });
      const x64Services = {
        kernel: os.kernel,
        processManager: os.processManager,
        scheduler: os.scheduler,
        eventBus: os.eventBus,
        cpuRegistry: os.cpuRegistry,
        vfs: os.vfs,
        configStore: os.configStore,
        ipc: os.ipc,
        intentRouter: os.intentRouter,
        clipboard: os.clipboard,
        notifications: os.notifications,
        users: os.users,
        permissions: os.permissions,
        compositor: os.compositor,
      };
      const x64Ctx = await os.runtimes.macos.createExecutionContext(x64Pcb, studioRecord, x64Services, {
        arch: 'x86_64',
      });
      x64Pcb.executionContext = x64Ctx;
      os.processManager.transitionState(x64Pcb.pid, PROCESS_STATES.READY, { reason: 'macos_x64_slice_test' });
      os.scheduler.runUntilIdle(x64Pcb.pid, 200);

      const x64Debug = x64Ctx.getDebugState();
      assert.equal(x64Debug.arch, 'x86_64', 'Intel x86-64 slice must report arch === x86_64');
      assert.equal(x64Pcb.arch, 'x86_64');
      const x64Win = os.compositor.listWindows({ pid: x64Pcb.pid })[0];
      assert.ok(x64Win, 'Intel x86-64 macOS slice must create a live CompositorWindow');
      assert.ok(Array.isArray(x64Debug.menuBar) && x64Debug.menuBar.length > 0, 'Intel slice must populate menuBar');
      assert.equal(
        os.configStore.defaults.get('com.omnios.macos.studio', 'studio.theme'),
        'graphite-pro',
        'Intel x86-64 slice must execute real ObjC NSUserDefaults write'
      );
      os.compositor.closeWindow(x64Win.windowId);
      os.scheduler.runUntilIdle(x64Pcb.pid, 200);
      assert.ok(
        x64Pcb.state === PROCESS_STATES.ZOMBIE || x64Pcb.state === PROCESS_STATES.TERMINATED,
        'Intel x86-64 slice must exit cleanly on window_close'
      );
      assert.equal(x64Pcb.stats.exitCode, 0);

      // --- Verify (7) universal-canvas.uapp: WASM/WASI drawOps + live pointer_down redraw ---
      const canvasWin0 = os.compositor.listWindows({ pid: canvasLaunch.pid })[0];
      assert.ok(canvasWin0, 'universal-canvas.uapp must create a CompositorWindow');
      assert.ok(Array.isArray(canvasWin0.surface.drawOps) && canvasWin0.surface.drawOps.length > 0);
      const canvasRev0 = canvasWin0.surfaceRevision;
      const canvasOps0 = canvasWin0.surface.drawOps.length;
      os.compositor.dispatchInput(canvasWin0.windowId, { type: 'pointer_down', x: 180, y: 120, button: 0 });
      os.scheduler.step(20);
      const canvasWin1 = os.compositor.getWindow(canvasWin0.windowId);
      assert.ok(canvasWin1.surfaceRevision > canvasRev0, 'pointer_down must trigger WASM redraw & bump surfaceRevision');
      assert.ok(canvasWin1.surface.drawOps.length >= canvasOps0, 'WASM canvas drawOps must remain populated after redraw');

      // 6. Verify kernel panic + os.recover()
      const panicDump = os.kernel.panic('E_TEST_PANIC', 'Suite 1 controlled panic test', { source: 'm5-test' });
      assert.equal(os.kernel.state, 'PANIC');
      assert.equal(panicDump.code, 'E_TEST_PANIC');

      const recovReport = await os.recover();
      assert.equal(recovReport.status, 'RUNNING');
      assert.equal(os.kernel.state, 'RUNNING');
      for (const svc of os.serviceManager.getStatus()) {
        assert.equal(svc.state, 'RUNNING', `Post-recovery service ${svc.name} must be RUNNING`);
      }
    } finally {
      await os.shutdown();
      await cleanupTempDir(dataDir);
    }
  });
});

// ============================================================================
// SUITE 2 — HTTP REST API v1, Health & Static `ui/` Security (`F-062`)
// ============================================================================

describe('Suite 2 (F-062): HTTP REST API v1, Health Endpoints & Static ui/ Security', () => {
  it('serves all Contract 7 REST routes, binary uploads, coexistence, and error codes on ephemeral port', async () => {
    const dataDir = await makeTempDir('omnios-m5-http-');
    const missingUiDir = path.join(dataDir, 'nonexistent-ui');
    const os = await bootOmniOS({ dataDir, autoStartScheduler: false });
    const server = createHttpServer(os, { port: 0, host: '127.0.0.1', uiDir: missingUiDir });

    try {
      const addr = await server.start();
      assert.ok(addr.port > 0);
      const req = async (method, urlPath, { json, rawBody, headers = {} } = {}) => {
        const init = { method, headers: { ...headers } };
        if (json !== undefined) {
          init.headers['Content-Type'] = 'application/json';
          init.body = JSON.stringify(json);
        } else if (rawBody !== undefined) {
          init.body = rawBody;
        }
        const res = await fetch(`${addr.url}${urlPath}`, init);
        const ct = res.headers.get('content-type') ?? '';
        const text = await res.text();
        let data = null;
        if (ct.includes('application/json')) {
          data = text ? JSON.parse(text) : null;
        }
        return { status: res.status, headers: res.headers, text, data };
      };

      // Health + Fallback HTML when uiDir missing
      const h1 = await req('GET', '/api/health');
      assert.equal(h1.status, 200);
      assert.equal(h1.data.ok, true);
      assert.equal(h1.data.os, 'OmniOS');

      const hHead = await fetch(`${addr.url}/api/health`, { method: 'HEAD' });
      assert.equal(hHead.status, 200);

      const h2 = await req('GET', '/api/v1/health');
      assert.equal(h2.status, 200);
      assert.equal(h2.data.services.length, 6);

      const fallbackHtml = await req('GET', '/');
      assert.equal(fallbackHtml.status, 200);
      assert.match(fallbackHtml.headers.get('content-type') ?? '', /text\/html/);
      assert.match(fallbackHtml.text, /OmniOS/);

      // Kernel routes
      const kStatus = await req('GET', '/api/v1/kernel/status');
      assert.equal(kStatus.status, 200);
      assert.equal(kStatus.data.state, 'RUNNING');

      const kDmesg = await req('GET', '/api/v1/kernel/dmesg?limit=25');
      assert.equal(kDmesg.status, 200);
      assert.ok(Array.isArray(kDmesg.data.entries) && kDmesg.data.entries.length > 0);

      const kSvcs = await req('GET', '/api/v1/kernel/services');
      assert.equal(kSvcs.status, 200);
      assert.equal(kSvcs.data.services.length, 6);

      const kRestart = await req('POST', '/api/v1/kernel/services/vfsd/restart');
      assert.equal(kRestart.status, 200);
      assert.equal(kRestart.data.service.state, 'RUNNING');

      const kHealth = await req('POST', '/api/v1/kernel/services/vfsd/health');
      assert.equal(kHealth.status, 200);

      // Kernel panic & recover
      const kPanic = await req('POST', '/api/v1/kernel/panic', { json: { code: 'E_HTTP_PANIC', reason: 'HTTP test' } });
      assert.equal(kPanic.status, 200);
      assert.equal(kPanic.data.panic.code, 'E_HTTP_PANIC');
      const kRec = await req('POST', '/api/v1/kernel/recover', { json: { safeMode: false } });
      assert.equal(kRec.status, 200);
      assert.equal(kRec.data.bootReport.status, 'RUNNING');

      // Processes routes + PID 1 EPERM (403) + missing PID (404)
      const procs = await req('GET', '/api/v1/processes');
      assert.equal(procs.status, 200);
      assert.ok(procs.data.processes.some((p) => p.pid === 1));

      const pTree = await req('GET', '/api/v1/processes/tree');
      assert.equal(pTree.status, 200);
      assert.ok(Array.isArray(pTree.data.tree));

      const p1 = await req('GET', '/api/v1/processes/1');
      assert.equal(p1.status, 200);
      assert.equal(p1.data.process.pid, 1);

      const pMissing = await req('GET', '/api/v1/processes/999999');
      assert.equal(pMissing.status, 404);

      const killPid1 = await req('POST', '/api/v1/processes/1/signal', { json: { signal: 'SIGKILL' } });
      assert.equal(killPid1.status, 403);
      assert.equal(killPid1.data.error.code, 'EPERM');

      // Launch system app, write stdin, inspect detail, signal stop
      const termLaunch = await req('POST', '/api/v1/packages/com.omnios.terminal/launch', { json: {} });
      assert.equal(termLaunch.status, 200);
      assert.equal(termLaunch.data.platform, 'system');
      assert.ok(termLaunch.data.windowIds.length >= 1);
      const termPid = termLaunch.data.pid;
      const termWinId = termLaunch.data.windowIds[0];

      const stdinRes = await req('POST', `/api/v1/processes/${termPid}/stdin`, { json: { data: 'hello\n' } });
      assert.equal(stdinRes.status, 200);
      assert.equal(stdinRes.data.bytesWritten, 6);

      // VFS routes (mkdir, PUT/GET/POST/DELETE file, rename, symlink, resolve Windows path, /dev/zero, dir delete, mounts)
      const mkRes = await req('POST', '/api/v1/vfs/mkdir', { json: { path: '/home/user/http-test', recursive: true } });
      assert.equal(mkRes.status, 201);

      const putFile = await req('PUT', '/api/v1/vfs/file', {
        json: { path: '/home/user/http-test/hello.txt', content: 'Hello HTTP VFS' },
      });
      assert.equal(putFile.status, 200);

      const getFile = await req('GET', '/api/v1/vfs/file?path=/home/user/http-test/hello.txt');
      assert.equal(getFile.status, 200);
      assert.equal(getFile.data.content, 'Hello HTTP VFS');

      const postAppend = await req('POST', '/api/v1/vfs/file', {
        json: { path: '/home/user/http-test/hello.txt', content: '!', append: true },
      });
      assert.equal(postAppend.status, 200);
      const getAppended = await req('GET', '/api/v1/vfs/file?path=/home/user/http-test/hello.txt');
      assert.equal(getAppended.data.content, 'Hello HTTP VFS!');

      const lsRes = await req('GET', '/api/v1/vfs/ls?path=/home/user/http-test');
      assert.equal(lsRes.status, 200);
      assert.ok(lsRes.data.entries.some((e) => e.name === 'hello.txt'));

      const statRes = await req('GET', '/api/v1/vfs/stat?path=/home/user/http-test/hello.txt');
      assert.equal(statRes.status, 200);
      assert.equal(statRes.data.stat.type, 'file');

      const symRes = await req('POST', '/api/v1/vfs/symlink', {
        json: { target: '/home/user/http-test/hello.txt', linkPath: '/home/user/http-test/link.txt' },
      });
      assert.equal(symRes.status, 201);

      const renRes = await req('POST', '/api/v1/vfs/rename', {
        json: { oldPath: '/home/user/http-test/hello.txt', newPath: '/home/user/http-test/renamed.txt' },
      });
      assert.equal(renRes.status, 200);

      const winResolve = await req(
        'GET',
        `/api/v1/vfs/resolve?path=${encodeURIComponent('C:\\Users\\user\\Documents')}&platform=windows`
      );
      assert.equal(winResolve.status, 200);
      assert.equal(winResolve.data.canonicalPath, '/home/user/Documents');

      const devZero = await req('GET', '/api/v1/vfs/file?path=/dev/zero&encoding=base64&length=16');
      assert.equal(devZero.status, 200);
      assert.equal(devZero.data.size, 16);
      assert.deepEqual(Array.from(Buffer.from(devZero.data.content, 'base64')), new Array(16).fill(0));

      const mounts = await req('GET', '/api/v1/vfs/mounts');
      assert.equal(mounts.status, 200);
      assert.ok(Array.isArray(mounts.data.mounts) && mounts.data.mounts.length > 0);

      const delFile = await req('DELETE', '/api/v1/vfs/file?path=/home/user/http-test/renamed.txt');
      assert.equal(delFile.status, 200);
      assert.equal(delFile.data.type, 'file');

      const delDir = await req('DELETE', '/api/v1/vfs/file?path=/home/user/http-test&recursive=true');
      assert.equal(delDir.status, 200);
      assert.equal(delDir.data.type, 'dir');

      // Config routes: system + live sync, Registry (incl. REG_QWORD BigInt), Defaults (JSON & XML plist), SharedPrefs
      const sysPut = await req('PUT', '/api/v1/config/system', { json: { key: 'system.theme', value: 'light' } });
      assert.equal(sysPut.status, 200);
      assert.equal(sysPut.data.values['system.theme'], 'light');
      const nsGlobalTheme = await req('GET', '/api/v1/config/defaults?domain=NSGlobalDomain&key=AppleInterfaceStyle');
      assert.equal(nsGlobalTheme.status, 200);
      assert.equal(String(nsGlobalTheme.data.value).toLowerCase(), 'light');

      const regQword = await req('PUT', '/api/v1/config/registry', {
        json: {
          hive: 'HKCU',
          keyPath: 'Software\\OmniOS\\HttpTest',
          valueName: 'BigCounter',
          type: 'REG_QWORD',
          data: '9007199254740993123',
        },
      });
      assert.equal(regQword.status, 200);
      const regGet = await req(
        'GET',
        `/api/v1/config/registry?hive=HKCU&keyPath=${encodeURIComponent('Software\\OmniOS\\HttpTest')}&valueName=BigCounter`
      );
      assert.equal(regGet.status, 200);
      assert.equal(regGet.data.value.type, 'REG_QWORD');
      assert.equal(regGet.data.value.data, '9007199254740993123');

      const defPut = await req('PUT', '/api/v1/config/defaults', {
        json: { domain: 'com.omnios.httptest', key: 'greeting', value: 'bonjour' },
      });
      assert.equal(defPut.status, 200);
      const defJson = await req('GET', '/api/v1/config/defaults?domain=com.omnios.httptest');
      assert.equal(defJson.data.values.greeting, 'bonjour');
      const defPlist = await req('GET', '/api/v1/config/defaults?domain=com.omnios.httptest&format=plist');
      assert.equal(defPlist.status, 200);
      assert.match(defPlist.headers.get('content-type') ?? '', /xml/);
      assert.match(defPlist.text, /<plist/);
      assert.match(defPlist.text, /bonjour/);

      const prefsPut = await req('PUT', '/api/v1/config/prefs', {
        json: { packageName: 'com.omnios.httptest', prefName: 'main', key: 'score', value: 77 },
      });
      assert.equal(prefsPut.status, 200);
      const prefsGet = await req('GET', '/api/v1/config/prefs?packageName=com.omnios.httptest&prefName=main&key=score');
      assert.equal(prefsGet.data.value, 77);
      assert.equal((await req('DELETE', '/api/v1/config/prefs?packageName=com.omnios.httptest&prefName=main&key=score')).status, 200);
      assert.equal((await req('DELETE', '/api/v1/config/defaults?domain=com.omnios.httptest&key=greeting')).status, 200);
      assert.equal(
        (await req('DELETE', `/api/v1/config/registry?hive=HKCU&keyPath=${encodeURIComponent('Software\\OmniOS\\HttpTest')}&valueName=BigCounter`)).status,
        200
      );

      // IPC routes: intents resolve/dispatch/choose, clipboard, notifications
      const intRes = await req('GET', '/api/v1/ipc/intents/resolve?action=send&mime=text/plain');
      assert.equal(intRes.status, 200);
      assert.ok(intRes.data.candidates.some((c) => c.appId === 'com.omnios.notes'));

      os.intentRouter.registerHandlers(
        'com.omnios.custom.chooser1',
        [{ actions: ['share_test'], mimeTypes: ['text/x-chooser'], priority: 10 }],
        { platform: 'system', label: 'Chooser Target 1' }
      );
      os.intentRouter.registerHandlers(
        'com.omnios.custom.chooser2',
        [{ actions: ['share_test'], mimeTypes: ['text/x-chooser'], priority: 10 }],
        { platform: 'system', label: 'Chooser Target 2' }
      );
      const chooseDisp = await req('POST', '/api/v1/ipc/intents/dispatch', {
        json: { action: 'share_test', mimeType: 'text/x-chooser' },
      });
      assert.equal(chooseDisp.status, 200);
      assert.equal(chooseDisp.data.status, 'CHOOSER_REQUIRED');
      const chosen = await req('POST', '/api/v1/ipc/intents/choose', {
        json: { requestId: chooseDisp.data.requestId, cancel: true },
      });
      assert.equal(chosen.status, 200);
      assert.equal(chosen.data.cancelled, true);

      const clipSet = await req('POST', '/api/v1/ipc/clipboard', { json: { text: 'HTTP Clipboard Data' } });
      assert.equal(clipSet.status, 200);
      const clipGet = await req('GET', '/api/v1/ipc/clipboard');
      assert.equal(clipGet.data.current.text, 'HTTP Clipboard Data');

      const notifPost = await req('POST', '/api/v1/ipc/notifications', {
        json: {
          appId: 'com.omnios.httptest',
          title: 'HTTP Alert',
          body: 'Action required',
          actions: [{ id: 'ack', label: 'Acknowledge' }],
        },
      });
      assert.equal(notifPost.status, 201);
      const notifId = notifPost.data.notification.id;
      const notifAct = await req('POST', `/api/v1/ipc/notifications/${encodeURIComponent(notifId)}/action`, {
        json: { actionId: 'ack' },
      });
      assert.equal(notifAct.status, 200);
      const notifDis = await req('POST', `/api/v1/ipc/notifications/${encodeURIComponent(notifId)}/dismiss`);
      assert.equal(notifDis.status, 200);

      // Security routes: permissions (GET, PUT grant, PUT prompt resolve), audit, users
      const permsGet = await req('GET', '/api/v1/security/permissions');
      assert.equal(permsGet.status, 200);
      assert.equal(permsGet.data.capabilities.length, ALL_CAPABILITIES.length);

      const grantRes = await req('PUT', '/api/v1/security/permissions', {
        json: { appId: 'com.omnios.httptest', capability: 'clipboard.write', state: 'allow' },
      });
      assert.equal(grantRes.status, 200);
      assert.equal(grantRes.data.grant.state, 'allow');

      const promptPromise = os.permissions.checkPermission({
        appId: 'com.omnios.httptest',
        pid: 1,
        platform: 'android',
        capability: 'location.device',
      });
      const pendingList = (await req('GET', '/api/v1/security/permissions')).data.pendingPrompts;
      assert.ok(pendingList.length >= 1);
      const promptId = pendingList[0].promptId;
      const resolveHttp = await req('PUT', '/api/v1/security/permissions', {
        json: { promptId, decision: 'allow' },
      });
      assert.equal(resolveHttp.status, 200);
      const promptOutcome = await promptPromise;
      assert.equal(promptOutcome.granted, true);

      const auditRes = await req('GET', '/api/v1/security/audit?appId=com.omnios.httptest');
      assert.equal(auditRes.status, 200);
      assert.ok(auditRes.data.entries.length > 0);

      const usersRes = await req('GET', '/api/v1/security/users');
      assert.equal(usersRes.status, 200);
      assert.ok(usersRes.data.users.some((u) => u.uid === 0));

      // Packages routes: catalog, JSON {path}, JSON {base64}, raw application/octet-stream + X-Filename, launch/stop/delete
      const catRes = await req('GET', '/api/v1/packages/catalog');
      assert.equal(catRes.status, 200);
      assert.equal(catRes.data.catalog.length, 7);

      const inspPath = await req('POST', '/api/v1/packages/inspect', {
        json: { path: '/packages/android-calc.apk' },
      });
      assert.equal(inspPath.status, 200);
      assert.equal(inspPath.data.inspection.appId, 'com.omnios.calc');

      const calcBytes = await fsp.readFile(path.join(PACKAGES_DIR, 'android-calc.apk'));
      const rawInsp = await req('POST', '/api/v1/packages/inspect', {
        rawBody: calcBytes,
        headers: { 'Content-Type': 'application/octet-stream', 'X-Filename': 'android-calc.apk' },
      });
      assert.equal(rawInsp.status, 200);
      assert.equal(rawInsp.data.inspection.format, 'android-apk');

      const rawInst = await req('POST', '/api/v1/packages/install?grantAll=true', {
        rawBody: calcBytes,
        headers: { 'Content-Type': 'application/octet-stream', 'X-Filename': 'android-calc.apk' },
      });
      assert.equal(rawInst.status, 201);
      assert.equal(rawInst.data.package.appId, 'com.omnios.calc');

      const notesApkBytes = await fsp.readFile(path.join(PACKAGES_DIR, 'android-notes-sharer.apk'));
      const b64Inst = await req('POST', '/api/v1/packages/install', {
        json: {
          base64: notesApkBytes.toString('base64'),
          filenameHint: 'android-notes-sharer.apk',
          grantAll: true,
        },
      });
      assert.equal(b64Inst.status, 201);
      const launchAndroidNotes = await req('POST', '/api/v1/packages/com.omnios.notes/launch', { json: {} });
      assert.equal(launchAndroidNotes.status, 200);
      assert.equal(launchAndroidNotes.data.platform, 'android');
      const launchSysNotes = await req('POST', '/api/v1/packages/com.omnios.notes/launch', {
        json: { preferSystem: true },
      });
      assert.equal(launchSysNotes.status, 200);
      assert.equal(launchSysNotes.data.platform, 'system');

      const stopNotes = await req('POST', '/api/v1/packages/com.omnios.notes/stop', { json: {} });
      assert.equal(stopNotes.status, 200);
      assert.ok(stopNotes.data.stoppedPids.length >= 2);

      const pkgGet = await req('GET', '/api/v1/packages/com.omnios.calc');
      assert.equal(pkgGet.status, 200);
      assert.equal(pkgGet.data.package.appId, 'com.omnios.calc');

      const pkgDel = await req('DELETE', '/api/v1/packages/com.omnios.calc?purgeData=true');
      assert.equal(pkgDel.status, 200);
      assert.equal(pkgDel.data.removed, true);

      // Compositor routes
      const compSnap = await req('GET', '/api/v1/compositor/snapshot');
      assert.equal(compSnap.status, 200);
      assert.ok(compSnap.data.windows.some((w) => w.windowId === termWinId));

      const modeRes = await req('PUT', '/api/v1/compositor/shell-mode', { json: { mode: 'macos' } });
      assert.equal(modeRes.status, 200);
      assert.equal(modeRes.data.snapshot.shellMode, 'macos');

      const mvRes = await req('POST', `/api/v1/compositor/windows/${termWinId}/move`, { json: { x: 40, y: 50 } });
      assert.equal(mvRes.status, 200);
      assert.equal(mvRes.data.window.bounds.x, 40);

      const rzRes = await req('POST', `/api/v1/compositor/windows/${termWinId}/resize`, { json: { width: 700, height: 450 } });
      assert.equal(rzRes.status, 200);
      assert.equal(rzRes.data.window.bounds.width, 700);

      const focRes = await req('POST', `/api/v1/compositor/windows/${termWinId}/focus`);
      assert.equal(focRes.status, 200);

      const stRes = await req('POST', `/api/v1/compositor/windows/${termWinId}/state`, { json: { state: 'snapped-left' } });
      assert.equal(stRes.status, 200);
      assert.equal(stRes.data.window.state, 'snapped-left');

      const inpRes = await req('POST', `/api/v1/compositor/windows/${termWinId}/input`, {
        json: { type: 'submit', command: 'echo http-term-ok' },
      });
      assert.equal(inpRes.status, 200);
      assert.equal(inpRes.data.delivered.delivered, true);

      const clsRes = await req('POST', `/api/v1/compositor/windows/${termWinId}/close`);
      assert.equal(clsRes.status, 200);

      // Shell & Search routes
      const shRes = await req('POST', '/api/v1/shell/exec', { json: { command: 'echo REST_SHELL_OK' } });
      assert.equal(shRes.status, 200);
      assert.equal(shRes.data.stdout.trim(), 'REST_SHELL_OK');

      const searchRes = await req('GET', '/api/v1/search?q=OmniTerm');
      assert.equal(searchRes.status, 200);
      assert.ok(searchRes.data.results.some((r) => r.appId === 'com.omnios.terminal'));

      // Error bounds: 400 malformed JSON, 404 unknown /api/*, 405 wrong method + Allow
      const badJson = await req('POST', '/api/v1/shell/exec', {
        rawBody: '{"broken":',
        headers: { 'Content-Type': 'application/json' },
      });
      assert.equal(badJson.status, 400);

      const unknownApi = await req('GET', '/api/v1/does-not-exist');
      assert.equal(unknownApi.status, 404);

      const wrongMethod = await req('DELETE', '/api/v1/kernel/status');
      assert.equal(wrongMethod.status, 405);
      assert.match(wrongMethod.headers.get('allow') ?? '', /GET/);
    } finally {
      await server.stop();
      await os.shutdown();
      await cleanupTempDir(dataDir);
    }
  });

  it('enforces 413 body limits, raw TCP static path traversal rejection, symlink containment, and real static uiDir serving', async () => {
    const tmpRoot = await makeTempDir('omnios-m5-sec-');
    const uiDir = path.join(tmpRoot, 'ui');
    const outsideSecret = path.join(tmpRoot, 'secret.txt');
    await fsp.mkdir(uiDir, { recursive: true });
    await fsp.writeFile(path.join(uiDir, 'index.html'), '<!doctype html><html><body>Real UI OK</body></html>');
    await fsp.writeFile(path.join(uiDir, 'app.js'), 'export const ok = true;\n');
    await fsp.writeFile(outsideSecret, 'TOP_SECRET_OUTSIDE_UI');
    await fsp.symlink(outsideSecret, path.join(uiDir, 'escape-link.txt'));

    const { server, address } = await startOmniOSServer({
      port: 0,
      host: '127.0.0.1',
      uiDir,
      seedSamples: false,
      autoStartScheduler: false,
      maxJsonBodyBytes: 128,
      maxBinaryBodyBytes: 256,
    });

    try {
      const idxRes = await fetch(`${address.url}/`);
      assert.equal(idxRes.status, 200);
      assert.match(await idxRes.text(), /Real UI OK/);

      const jsRes = await fetch(`${address.url}/app.js`);
      assert.equal(jsRes.status, 200);
      assert.match(jsRes.headers.get('content-type') ?? '', /javascript/);

      const symRes = await fetch(`${address.url}/escape-link.txt`);
      assert.equal(symRes.status, 403);

      const t1 = await rawTcpHttpRequest(address.host, address.port, 'GET /../package.json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');
      assert.equal(t1.status, 403);

      const t2 = await rawTcpHttpRequest(address.host, address.port, 'GET /%2e%2e/package.json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');
      assert.equal(t2.status, 403);

      const t3 = await rawTcpHttpRequest(address.host, address.port, 'GET /..%5cpackage.json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');
      assert.equal(t3.status, 403);

      const t4 = await rawTcpHttpRequest(address.host, address.port, 'GET /%E0%A4%A HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');
      assert.equal(t4.status, 400);

      const bigJson = await fetch(`${address.url}/api/v1/shell/exec`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: 'echo ' + 'x'.repeat(300) }),
      });
      assert.equal(bigJson.status, 413);

      const bigBin = await fetch(`${address.url}/api/v1/packages/inspect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream', 'X-Filename': 'big.bin' },
        body: Buffer.alloc(512, 0x41),
      });
      assert.equal(bigBin.status, 413);
    } finally {
      await server.stop();
      await cleanupTempDir(tmpRoot);
    }
  });
});

// ============================================================================
// SUITE 3 — Zero-Dep RFC 6455 WebSocket Server (`/ws`, `F-063`)
// ============================================================================

describe('Suite 3 (F-063): Zero-Dep RFC 6455 WebSocket Server (/ws)', () => {
  it('validates handshake, framing, fragmentation + interleaved PING/PONG, strict protocol violations, Contract 7 bus, and Node 24 WebSocket interop', async () => {
    const os = await bootOmniOS({ seedSamples: false, autoStartScheduler: false });
    const server = createHttpServer(os, {
      port: 0,
      host: '127.0.0.1',
      wsOptions: { maxFrameBytes: 4096, maxMessageBytes: 6144 },
    });

    try {
      const addr = await server.start();

      // 1. Handshake rejections (426 wrong version, 400 invalid key, 404 wrong path)
      const badVer = new RawWsClient();
      const r426 = await badVer.connect(addr.host, addr.port, {
        headers: { 'Sec-WebSocket-Version': '8' },
      });
      assert.equal(r426.status, 426);
      badVer.close();

      const badKey = new RawWsClient();
      const r400 = await badKey.connect(addr.host, addr.port, { key: 'not-16-bytes' });
      assert.equal(r400.status, 400);
      badKey.close();

      const badPath = new RawWsClient();
      const r404 = await badPath.connect(addr.host, addr.port, { path: '/wrong-ws' });
      assert.equal(r404.status, 404);
      badPath.close();

      // 2. Valid RFC 6455 handshake + Sec-WebSocket-Accept + initial unmasked compositor:snapshot
      const ws = new RawWsClient();
      const hs = await ws.connect(addr.host, addr.port);
      assert.equal(hs.status, 101);
      const expectedAccept = crypto
        .createHash('sha1')
        .update(hs.key + WS_GUID, 'utf8')
        .digest('base64');
      assert.equal(hs.headers['sec-websocket-accept'], expectedAccept);

      const snapFrame = await ws.waitForFrame((f) => f.opcode === WS_OPCODES.TEXT && f.json?.type === 'compositor:snapshot');
      assert.equal(snapFrame.masked, false, 'Server->Client frames MUST be unmasked per RFC 6455');
      assert.equal(snapFrame.json.payload.shellMode, 'unified');

      // 3. Fragmented client TEXT message with interleaved PING -> immediate PONG + reassembled terminal:exec
      const fullMsg = JSON.stringify({
        type: 'terminal:exec',
        id: 'frag-1',
        payload: { command: 'echo FRAG_OK' },
      });
      const buf = Buffer.from(fullMsg, 'utf8');
      const part1 = buf.subarray(0, 15);
      const part2 = buf.subarray(15, 35);
      const part3 = buf.subarray(35);

      ws.sendRaw(encodeWsFrame(WS_OPCODES.TEXT, part1, { fin: false, mask: true }));
      ws.sendRaw(encodeWsFrame(WS_OPCODES.PING, Buffer.from('hb-mid-frag'), { fin: true, mask: true }));
      const pongFrame = await ws.waitForFrame((f) => f.opcode === WS_OPCODES.PONG);
      assert.equal(pongFrame.masked, false);
      assert.equal(pongFrame.payload.toString('utf8'), 'hb-mid-frag');

      ws.sendRaw(encodeWsFrame(WS_OPCODES.CONTINUATION, part2, { fin: false, mask: true }));
      ws.sendRaw(encodeWsFrame(WS_OPCODES.CONTINUATION, part3, { fin: true, mask: true }));
      const termRes = await ws.waitForEnvelope('terminal:result');
      assert.equal(termRes.payload.id, 'frag-1');
      assert.equal(termRes.payload.stdout.trim(), 'FRAG_OK');

      // 4. Contract 7 Client->Server commands & live Server->Client broadcasts
      ws.sendJson({ type: 'ping', id: 'p-1', payload: { nonce: 123 } });
      const pongEnv = await ws.waitForEnvelope('pong');
      assert.equal(pongEnv.payload.id, 'p-1');

      ws.sendJson({ type: 'shell:mode', payload: { mode: 'ios' } });
      const snapAfterMode = await ws.waitForEnvelope('compositor:snapshot');
      assert.equal(snapAfterMode.payload.shellMode, 'ios');

      os.configStore.system.set('system.volume', 64);
      const cfgEvt = await ws.waitForEnvelope('config:changed');
      assert.ok(cfgEvt.payload);

      const monLaunch = await os.launchApp('com.omnios.monitor', { stepTicks: 2 });
      const winCreated = await ws.waitForEnvelope('compositor:window_created');
      assert.equal(winCreated.payload.window.appId, 'com.omnios.monitor');
      const monWinId = monLaunch.windowIds[0];

      ws.sendJson({ type: 'compositor:move', payload: { windowId: monWinId, x: 55, y: 66 } });
      const winUpd1 = await ws.waitForEnvelope('compositor:window_updated');
      assert.equal(winUpd1.payload.window.windowId, monWinId);

      ws.sendJson({ type: 'compositor:resize', payload: { windowId: monWinId, width: 880, height: 590 } });
      await ws.waitForEnvelope('compositor:window_updated');

      ws.sendJson({ type: 'compositor:focus', payload: { windowId: monWinId } });
      await ws.waitForEnvelope('compositor:window_updated');

      ws.sendJson({ type: 'compositor:state', payload: { windowId: monWinId, state: 'maximized' } });
      await ws.waitForEnvelope('compositor:window_updated');

      const victim = await os.launchApp('com.omnios.notes', { preferSystem: true });
      await ws.waitForEnvelope('process:update');
      os.processManager.writeStdout(victim.pid, 'LIVE_WS_STDOUT');
      const stdoutEnv = await ws.waitForEnvelope('process:stdout');
      assert.equal(stdoutEnv.payload.data, 'LIVE_WS_STDOUT');
      assert.equal(stdoutEnv.payload.stream, 'stdout');

      const monRevBeforeKill = os.compositor.getWindow(monWinId).surfaceRevision;
      ws.sendJson({
        type: 'compositor:input',
        payload: { windowId: monWinId, action: 'kill', targetPid: victim.pid, signal: 'SIGTERM' },
      });
      await ws.waitForFrame(
        (f) =>
          f.opcode === WS_OPCODES.TEXT &&
          f.json?.type === 'compositor:surface_patch' &&
          f.json.payload?.windowId === monWinId &&
          f.json.payload?.surfaceRevision > monRevBeforeKill,
        { label: 'surface_patch after kill' }
      );
      const victimPcb = os.processManager.get(victim.pid);
      assert.ok(
        victimPcb.state === PROCESS_STATES.ZOMBIE || victimPcb.state === PROCESS_STATES.TERMINATED,
        'Flat WS compositor:input with targetPid must pass through and terminate victim PID'
      );

      const monRevBeforeMenu = os.compositor.getWindow(monWinId).surfaceRevision;
      ws.sendJson({ type: 'compositor:menu_action', payload: { windowId: monWinId, actionId: 'tab.services' } });
      await ws.waitForFrame(
        (f) =>
          f.opcode === WS_OPCODES.TEXT &&
          f.json?.type === 'compositor:surface_patch' &&
          f.json.payload?.windowId === monWinId &&
          f.json.payload?.surfaceRevision > monRevBeforeMenu,
        { label: 'surface_patch after menu_action' }
      );
      assert.equal(os.compositor.getWindow(monWinId).surface.uiTree.props.activeTab, 'services');

      ws.sendJson({ type: 'compositor:close', payload: { windowId: monWinId } });
      const winClosedFrame = await ws.waitForFrame(
        (f) =>
          f.opcode === WS_OPCODES.TEXT &&
          f.json?.type === 'compositor:window_closed' &&
          f.json.payload?.windowId === monWinId,
        { label: `window_closed:${monWinId}` }
      );
      assert.equal(winClosedFrame.json.payload.windowId, monWinId);

      const notif = os.notifications.post({ appId: 'com.omnios.ws', title: 'WS Ping', body: 'Hello' });
      const nPosted = await ws.waitForEnvelope('notification:posted');
      assert.equal(nPosted.payload.id, notif.id);
      os.notifications.dismiss(notif.id);
      const nUpd = await ws.waitForEnvelope('notification:updated');
      assert.equal(nUpd.payload.type, 'dismissed');

      os.kernel.log('info', 'ws-test', 'Kernel WS broadcast test');
      const kEvt = await ws.waitForEnvelope('kernel:event');
      assert.equal(kEvt.payload.event, 'kernel:dmesg');

      const permPromise = os.permissions.checkPermission({
        appId: 'com.omnios.ws.perm',
        pid: 1,
        platform: 'ios',
        capability: 'camera.device',
      });
      const promptEnv = await ws.waitForEnvelope('permission:prompt');
      ws.sendJson({
        type: 'permission:decision',
        payload: { promptId: promptEnv.payload.promptId, decision: 'allow_once' },
      });
      const permOutcome = await permPromise;
      assert.equal(permOutcome.granted, true);

      os.intentRouter.registerHandlers(
        'com.omnios.notes',
        [{ actions: ['ws_pick'], mimeTypes: ['text/x-ws'], priority: 5 }],
        { platform: 'system', label: 'OmniNotes WS Pick', replace: false }
      );
      os.intentRouter.registerHandlers(
        'com.omnios.files',
        [{ actions: ['ws_pick'], mimeTypes: ['text/x-ws'], priority: 5 }],
        { platform: 'system', label: 'OmniFiles WS Pick', replace: false }
      );
      const dispRes = await os.intentRouter.dispatch({
        action: 'ws_pick',
        mimeType: 'text/x-ws',
        extras: { title: 'ws-chosen.txt', text: 'Chosen via WS' },
      });
      assert.equal(dispRes.status, 'CHOOSER_REQUIRED');
      const chooserEnv = await ws.waitForEnvelope('intent:chooser');
      assert.equal(chooserEnv.payload.requestId, dispRes.requestId);
      ws.sendJson({
        type: 'intent:choice',
        payload: { requestId: dispRes.requestId, appId: 'com.omnios.notes' },
      });
      const chosenWin = await ws.waitForFrame(
        (f) =>
          f.opcode === WS_OPCODES.TEXT &&
          f.json?.type === 'compositor:window_created' &&
          f.json.payload?.window?.appId === 'com.omnios.notes',
        { label: 'window_created for WS intent:choice' }
      );
      assert.equal(chosenWin.json.payload.window.appId, 'com.omnios.notes');

      const closeBody = Buffer.alloc(2);
      closeBody.writeUInt16BE(WS_CLOSE_CODES.NORMAL, 0);
      ws.sendRaw(encodeWsFrame(WS_OPCODES.CLOSE, closeBody, { mask: true }));
      const closeEcho = await ws.waitForClose();
      assert.equal(closeEcho.closeCode, WS_CLOSE_CODES.NORMAL);
      ws.close();

      // 5. Strict RFC 6455 protocol violation checks
      const assertViolationCloseCode = async (label, rawFrames, expectedCode) => {
        const c = new RawWsClient();
        try {
          const r = await c.connect(addr.host, addr.port);
          assert.equal(r.status, 101, `${label}: handshake must succeed`);
          await c.waitForEnvelope('compositor:snapshot');
          for (const frame of rawFrames) {
            c.sendRaw(frame);
          }
          const closeFrame = await c.waitForClose();
          assert.equal(
            closeFrame.closeCode,
            expectedCode,
            `${label}: expected close code ${expectedCode}, got ${closeFrame.closeCode}`
          );
        } finally {
          c.close();
        }
      };

      await assertViolationCloseCode(
        'unmasked-client-frame',
        [encodeWsFrame(WS_OPCODES.TEXT, Buffer.from('{"type":"ping"}'), { mask: false })],
        1002
      );
      await assertViolationCloseCode(
        'rsv1-nonzero',
        [encodeWsFrame(WS_OPCODES.TEXT, Buffer.from('{"type":"ping"}'), { mask: true, rsv1: true })],
        1002
      );
      await assertViolationCloseCode(
        'rsv2-nonzero',
        [encodeWsFrame(WS_OPCODES.TEXT, Buffer.from('{"type":"ping"}'), { mask: true, rsv2: true })],
        1002
      );
      await assertViolationCloseCode(
        'rsv3-nonzero',
        [encodeWsFrame(WS_OPCODES.TEXT, Buffer.from('{"type":"ping"}'), { mask: true, rsv3: true })],
        1002
      );
      await assertViolationCloseCode(
        'reserved-opcode',
        [encodeWsFrame(0x3, Buffer.alloc(0), { mask: true })],
        1002
      );
      await assertViolationCloseCode(
        'fragmented-control',
        [encodeWsFrame(WS_OPCODES.PING, Buffer.from('x'), { fin: false, mask: true })],
        1002
      );
      await assertViolationCloseCode(
        'oversized-control',
        [encodeWsFrame(WS_OPCODES.PING, Buffer.alloc(126, 0x41), { fin: true, mask: true })],
        1002
      );
      await assertViolationCloseCode(
        'unexpected-continuation',
        [encodeWsFrame(WS_OPCODES.CONTINUATION, Buffer.from('orphan'), { fin: true, mask: true })],
        1002
      );
      await assertViolationCloseCode(
        'invalid-utf8',
        [encodeWsFrame(WS_OPCODES.TEXT, Buffer.from([0xff, 0xfe, 0xfd]), { fin: true, mask: true })],
        1007
      );
      await assertViolationCloseCode(
        'close-1byte',
        [encodeWsFrame(WS_OPCODES.CLOSE, Buffer.from([0x03]), { fin: true, mask: true })],
        1002
      );
      const badClose1005 = Buffer.alloc(2);
      badClose1005.writeUInt16BE(1005, 0);
      await assertViolationCloseCode(
        'close-code-1005',
        [encodeWsFrame(WS_OPCODES.CLOSE, badClose1005, { fin: true, mask: true })],
        1002
      );
      await assertViolationCloseCode(
        'oversized-frame',
        [encodeWsFrame(WS_OPCODES.TEXT, Buffer.alloc(5000, 0x61), { fin: true, mask: true })],
        1009
      );
      await assertViolationCloseCode(
        'oversized-fragmented-message',
        [
          encodeWsFrame(WS_OPCODES.TEXT, Buffer.alloc(3500, 0x61), { fin: false, mask: true }),
          encodeWsFrame(WS_OPCODES.CONTINUATION, Buffer.alloc(3500, 0x62), { fin: true, mask: true }),
        ],
        1009
      );

      // 6. Node 24 native global WebSocket client interop
      assert.equal(typeof globalThis.WebSocket, 'function', 'Node 24 global WebSocket must be available');
      await new Promise((resolve, reject) => {
        const nativeWs = new globalThis.WebSocket(addr.wsUrl);
        const received = [];
        const timer = setTimeout(() => {
          nativeWs.close();
          reject(new Error('Native WebSocket interop timeout'));
        }, 4000);
        timer.unref?.();

        nativeWs.addEventListener('message', (ev) => {
          const parsed = JSON.parse(String(ev.data));
          received.push(parsed.type);
          if (parsed.type === 'compositor:snapshot') {
            nativeWs.send(JSON.stringify({ type: 'ping', id: 'native-1' }));
          } else if (parsed.type === 'pong') {
            nativeWs.send(JSON.stringify({ type: 'terminal:exec', id: 'native-2', payload: { command: 'echo NATIVE_WS_OK' } }));
          } else if (parsed.type === 'terminal:result') {
            assert.equal(parsed.payload.stdout.trim(), 'NATIVE_WS_OK');
            clearTimeout(timer);
            nativeWs.close(1000, 'done');
          }
        });
        nativeWs.addEventListener('close', () => {
          clearTimeout(timer);
          assert.ok(received.includes('compositor:snapshot'));
          assert.ok(received.includes('pong'));
          assert.ok(received.includes('terminal:result'));
          resolve();
        });
        nativeWs.addEventListener('error', (err) => {
          clearTimeout(timer);
          reject(err);
        });
      });
    } finally {
      await server.stop();
      await os.shutdown();
    }
  });
});

// ============================================================================
// SUITE 4 — Spotlight Universal Search (`os/server/search.mjs`, `F-064`)
// ============================================================================

describe('Suite 4 (F-064): Spotlight Universal Search Engine', () => {
  it('indexes & ranks macOS Spotlight metadata, installed & catalog apps, 7 system apps, VFS files, processes, settings, defaults & quick actions', async () => {
    const os = await bootOmniOS({ autoStartScheduler: false });
    try {
      await os.pkgManager.install('/packages/macos-studio.app.zip', {
        filenameHint: 'macos-studio.app.zip',
        grantAll: true,
      });

      os.vfs.writeFile('/home/user/Documents/quarterly-quantum-roadmap.txt', 'Q4 Quantum Plan', {
        uid: 1000,
        gid: 1000,
      });

      const mon = await os.launchApp('com.omnios.monitor');

      const macHit = os.search.query('OmniStudio');
      assert.ok(macHit.results.some((r) => r.type === 'app' && r.appId === 'com.omnios.macos.studio'));
      const macCategoryHit = os.search.query('developer-tools');
      assert.ok(
        macCategoryHit.results.some((r) => r.appId === 'com.omnios.macos.studio'),
        'macOS Spotlight kMDItemCategory must be searchable'
      );

      const catHit = os.search.query('Weather Island');
      const weatherItem = catHit.results.find((r) => r.appId === 'com.omnios.ios.weather-island');
      assert.ok(weatherItem);
      assert.equal(weatherItem.metadata.installed, false);

      const allApps = os.search.query('', { types: 'app', limit: 50 });
      for (const sysId of Object.values(SYSTEM_APP_IDS)) {
        assert.ok(
          allApps.results.some((r) => r.appId === sysId),
          `System app ${sysId} must appear in Spotlight search`
        );
      }

      const fileHit = os.search.query('quantum-roadmap', { types: 'file' });
      assert.ok(
        fileHit.results.some((r) => r.type === 'file' && r.path === '/home/user/Documents/quarterly-quantum-roadmap.txt')
      );
      assert.equal(fileHit.groups.apps.length, 0, 'types=file must exclude apps');

      const procHit = os.search.query(String(mon.pid), { types: 'process' });
      assert.ok(procHit.results.some((r) => r.type === 'process' && r.pid === mon.pid));

      const setHit = os.search.query('brightness', { types: 'setting' });
      assert.ok(setHit.results.some((r) => r.key === 'system.brightness'));
      const defHit = os.search.query('NSGlobalDomain', { types: 'setting' });
      assert.ok(defHit.results.some((r) => r.key === 'NSGlobalDomain'));

      const actHit = os.search.query('switch macos', { types: 'action' });
      assert.ok(actHit.results.some((r) => r.action === 'switch-shell-mode:macos'));

      const emptyRes = os.search.query('');
      assert.ok(emptyRes.results.length > 0);
      const hugeRes = os.search.query('z'.repeat(10_000));
      assert.equal(hugeRes.query.length, 256);
      assert.equal(hugeRes.results.length, 0);
    } finally {
      await os.shutdown();
    }
  });
});

// ============================================================================
// SUITE 5 — Multi-Syntax Shell Interpreter (`os/apps/shell-interpreter.mjs`, `F-066`)
// ============================================================================

describe('Suite 5 (F-066): Multi-Syntax Shell Interpreter', () => {
  it('executes POSIX, Windows, macOS, Android, OmniOS commands, pipes, redirects, chains, lazy var expansion & safety bounds', async () => {
    const os = await bootOmniOS({ autoStartScheduler: false });
    const sh = os.shell;
    try {
      let r = await sh.exec('mkdir -p /home/user/shlab && cd /home/user/shlab && pwd');
      assert.equal(r.exitCode, 0);
      assert.equal(r.stdout.trim(), '/home/user/shlab');

      r = await sh.exec("export HERO=OmniOS && echo \"Hello $HERO\" 'Literal $HERO' ${HERO} %HERO%");
      assert.equal(r.exitCode, 0);
      assert.equal(r.stdout.trim(), 'Hello OmniOS Literal $HERO OmniOS OmniOS');

      r = await sh.exec('echo "alpha\nbeta\ngamma\nbeta2" > lines.txt && echo "delta" >> lines.txt');
      assert.equal(r.exitCode, 0);

      r = await sh.exec('cat lines.txt | grep beta | wc -l');
      assert.equal(r.exitCode, 0);
      assert.equal(r.stdout.trim(), '2');

      r = await sh.exec('head -n 2 lines.txt | tail -n 1');
      assert.equal(r.stdout.trim(), 'beta');

      r = await sh.exec('touch empty.txt && cp lines.txt copy.txt && mv copy.txt moved.txt && ln -s moved.txt sym.txt && stat sym.txt');
      assert.equal(r.exitCode, 0);
      assert.match(r.stdout, /moved\.txt|file|symlink/i);

      r = await sh.exec('ls -la');
      assert.equal(r.exitCode, 0);
      assert.match(r.stdout, /moved\.txt/);

      r = await sh.exec('cat nonexistent_xyz || echo FALLBACK_OK');
      assert.equal(r.exitCode, 0);
      assert.equal(r.stdout.trim(), 'FALLBACK_OK');

      assert.match((await sh.exec('uname -a')).stdout, /OmniOS/);
      assert.equal((await sh.exec('whoami')).stdout.trim(), 'user');
      assert.match((await sh.exec('env')).stdout, /HERO=OmniOS/);
      assert.match((await sh.exec('ps')).stdout, /omnid/);
      assert.ok((await sh.exec('dmesg')).stdout.length > 0);
      assert.match((await sh.exec('help')).stdout, /POSIX/i);
      const clr = await sh.exec('clear');
      assert.equal(clr.cleared, true);

      r = await sh.exec('md C:\\Users\\user\\winlab && echo WinText > C:\\Users\\user\\winlab\\a.txt && type C:\\Users\\user\\winlab\\a.txt');
      assert.equal(r.exitCode, 0);
      assert.equal(r.stdout.trim(), 'WinText');
      assert.match((await sh.exec('dir C:\\Users\\user\\winlab')).stdout, /a\.txt/);
      r = await sh.exec('copy C:\\Users\\user\\winlab\\a.txt C:\\Users\\user\\winlab\\b.txt && move C:\\Users\\user\\winlab\\b.txt C:\\Users\\user\\winlab\\c.txt && del C:\\Users\\user\\winlab\\c.txt && del C:\\Users\\user\\winlab\\a.txt && rd C:\\Users\\user\\winlab');
      assert.equal(r.exitCode, 0);
      assert.match((await sh.exec('tasklist')).stdout, /omnid/);

      r = await sh.exec('reg add HKCU\\Software\\OmniOS\\ShellTest /v Key1 /t REG_SZ /d Value1 && reg query HKCU\\Software\\OmniOS\\ShellTest /v Key1');
      assert.equal(r.exitCode, 0);
      assert.match(r.stdout, /Value1/);
      r = await sh.exec('reg delete HKCU\\Software\\OmniOS\\ShellTest /v Key1');
      assert.equal(r.exitCode, 0);

      const s1 = await os.launchApp('com.omnios.notes');
      r = await sh.exec(`kill ${s1.pid}`);
      assert.equal(r.exitCode, 0);
      const s2 = await os.launchApp('com.omnios.notes');
      r = await sh.exec(`taskkill /PID ${s2.pid} /F`);
      assert.equal(r.exitCode, 0);

      r = await sh.exec('defaults write com.omnios.shmac theme cobalt && defaults read com.omnios.shmac theme');
      assert.equal(r.exitCode, 0);
      assert.equal(r.stdout.trim(), 'cobalt');
      assert.match((await sh.exec('defaults export com.omnios.shmac')).stdout, /<plist/);
      r = await sh.exec('open terminal');
      assert.equal(r.exitCode, 0);

      r = await sh.exec('pm install /packages/android-calc.apk && pm list packages');
      assert.equal(r.exitCode, 0);
      assert.match(r.stdout, /com\.omnios\.calc/);
      r = await sh.exec('pm grant com.omnios.calc clipboard.read && pm revoke com.omnios.calc clipboard.read');
      assert.equal(r.exitCode, 0);
      r = await sh.exec('prefs set com.omnios.calc main theme dark');
      assert.equal(r.exitCode, 0);
      r = await sh.exec('prefs get com.omnios.calc main theme');
      assert.equal(r.exitCode, 0);
      assert.equal(r.stdout.trim(), 'dark');
      r = await sh.exec('am start com.omnios.calc');
      assert.equal(r.exitCode, 0);

      assert.match((await sh.exec('ospm catalog')).stdout, /com\.omnios\.calc/);
      assert.match((await sh.exec('ospm inspect /packages/win-sysinfo.exe')).stdout, /windows/i);
      assert.equal((await sh.exec('ospm stop com.omnios.calc')).exitCode, 0);
      assert.equal((await sh.exec('pm uninstall com.omnios.calc')).exitCode, 0);
      assert.match((await sh.exec('intent resolve --action send --mime text/plain')).stdout, /com\.omnios\.notes/);
      assert.equal((await sh.exec('clip set "Shell Clip Hello"')).exitCode, 0);
      assert.equal((await sh.exec('clip get')).stdout.trim(), 'Shell Clip Hello');
      assert.match((await sh.exec('notify send "ShellTitle" "ShellBody"')).stdout, /ShellTitle|notif/i);
      assert.match((await sh.exec('notify list')).stdout, /ShellTitle/);
      assert.match((await sh.exec('search OmniFiles')).stdout, /OmniFiles/);

      r = await sh.exec('cd /home/user && rm -rf /home/user/shlab');
      assert.equal(r.exitCode, 0);

      const tooLong = await sh.exec('echo ' + 'a'.repeat(9000));
      assert.notEqual(tooLong.exitCode, 0);
      assert.match(tooLong.stderr, /length|maximum/i);

      const deepPipe = await sh.exec(new Array(20).fill('cat').join(' | '));
      assert.notEqual(deepPipe.exitCode, 0);
      assert.match(deepPipe.stderr, /pipeline|depth/i);

      const badQuote = await sh.exec('echo "unterminated');
      assert.notEqual(badQuote.exitCode, 0);
    } finally {
      await os.shutdown();
    }
  });
});

// ============================================================================
// SUITE 6 — All 7 Kernel-Backed Built-in System Apps (`F-067` – `F-072`)
// ============================================================================

describe('Suite 6 (F-067 – F-072): All 7 Kernel-Backed Built-in System Apps', () => {
  it('runs all 7 system apps as real PIDs + CompositorWindows with synchronous step() and live OS mutations', async () => {
    const os = await bootOmniOS({ autoStartScheduler: false });
    try {
      assert.equal(os.systemApps.list().length, 7);

      const assertSyncStep = (pid, label) => {
        const pcb = os.processManager.get(pid);
        assert.ok(pcb?.executionContext, `${label}: missing executionContext`);
        const stepRet = pcb.executionContext.step(50);
        assert.equal(typeof stepRet?.then, 'undefined', `${label}: step() MUST be strictly synchronous`);
        assert.ok(['BLOCKED', 'YIELD', 'EXITED'].includes(stepRet.status));
        const dbg = pcb.executionContext.getDebugState();
        assert.equal(dbg.arch, 'native');
        return pcb;
      };

      // --- 1. OmniTerm (`com.omnios.terminal`) ---
      const term = await os.launchApp(SYSTEM_APP_IDS.TERMINAL);
      const termPcb = assertSyncStep(term.pid, 'OmniTerm');
      const termWin0 = os.compositor.getWindow(term.windowIds[0]);
      const termRev0 = termWin0.surfaceRevision;
      os.compositor.dispatchInput(termWin0.windowId, {
        type: 'submit',
        command: 'echo OMNI_TERM_LIVE > /home/user/Documents/term-live.txt && echo DONE_TERM',
      });
      await termPcb.executionContext.flushPending();
      const termWin1 = os.compositor.getWindow(termWin0.windowId);
      assert.ok(termWin1.surfaceRevision > termRev0);
      assert.equal(
        os.vfs.readFile('/home/user/Documents/term-live.txt', { uid: 1000, gid: 1000, encoding: 'utf8' }).trim(),
        'OMNI_TERM_LIVE'
      );

      // --- 2. OmniFiles (`com.omnios.files`) ---
      const files = await os.launchApp(SYSTEM_APP_IDS.FILES);
      const filesPcb = assertSyncStep(files.pid, 'OmniFiles');
      const filesWin0 = os.compositor.getWindow(files.windowIds[0]);
      const filesRev0 = filesWin0.surfaceRevision;

      const expectedPaths = {
        finder: '/Users/user',
        explorer: 'C:\\Users\\user',
        android: '/sdcard',
        ios: '/var/mobile',
        posix: '/home/user',
      };
      for (const [mode, expectedPrefix] of Object.entries(expectedPaths)) {
        os.compositor.dispatchInput(filesWin0.windowId, { type: 'action', action: 'set_mode', mode });
        const curWin = os.compositor.getWindow(filesWin0.windowId);
        assert.equal(curWin.surface.uiTree.props.viewMode, mode);
        if (mode !== 'ios') {
          assert.ok(
            curWin.surface.uiTree.props.platformPath.startsWith(expectedPrefix),
            `Mode ${mode} platformPath "${curWin.surface.uiTree.props.platformPath}" should start with "${expectedPrefix}"`
          );
        }
      }
      os.compositor.dispatchInput(filesWin0.windowId, { type: 'action', action: 'mkdir', name: 'files-app-dir' });
      os.compositor.dispatchInput(filesWin0.windowId, {
        type: 'action',
        action: 'create_file',
        path: '/home/user/files-app-dir/doc.txt',
        content: 'OmniFiles real VFS write',
      });
      os.compositor.dispatchInput(filesWin0.windowId, {
        type: 'action',
        action: 'symlink',
        target: '/home/user/files-app-dir/doc.txt',
        linkPath: '/home/user/files-app-dir/doc-link.txt',
      });
      os.compositor.dispatchInput(filesWin0.windowId, {
        type: 'action',
        action: 'open_with',
        path: '/home/user/files-app-dir/doc.txt',
      });
      await filesPcb.executionContext.flushPending();
      const filesWin1 = os.compositor.getWindow(filesWin0.windowId);
      assert.ok(filesWin1.surfaceRevision > filesRev0);
      assert.equal(filesWin1.surface.uiTree.children.find((c) => c.id === 'files-preview').props.lastOpenWithResult.status, 'DELIVERED');

      // --- 3. Activity Monitor (`com.omnios.monitor`) ---
      const monitor = await os.launchApp(SYSTEM_APP_IDS.MONITOR);
      const monPcb = assertSyncStep(monitor.pid, 'ActivityMonitor');
      const monWin0 = os.compositor.getWindow(monitor.windowIds[0]);
      assert.ok(Array.isArray(monWin0.surface.drawOps) && monWin0.surface.drawOps.length > 0, 'Monitor must emit Canvas2D drawOps');

      os.compositor.dispatchInput(monWin0.windowId, { type: 'action', action: 'kill', targetPid: 1, signal: 'SIGKILL' });
      const monAfterPid1 = os.compositor.getWindow(monWin0.windowId);
      assert.match(monAfterPid1.surface.uiTree.props.lastError ?? '', /EPERM/i);
      const pid1State = os.processManager.get(1).state;
      assert.ok(pid1State === PROCESS_STATES.READY || pid1State === PROCESS_STATES.RUNNING, `PID 1 must stay alive, got ${pid1State}`);

      const targetTerm = await os.launchApp(SYSTEM_APP_IDS.TERMINAL);
      os.compositor.dispatchInput(monWin0.windowId, {
        type: 'action',
        action: 'kill',
        targetPid: targetTerm.pid,
        signal: 'SIGTERM',
      });
      const deadPcb = os.processManager.get(targetTerm.pid);
      assert.ok(deadPcb.state === PROCESS_STATES.ZOMBIE || deadPcb.state === PROCESS_STATES.TERMINATED);

      const restartsBefore = os.serviceManager.getStatus('vfsd').totalRestarts;
      os.compositor.dispatchInput(monWin0.windowId, { type: 'action', action: 'restart_service', name: 'vfsd' });
      await monPcb.executionContext.flushPending();
      assert.ok(os.serviceManager.getStatus('vfsd').totalRestarts > restartsBefore);

      // --- 4. App Hub (`com.omnios.apphub`) ---
      const hub = await os.launchApp(SYSTEM_APP_IDS.APPHUB);
      const hubPcb = assertSyncStep(hub.pid, 'AppHub');
      const hubWin0 = os.compositor.getWindow(hub.windowIds[0]);
      os.compositor.dispatchInput(hubWin0.windowId, { type: 'action', action: 'set_filter', platform: 'android' });
      assert.equal(os.compositor.getWindow(hubWin0.windowId).surface.uiTree.props.platformFilter, 'android');

      os.compositor.dispatchInput(hubWin0.windowId, { type: 'action', action: 'inspect', catalogId: 'com.omnios.calc' });
      await hubPcb.executionContext.flushPending();
      assert.equal(os.compositor.getWindow(hubWin0.windowId).surface.uiTree.props.inspectedPackage.appId, 'com.omnios.calc');

      os.compositor.dispatchInput(hubWin0.windowId, { type: 'action', action: 'install', catalogId: 'com.omnios.calc' });
      await hubPcb.executionContext.flushPending();
      assert.ok(os.pkgManager.get('com.omnios.calc'));

      os.compositor.dispatchInput(hubWin0.windowId, { type: 'action', action: 'launch', appId: 'com.omnios.calc' });
      await hubPcb.executionContext.flushPending();
      const hubLaunchedPid = os.compositor.getWindow(hubWin0.windowId).surface.uiTree.props.lastLaunchResult.pid;
      assert.ok(hubLaunchedPid > 1);

      os.compositor.dispatchInput(hubWin0.windowId, { type: 'action', action: 'stop', targetPid: hubLaunchedPid });
      const stoppedCalc = os.processManager.get(hubLaunchedPid);
      assert.ok(stoppedCalc.state === PROCESS_STATES.ZOMBIE || stoppedCalc.state === PROCESS_STATES.TERMINATED);

      // --- 5. Settings & Privacy Center (`com.omnios.settings`) ---
      const settings = await os.launchApp(SYSTEM_APP_IDS.SETTINGS);
      assertSyncStep(settings.pid, 'Settings');
      const setWin0 = os.compositor.getWindow(settings.windowIds[0]);
      os.compositor.dispatchInput(setWin0.windowId, { type: 'action', action: 'set_shell_mode', mode: 'windows' });
      assert.equal(os.compositor.getSnapshot().shellMode, 'windows');
      assert.equal(os.configStore.system.get('system.shellMode'), 'windows');

      const testSysValues = {
        'system.theme': 'light',
        'system.shellMode': 'macos',
        'system.volume': 55,
        'system.brightness': 80,
        'system.wifi': false,
        'system.bluetooth': true,
        'system.dnd': true,
        'system.locale': 'fr-FR',
      };
      assert.equal(Object.keys(testSysValues).length, CANONICAL_SYSTEM_KEYS.length);
      for (const [k, v] of Object.entries(testSysValues)) {
        os.compositor.dispatchInput(setWin0.windowId, { type: 'action', action: 'set_system', key: k, value: v });
        assert.equal(os.configStore.system.get(k), v);
      }

      os.compositor.dispatchInput(setWin0.windowId, {
        type: 'action',
        action: 'set_grant',
        appId: 'com.omnios.calc',
        capability: 'notifications.post',
        state: 'allow',
      });
      assert.equal(os.permissions.getGrant('com.omnios.calc', 'notifications.post').state, 'allow');

      // Resolve a live pending PermissionBroker prompt through Settings & Privacy Center
      const settingsPrompt = os.permissions.checkPermission({
        appId: 'com.omnios.calc',
        pid: 1,
        platform: 'android',
        capability: 'camera.device',
      });
      const pendingPrompts = os.permissions.getPendingPrompts();
      assert.ok(pendingPrompts.length >= 1);
      os.compositor.dispatchInput(setWin0.windowId, {
        type: 'action',
        action: 'resolve_prompt',
        promptId: pendingPrompts[0].promptId,
        decision: 'allow_once',
      });
      assert.equal((await settingsPrompt).granted, true);

      os.compositor.dispatchInput(setWin0.windowId, {
        type: 'action',
        action: 'reg_set',
        hive: 'HKCU',
        keyPath: 'Software\\OmniOS\\SettingsApp',
        valueName: 'DefaultSzKey',
        value: 'WorksWithoutRegType',
      });
      assert.equal(
        os.configStore.registry.getValue('HKCU', 'Software\\OmniOS\\SettingsApp', 'DefaultSzKey').data,
        'WorksWithoutRegType'
      );

      os.compositor.dispatchInput(setWin0.windowId, {
        type: 'action',
        action: 'defaults_set',
        domain: 'com.omnios.settings.test',
        key: 'accent',
        value: 'blue',
      });
      assert.equal(os.configStore.defaults.get('com.omnios.settings.test', 'accent'), 'blue');

      os.compositor.dispatchInput(setWin0.windowId, {
        type: 'action',
        action: 'prefs_set',
        packageName: 'com.omnios.settings.test',
        prefName: 'prefs',
        key: 'enabled',
        value: true,
      });
      assert.equal(os.configStore.sharedPrefs.get('com.omnios.settings.test', 'prefs', 'enabled'), true);

      os.compositor.dispatchInput(setWin0.windowId, { type: 'action', action: 'set_section', section: 'audit' });
      assert.equal(os.compositor.getWindow(setWin0.windowId).surface.uiTree.props.activeSection, 'audit');

      // --- 6. Binary Inspector (`com.omnios.inspector`) ---
      const inspector = await os.launchApp(SYSTEM_APP_IDS.INSPECTOR);
      const inspPcb = assertSyncStep(inspector.pid, 'BinaryInspector');
      const inspWin0 = os.compositor.getWindow(inspector.windowIds[0]);

      const fivePlatformSamples = [
        { path: '/packages/android-calc.apk', platform: 'android' },
        { path: '/packages/win-sysinfo.exe', platform: 'windows' },
        { path: '/packages/ios-weather-island.ipa', platform: 'ios' },
        { path: '/packages/macos-studio.app.zip', platform: 'macos' },
        { path: '/packages/universal-canvas.uapp', platform: 'universal' },
      ];
      for (const sample of fivePlatformSamples) {
        os.compositor.dispatchInput(inspWin0.windowId, {
          type: 'action',
          action: 'inspect_path',
          path: sample.path,
        });
        await inspPcb.executionContext.flushPending();
        const report = os.compositor.getWindow(inspWin0.windowId).surface.uiTree.props.packageReport;
        assert.equal(report.platform, sample.platform, `Inspector must detect ${sample.platform}`);
        assert.ok(Array.isArray(report.sectionsOrClasses));
        assert.ok(Array.isArray(report.importsOrMethods));
        for (const sec of report.sectionsOrClasses) {
          assert.equal(typeof sec.label, 'string', 'Every normalized section must have string label');
        }
      }

      os.compositor.dispatchInput(inspWin0.windowId, {
        type: 'action',
        action: 'inspect_pid',
        targetPid: monitor.pid,
      });
      const procReport = os.compositor.getWindow(inspWin0.windowId).surface.uiTree.props.processReport;
      assert.equal(procReport.pid, monitor.pid);
      assert.ok(procReport.debugState?.registers);
      assert.ok(procReport.vmmStats && typeof procReport.vmmStats.mappedPages === 'number');

      // --- 7. OmniNotes (`com.omnios.notes`) ---
      const notes = await os.launchApp(SYSTEM_APP_IDS.NOTES, { preferSystem: true });
      const notesPcb = assertSyncStep(notes.pid, 'OmniNotes');
      const notesWin0 = os.compositor.getWindow(notes.windowIds[0]);
      os.compositor.dispatchInput(notesWin0.windowId, {
        type: 'action',
        action: 'new_note',
        filename: 'm5-note.txt',
        content: 'Saved by OmniNotes App',
        save: true,
      });
      assert.equal(
        os.vfs.readFile('/home/user/Documents/m5-note.txt', { uid: 1000, gid: 1000, encoding: 'utf8' }),
        'Saved by OmniNotes App'
      );
      os.compositor.dispatchInput(notesWin0.windowId, { type: 'action', action: 'copy' });
      assert.equal(os.clipboard.get('text/plain'), 'Saved by OmniNotes App');

      os.compositor.dispatchInput(notesWin0.windowId, { type: 'action', action: 'share' });
      await notesPcb.executionContext.flushPending();
      const shareRes = os.compositor.getWindow(notesWin0.windowId).surface.uiTree.props.lastShareResult;
      assert.ok(shareRes && (shareRes.status === 'DELIVERED' || shareRes.status === 'CHOOSER_REQUIRED'));

      os.compositor.dispatchInput(notesWin0.windowId, {
        type: 'intent',
        intent: {
          action: 'send',
          mimeType: 'text/plain',
          extras: { title: 'received-intent.txt', text: 'Incoming Cross-Platform Note' },
        },
      });
      assert.equal(
        os.vfs.readFile('/home/user/Documents/received-intent.txt', { uid: 1000, gid: 1000, encoding: 'utf8' }),
        'Incoming Cross-Platform Note'
      );
    } finally {
      await os.shutdown();
    }
  });
});

// ============================================================================
// SUITE 7 — Real Subprocess CLI (`os/cli/omnios-cli.mjs`, `F-065`)
// ============================================================================

describe('Suite 7 (F-065): Real Subprocess OmniOS CLI (Local, --remote, SDK & Error Paths)', () => {
  it('runs local headless CLI commands with persistent --data-dir and --json without hanging', async () => {
    const dataDir = await makeTempDir('omnios-m5-cli-local-');
    const runJson = async (args, opts = {}) => {
      const res = await runCliSubprocess(['--data-dir', dataDir, '--json', ...args], opts);
      assert.equal(res.timedOut, false, `CLI timed out on: ${args.join(' ')}`);
      assert.equal(res.exitCode, 0, `CLI failed (${res.exitCode}) on [${args.join(' ')}]: ${res.stderr}`);
      return JSON.parse(res.stdout);
    };

    try {
      const bootData = await runJson(['boot']);
      assert.equal(bootData.ok, true);
      assert.equal(bootData.status, 'RUNNING');

      const stData = await runJson(['status']);
      assert.equal(stData.state, 'RUNNING');

      const dmData = await runJson(['dmesg', '--limit', '10']);
      assert.ok(Array.isArray(dmData) && dmData.length > 0);

      const svcs = await runJson(['services']);
      assert.equal(svcs.length, 6);

      const execRes = await runJson(['exec', 'echo CLI_LOCAL_OK']);
      assert.equal(execRes.stdout.trim(), 'CLI_LOCAL_OK');

      const repl = await runCliSubprocess(['--data-dir', dataDir, 'shell'], {
        stdin: 'pwd\necho PIPED_LOCAL_REPL\nexit\n',
      });
      assert.equal(repl.timedOut, false);
      assert.equal(repl.exitCode, 0);
      assert.match(repl.stdout, /\/home\/user/);
      assert.match(repl.stdout, /PIPED_LOCAL_REPL/);

      await runJson(['vfs', 'mkdir', '/home/user/clidir', '-r']);
      await runJson(['vfs', 'write', '/home/user/clidir/test.txt', 'Persisted across CLI runs']);
      await runJson(['vfs', 'symlink', '/home/user/clidir/test.txt', '/home/user/clidir/link.txt']);
      const catData = await runJson(['vfs', 'cat', '/home/user/clidir/link.txt']);
      assert.equal(catData.content, 'Persisted across CLI runs');
      const lsData = await runJson(['vfs', 'ls', '/home/user/clidir']);
      assert.ok(lsData.some((e) => e.name === 'test.txt'));
      const resData = await runJson(['vfs', 'resolve', 'C:\\Users\\user\\Documents', '--platform', 'windows']);
      assert.equal(resData.canonicalPath, '/home/user/Documents');
      await runJson(['vfs', 'rm', '/home/user/clidir', '-r']);

      await runJson(['reg', 'set', 'HKCU', 'Software\\OmniOS\\Cli', 'Ver', '2026', '--type', 'REG_DWORD']);
      const regVal = await runJson(['reg', 'get', 'HKCU', 'Software\\OmniOS\\Cli', 'Ver']);
      assert.equal(regVal.data, 2026);
      const regList = await runJson(['reg', 'list', 'HKCU', 'Software\\OmniOS\\Cli']);
      assert.ok(regList.values.Ver);
      await runJson(['reg', 'delete', 'HKCU', 'Software\\OmniOS\\Cli', 'Ver']);

      await runJson(['defaults', 'write', 'com.omnios.cli', 'mode', 'pro']);
      assert.equal(await runJson(['defaults', 'read', 'com.omnios.cli', 'mode']), 'pro');
      const expPlist = await runJson(['defaults', 'export', 'com.omnios.cli']);
      assert.match(expPlist.plist, /<plist/);
      await runJson(['defaults', 'delete', 'com.omnios.cli', 'mode']);

      await runJson(['prefs', 'set', 'com.omnios.cli', 'main', 'count', '9']);
      assert.equal(await runJson(['prefs', 'get', 'com.omnios.cli', 'main', 'count']), 9);
      await runJson(['prefs', 'delete', 'com.omnios.cli', 'main', 'count']);

      const hostApk = path.join(PACKAGES_DIR, 'android-calc.apk');
      const insp = await runJson(['ospm', 'inspect', hostApk]);
      assert.equal(insp.appId, 'com.omnios.calc');
      const inst = await runJson(['ospm', 'install', hostApk, '--grant-all']);
      assert.equal(inst.appId, 'com.omnios.calc');
      const pkgList = await runJson(['ospm', 'list']);
      assert.ok(pkgList.some((p) => p.appId === 'com.omnios.calc'));
      const uninst = await runJson(['ospm', 'uninstall', 'com.omnios.calc', '--purge']);
      assert.equal(uninst.removed, true);

      const clipSetObj = await runJson(['clipboard', 'set', 'CLI Clipboard Sync']);
      assert.equal(clipSetObj.text, 'CLI Clipboard Sync');
      const clipRoundTrip = await runJson(['exec', 'clip set "InProcClip" && clip get']);
      assert.match(clipRoundTrip.stdout, /InProcClip/);

      const notif = await runJson(['notify', 'send', '--title', 'CLI Alert', '--body', 'Hello from CLI']);
      assert.equal(notif.title, 'CLI Alert');
      const notifList = await runJson(['notify', 'list']);
      assert.ok(Array.isArray(notifList));

      const intentCand = await runJson(['intent', 'resolve', '--action', 'send', '--mime', 'text/plain']);
      assert.ok(intentCand.some((c) => c.appId === 'com.omnios.notes'));
    } finally {
      await cleanupTempDir(dataDir);
    }
  });

  it('runs remote CLI (--remote <url>) against live server, sdk build-samples in isolated tmpDir, and structured JSON errors', async () => {
    const tmpOut = await makeTempDir('omnios-m5-sdk-out-');
    const { server, address } = await startOmniOSServer({
      port: 0,
      host: '127.0.0.1',
      autoStartScheduler: false,
    });

    const runRemote = async (args) => {
      const res = await runCliSubprocess(['--remote', address.url, '--json', ...args]);
      assert.equal(res.timedOut, false, `Remote CLI timed out on: ${args.join(' ')}`);
      assert.equal(res.exitCode, 0, `Remote CLI failed (${res.exitCode}) on [${args.join(' ')}]: ${res.stderr}`);
      return JSON.parse(res.stdout);
    };

    try {
      const st = await runRemote(['status']);
      assert.equal(st.state, 'RUNNING');

      const dm = await runRemote(['dmesg', '--limit', '10']);
      assert.ok(Array.isArray(dm) && dm.length > 0);

      const svcs = await runRemote(['services']);
      assert.equal(svcs.length, 6);

      const psList = await runRemote(['ps']);
      assert.ok(psList.some((p) => p.pid === 1));

      const ex = await runRemote(['exec', 'echo CLI_REMOTE_OK']);
      assert.equal(ex.stdout.trim(), 'CLI_REMOTE_OK');

      const replRemote = await runCliSubprocess(['--remote', address.url, 'shell'], {
        stdin: 'echo PIPED_REMOTE_OK\nexit\n',
      });
      assert.equal(replRemote.exitCode, 0);
      assert.match(replRemote.stdout, /PIPED_REMOTE_OK/);

      await runRemote(['vfs', 'write', '/home/user/remote-cli.txt', 'Remote CLI payload']);
      assert.equal((await runRemote(['vfs', 'cat', '/home/user/remote-cli.txt'])).content, 'Remote CLI payload');
      await runRemote(['vfs', 'rm', '/home/user/remote-cli.txt']);

      await runRemote(['reg', 'set', 'HKCU', 'Software\\OmniOS\\Remote', 'Tag', 'ok']);
      assert.equal((await runRemote(['reg', 'get', 'HKCU', 'Software\\OmniOS\\Remote', 'Tag'])).data, 'ok');

      await runRemote(['defaults', 'write', 'com.omnios.remote', 'flag', 'true']);
      assert.equal(await runRemote(['defaults', 'read', 'com.omnios.remote', 'flag']), true);

      await runRemote(['prefs', 'set', 'com.omnios.remote', 'main', 'k', 'v']);
      assert.equal(await runRemote(['prefs', 'get', 'com.omnios.remote', 'main', 'k']), 'v');

      const rInsp = await runRemote(['ospm', 'inspect', '/packages/android-calc.apk']);
      assert.equal(rInsp.appId, 'com.omnios.calc');
      await runRemote(['ospm', 'install', '/packages/android-calc.apk', '--grant-all']);
      const rLaunch = await runRemote(['ospm', 'launch', 'com.omnios.calc']);
      assert.ok(rLaunch.pid > 1);
      assert.ok(rLaunch.windowIds.length >= 1);
      const rStop = await runRemote(['ospm', 'stop', 'com.omnios.calc']);
      assert.ok(rStop.stoppedPids.includes(rLaunch.pid));

      const sysNotes = await runRemote(['ospm', 'launch', 'com.omnios.notes', '--platform', 'system']);
      assert.equal(sysNotes.platform, 'system');
      const kRes = await runRemote(['kill', String(sysNotes.pid), '--signal', 'SIGTERM']);
      assert.equal(kRes.pid, sysNotes.pid);

      await runRemote(['ospm', 'uninstall', 'com.omnios.calc', '--purge']);

      await runRemote(['clipboard', 'set', 'Remote Clip']);
      assert.equal((await runRemote(['clipboard', 'get'])).text, 'Remote Clip');
      const rn = await runRemote(['notify', 'send', '--title', 'RemoteN', '--body', 'Body']);
      assert.equal(rn.title, 'RemoteN');
      await runRemote(['notify', 'dismiss', rn.id]);
      const ri = await runRemote(['intent', 'resolve', '--action', 'send', '--mime', 'text/plain']);
      assert.ok(ri.some((c) => c.appId === 'com.omnios.notes'));

      const sdkRes = await runCliSubprocess(['sdk', 'build-samples', '--out', tmpOut, '--json']);
      assert.equal(sdkRes.timedOut, false);
      assert.equal(sdkRes.exitCode, 0, `sdk build-samples failed: ${sdkRes.stderr}`);
      const sdkManifest = JSON.parse(sdkRes.stdout);
      assert.equal(sdkManifest.packages.length, 7);
      for (const pkg of sdkManifest.packages) {
        const stFile = await fsp.stat(path.join(tmpOut, pkg.filename));
        assert.equal(stFile.size, pkg.bytes);
        assert.equal(pkg.sha256.length, 64);
      }

      const badCmd = await runCliSubprocess(['--json', 'nonexistent-command']);
      assert.notEqual(badCmd.exitCode, 0);
      const badCmdJson = JSON.parse(badCmd.stdout);
      assert.equal(badCmdJson.ok, false);
      assert.ok(typeof badCmdJson.code === 'string' && badCmdJson.code.length > 0);
      assert.ok(badCmdJson.error && typeof badCmdJson.error.message === 'string');

      const badFlag = await runCliSubprocess(['--json', '--bogus-flag', 'status']);
      assert.notEqual(badFlag.exitCode, 0);
      const badFlagJson = JSON.parse(badFlag.stdout);
      assert.equal(badFlagJson.ok, false);
      assert.equal(badFlagJson.code, 'E_CLI_ARGS');

      const killPid1Err = await runCliSubprocess(['--remote', address.url, '--json', 'kill', '1']);
      assert.notEqual(killPid1Err.exitCode, 0);
      const killPid1Json = JSON.parse(killPid1Err.stdout);
      assert.equal(killPid1Json.ok, false);
      assert.equal(killPid1Json.code, 'EPERM');
    } finally {
      await server.stop();
      await cleanupTempDir(tmpOut);
    }
  });
});

// ============================================================================
// SUITE 8 — Iteration 2 Hardening & Remediation Regression Suite (All 19 Fixes)
// ============================================================================

describe('Suite 8 (Iter 2 Hardening): Regression Coverage for All 19 Wave-1 Verifier Fixes', () => {
  it('Group A (Shell): trailing backslash no-hang, double-quoted Windows paths, REG_QWORD/REG_BINARY + unprivileged HKLM virtualization, strict PID, trailing &&/||, dir POSIX path, ospm launch --platform', async () => {
    const os = await bootOmniOS({ autoStartScheduler: false });

    try {
      const sh = os.shell;

      // 1. Trailing unquoted backslash must NOT hang — must return exitCode 2 cleanly
      const t1 = await sh.exec('echo hi\\');
      assert.equal(t1.ok, false);
      assert.equal(t1.exitCode, 2);
      assert.match(t1.stderr, /backslash/i);

      const t2 = await sh.exec('\\');
      assert.equal(t2.ok, false);
      assert.equal(t2.exitCode, 2);

      // Trailing backslash inside unclosed double-quote must return SyntaxError (never hang)
      const t3 = await sh.exec('echo "unclosed\\');
      assert.equal(t3.ok, false);
      assert.equal(t3.exitCode, 2);
      assert.match(t3.stderr, /unterminated/i);

      // Escaped literal backslash at end still succeeds
      const t4 = await sh.exec('echo hi\\\\');
      assert.equal(t4.ok, true);
      assert.equal(t4.stdout.trim(), 'hi\\');

      // 2. Double-quoted Windows paths with \n and \t must stay intact (not turned into LF/TAB)
      os.vfs.writeFile('/home/user/Documents/notes.txt', 'WINDOWS_NOTES_OK', { uid: 1000, gid: 1000 });
      os.vfs.writeFile('/home/user/Documents/test.txt', 'WINDOWS_TEST_OK', { uid: 1000, gid: 1000 });

      const winNotes = await sh.exec('type "C:\\Users\\user\\Documents\\notes.txt"');
      assert.equal(winNotes.exitCode, 0, `stderr=${winNotes.stderr}`);
      assert.equal(winNotes.stdout, 'WINDOWS_NOTES_OK');

      const winTest = await sh.exec('type "C:\\Users\\user\\Documents\\test.txt"');
      assert.equal(winTest.exitCode, 0, `stderr=${winTest.stderr}`);
      assert.equal(winTest.stdout, 'WINDOWS_TEST_OK');

      // Inside double quotes, ", \, $, and ` remain escapable
      const dqEsc = await sh.exec('echo "quote:\\" slash:\\\\ dollar:\\$HOME tick:\\`ok\\`"');
      assert.equal(dqEsc.exitCode, 0);
      assert.equal(dqEsc.stdout.trim(), 'quote:" slash:\\ dollar:$HOME tick:`ok`');

      // 3. reg REG_QWORD (BigInt) & REG_BINARY (Uint8Array) add/query/get without crash
      let r = await sh.exec('reg add HKCU\\Software\\OmniOS\\Types /v BigNum /t REG_QWORD /d 12345678901234567890');
      assert.equal(r.exitCode, 0, r.stderr);
      r = await sh.exec('reg get HKCU\\Software\\OmniOS\\Types BigNum');
      assert.equal(r.exitCode, 0, r.stderr);
      assert.equal(r.stdout.trim(), '12345678901234567890');
      r = await sh.exec('reg query HKCU\\Software\\OmniOS\\Types /v BigNum');
      assert.equal(r.exitCode, 0, r.stderr);
      assert.match(r.stdout, /REG_QWORD/);
      assert.match(r.stdout, /12345678901234567890/);

      r = await sh.exec('reg add HKCU\\Software\\OmniOS\\Types /v HexVal /t REG_QWORD /d 0x10');
      assert.equal(r.exitCode, 0, r.stderr);
      r = await sh.exec('reg get HKCU\\Software\\OmniOS\\Types HexVal');
      assert.equal(r.stdout.trim(), '16');

      r = await sh.exec('reg add HKCU\\Software\\OmniOS\\Types /v Blob /t REG_BINARY /d deadbeef');
      assert.equal(r.exitCode, 0, r.stderr);
      r = await sh.exec('reg get HKCU\\Software\\OmniOS\\Types Blob');
      assert.equal(r.exitCode, 0, r.stderr);
      assert.equal(r.stdout.trim(), 'deadbeef');
      r = await sh.exec('reg query HKCU\\Software\\OmniOS\\Types');
      assert.equal(r.exitCode, 0, r.stderr);
      assert.match(r.stdout, /BigNum\s+REG_QWORD\s+12345678901234567890/);
      assert.match(r.stdout, /Blob\s+REG_BINARY\s+deadbeef/);

      // Invalid REG_BINARY odd hex & invalid REG_QWORD rejected cleanly
      const badBin = await sh.exec('reg add HKCU\\Software\\OmniOS\\Types /v Bad /t REG_BINARY /d abc');
      assert.equal(badBin.exitCode, 1);
      const badQword = await sh.exec('reg add HKCU\\Software\\OmniOS\\Types /v BadQ /t REG_QWORD /d -5');
      assert.equal(badQword.exitCode, 1);

      // 4. Unprivileged shell (uid 1000) HKLM virtualization vs root (uid 0)
      const userWrite = await sh.exec('reg add HKLM\\Software\\OmniOS\\VirtTest /v Secret /d UserVirt', {
        uid: 1000,
      });
      assert.equal(userWrite.exitCode, 0, userWrite.stderr);
      // Real privileged HKLM MUST NOT contain the unprivileged write
      assert.equal(
        os.configStore.registry.getValue('HKLM', 'Software\\OmniOS\\VirtTest', 'Secret', {
          uid: 0,
          privileged: true,
        }),
        null
      );
      // Unprivileged shell CAN read back its own virtualized HKLM value
      const userRead = await sh.exec('reg get HKLM\\Software\\OmniOS\\VirtTest Secret', { uid: 1000 });
      assert.equal(userRead.exitCode, 0, userRead.stderr);
      assert.equal(userRead.stdout.trim(), 'UserVirt');
      // Root shell does NOT see user's virtualized HKLM value, and writes to real HKLM
      const rootMiss = await sh.exec('reg get HKLM\\Software\\OmniOS\\VirtTest Secret', { uid: 0 });
      assert.equal(rootMiss.exitCode, 1);
      const rootWrite = await sh.exec('reg add HKLM\\Software\\OmniOS\\VirtTest /v RealKey /d RootReal', {
        uid: 0,
      });
      assert.equal(rootWrite.exitCode, 0, rootWrite.stderr);
      assert.equal(
        os.configStore.registry.getValue('HKLM', 'Software\\OmniOS\\VirtTest', 'RealKey', {
          uid: 0,
          privileged: true,
        })?.data,
        'RootReal'
      );

      // 5. Strict integer PID parsing in shell kill & taskkill
      const victim = await os.launchApp('com.omnios.terminal');
      const livePid = victim.pid;
      const badKill1 = await sh.exec(`kill ${livePid}abc`);
      assert.equal(badKill1.exitCode, 1);
      assert.match(badKill1.stderr, /invalid pid/i);
      const badKill2 = await sh.exec(`kill ${livePid}.5`);
      assert.equal(badKill2.exitCode, 1);
      const badTk1 = await sh.exec(`taskkill /PID ${livePid}abc`);
      assert.equal(badTk1.exitCode, 1);
      assert.match(badTk1.stderr, /invalid PID/i);
      const badTk2 = await sh.exec('taskkill /PID -1');
      assert.equal(badTk2.exitCode, 1);
      // Victim PID must remain alive & untouched
      const victimPcb = os.processManager.get(livePid);
      assert.notEqual(victimPcb.state, PROCESS_STATES.ZOMBIE);
      assert.notEqual(victimPcb.state, PROCESS_STATES.TERMINATED);
      os.stopApp(livePid);

      // 6a. Trailing && and || must return exitCode 2 SyntaxError
      const trailAnd = await sh.exec('echo hi &&');
      assert.equal(trailAnd.ok, false);
      assert.equal(trailAnd.exitCode, 2);
      const trailOr = await sh.exec('echo hi ||');
      assert.equal(trailOr.ok, false);
      assert.equal(trailOr.exitCode, 2);
      const badSemi = await sh.exec('echo hi && ;');
      assert.equal(badSemi.ok, false);
      assert.equal(badSemi.exitCode, 2);

      // 6b. dir /home/user/Documents lists /home/user/Documents (not .) while /B switch is still skipped
      const dirPosix = await sh.exec('dir /home/user/Documents');
      assert.equal(dirPosix.exitCode, 0, dirPosix.stderr);
      assert.match(dirPosix.stdout, /notes\.txt/);
      assert.match(dirPosix.stdout, /test\.txt/);

      const dirSwitch = await sh.exec('dir /B /home/user/Documents');
      assert.equal(dirSwitch.exitCode, 0, dirSwitch.stderr);
      assert.match(dirSwitch.stdout, /notes\.txt/);

      // 6c. ospm launch --platform system and --prefer-system
      const inst = await sh.exec('ospm install /packages/android-notes-sharer.apk --grant-all');
      assert.equal(inst.exitCode, 0, inst.stderr);

      const launchSys1 = await sh.exec('ospm launch com.omnios.notes --platform system');
      assert.equal(launchSys1.exitCode, 0, launchSys1.stderr);
      assert.match(launchSys1.stdout, /platform=system/);

      const launchSys2 = await sh.exec('ospm launch com.omnios.notes --prefer-system');
      assert.equal(launchSys2.exitCode, 0, launchSys2.stderr);
      assert.match(launchSys2.stdout, /platform=system/);

      os.systemApps.stopAll();
    } finally {
      await os.shutdown();
    }
  });

  it('Group B (System Apps): zero eventBus leaks & ghost VFS reads on close, Settings default system_settings & HKLM virtualization, OmniNotes ACTION_SEND confinement, Monitor/Inspector strict PIDs & service props', async () => {
    const os = await bootOmniOS({ autoStartScheduler: false });

    try {
      // 7. Zero eventBus listener leaks & zero ghost VFS queries on window_close AND menu *.close across ALL 7 system apps
      const baselineListeners = os.eventBus.listenerCount();
      const baselineVfsListeners = os.eventBus.listenerCount('vfs:changed');

      const allApps = [
        { id: SYSTEM_APP_IDS.TERMINAL, closeAction: 'terminal.close' },
        { id: SYSTEM_APP_IDS.FILES, closeAction: 'files.close' },
        { id: SYSTEM_APP_IDS.MONITOR, closeAction: 'monitor.close' },
        { id: SYSTEM_APP_IDS.APPHUB, closeAction: 'apphub.close' },
        { id: SYSTEM_APP_IDS.SETTINGS, closeAction: 'settings.close' },
        { id: SYSTEM_APP_IDS.INSPECTOR, closeAction: 'inspector.close' },
        { id: SYSTEM_APP_IDS.NOTES, closeAction: 'notes.close' },
      ];

      // 7a. Close via compositor.closeWindow (BEFORE stepping scheduler)
      const launched1 = [];
      for (const app of allApps) {
        launched1.push(await os.launchApp(app.id));
      }
      assert.ok(os.eventBus.listenerCount() > baselineListeners);
      for (const item of launched1) {
        os.compositor.closeWindow(item.windowIds[0]);
      }
      assert.equal(
        os.eventBus.listenerCount(),
        baselineListeners,
        'All system app eventBus listeners must unsubscribe immediately on compositor.closeWindow'
      );
      assert.equal(os.eventBus.listenerCount('vfs:changed'), baselineVfsListeners);

      // Verify zero ghost vfs.readdir calls after Files & Notes windows closed
      let ghostReaddirCount = 0;
      const origReaddir = os.vfs.readdir.bind(os.vfs);
      os.vfs.readdir = (...args) => {
        ghostReaddirCount += 1;
        return origReaddir(...args);
      };
      try {
        os.vfs.writeFile('/home/user/Documents/after-close.txt', 'check-no-ghost', { uid: 1000, gid: 1000 });
        assert.equal(ghostReaddirCount, 0, 'Closed OmniFiles/OmniNotes must not trigger ghost vfs.readdir calls');
      } finally {
        os.vfs.readdir = origReaddir;
      }

      // Step scheduler -> closed PCBs cleanly exit
      os.scheduler.step(20);
      for (const item of launched1) {
        const pcb = os.processManager.get(item.pid);
        assert.ok(
          pcb.state === PROCESS_STATES.ZOMBIE || pcb.state === PROCESS_STATES.TERMINATED,
          `Expected exited state for closed system app PID ${item.pid}, got ${pcb.state}`
        );
      }

      // 7b. Close via menu_action `<app>.close` (BEFORE stepping scheduler)
      const launched2 = [];
      for (const app of allApps) {
        const res = await os.launchApp(app.id);
        launched2.push({ ...res, closeAction: app.closeAction });
      }
      for (const item of launched2) {
        os.compositor.dispatchInput(item.windowIds[0], {
          type: 'menu_action',
          actionId: item.closeAction,
        });
      }
      assert.equal(
        os.eventBus.listenerCount(),
        baselineListeners,
        'All system app eventBus listeners must unsubscribe immediately on menu *.close'
      );
      os.scheduler.step(20);

      // 8. Settings default SharedPrefs = 'system_settings' showing all 8 live synced system.* keys + HKLM virtualization
      const settingsLaunch = await os.launchApp(SYSTEM_APP_IDS.SETTINGS, { section: 'prefs' });
      const settingsWin = os.compositor.getWindow(settingsLaunch.windowIds[0]);
      const settingsBody = settingsWin.surface.uiTree.children.find((c) => c.id === 'settings-body');
      assert.equal(settingsBody.props.sharedPrefs.prefName, 'system_settings');
      for (const key of CANONICAL_SYSTEM_KEYS) {
        assert.ok(
          Object.prototype.hasOwnProperty.call(settingsBody.props.sharedPrefs.values, key),
          `Settings sharedPrefs should contain synced key ${key}`
        );
      }
      // Unprivileged Settings (uid 1000) reg_set to HKLM must virtualize
      os.compositor.dispatchInput(settingsLaunch.windowIds[0], {
        type: 'action',
        action: 'reg_set',
        hive: 'HKLM',
        keyPath: 'Software\\OmniOS\\SettingsVirt',
        valueName: 'VirtKey',
        regType: 'REG_SZ',
        data: 'UserOnly',
      });
      assert.equal(
        os.configStore.registry.getValue('HKLM', 'Software\\OmniOS\\SettingsVirt', 'VirtKey', {
          uid: 0,
          privileged: true,
        }),
        null
      );
      const settingsWinAfterReg = os.compositor.getWindow(settingsLaunch.windowIds[0]);
      const settingsRegBody = settingsWinAfterReg.surface.uiTree.children.find((c) => c.id === 'settings-body');
      assert.equal(settingsRegBody.props.registry.values.VirtKey?.data, 'UserOnly');
      os.compositor.closeWindow(settingsLaunch.windowIds[0]);

      // 9. OmniNotes ACTION_SEND confused-deputy confinement strictly inside /home/user/Documents/
      os.vfs.writeFile('/home/user/protected.txt', 'DO_NOT_OVERWRITE', { uid: 1000, gid: 1000 });
      os.vfs.writeFile('/tmp/escape-target.txt', 'SAFE_TMP', { uid: 1000, gid: 1000 });

      const notesLaunch = await os.launchApp(SYSTEM_APP_IDS.NOTES);
      const notesWinId = notesLaunch.windowIds[0];
      const evilTitles = [
        '/home/user/protected.txt',
        'file:///tmp/escape-target.txt',
        '../../protected.txt',
        '../../../',
        '..\\..\\evil.txt',
      ];
      for (const evilTitle of evilTitles) {
        os.compositor.dispatchInput(notesWinId, {
          type: 'intent',
          intent: {
            action: 'android.intent.action.SEND',
            mimeType: 'text/plain',
            extras: { title: evilTitle, text: `payload-for-${evilTitle}` },
          },
        });
        const nw = os.compositor.getWindow(notesWinId);
        const curPath = nw.surface.uiTree.props.currentPath;
        assert.ok(
          curPath.startsWith('/home/user/Documents/') &&
            !curPath.slice('/home/user/Documents/'.length).includes('/') &&
            !curPath.includes('..'),
          `Shared note path escaped NOTES_DIR for "${evilTitle}": got "${curPath}"`
        );
      }
      assert.equal(os.vfs.readFile('/home/user/protected.txt', { encoding: 'utf8', uid: 1000 }), 'DO_NOT_OVERWRITE');
      assert.equal(os.vfs.readFile('/tmp/escape-target.txt', { encoding: 'utf8', uid: 1000 }), 'SAFE_TMP');
      os.compositor.closeWindow(notesWinId);

      // 10. Monitor & Inspector strict PID rejection + Monitor service props (restarts, totalRestarts, healthy, lastHealthOk)
      const targetApp = await os.launchApp(SYSTEM_APP_IDS.TERMINAL);
      const monLaunch = await os.launchApp(SYSTEM_APP_IDS.MONITOR, { tab: 'services' });
      const monWinId = monLaunch.windowIds[0];

      // Services tab row props
      const monWinSvc = os.compositor.getWindow(monWinId);
      const monContent = monWinSvc.surface.uiTree.children.find((c) => c.id === 'monitor-content');
      assert.ok(monContent.children.length >= 6);
      const vfsSvcRow = monContent.children.find((r) => r.id === 'svc-vfsd');
      assert.ok(vfsSvcRow);
      assert.equal(typeof vfsSvcRow.props.restarts, 'number');
      assert.equal(typeof vfsSvcRow.props.totalRestarts, 'number');
      assert.equal(vfsSvcRow.props.healthy, true);
      assert.ok('lastHealthOk' in vfsSvcRow.props);

      // Monitor strict PID validation rejects "<pid>abc"
      os.compositor.dispatchInput(monWinId, {
        type: 'action',
        action: 'select_pid',
        targetPid: `${targetApp.pid}abc`,
      });
      assert.equal(os.compositor.getWindow(monWinId).surface.uiTree.props.selectedPid, null);
      assert.ok(os.compositor.getWindow(monWinId).surface.uiTree.props.lastError);

      os.compositor.dispatchInput(monWinId, {
        type: 'action',
        action: 'kill',
        targetPid: `${targetApp.pid}abc`,
        signal: 'SIGKILL',
      });
      assert.ok(os.compositor.getWindow(monWinId).surface.uiTree.props.lastError);
      const stillAlive = os.processManager.get(targetApp.pid);
      assert.notEqual(stillAlive.state, PROCESS_STATES.ZOMBIE);
      assert.notEqual(stillAlive.state, PROCESS_STATES.TERMINATED);

      // Inspector strict PID validation rejects "<pid>abc"
      const inspLaunch = await os.launchApp(SYSTEM_APP_IDS.INSPECTOR);
      const inspWinId = inspLaunch.windowIds[0];
      os.compositor.dispatchInput(inspWinId, {
        type: 'action',
        action: 'inspect_pid',
        targetPid: `${targetApp.pid}abc`,
      });
      const inspWin = os.compositor.getWindow(inspWinId);
      assert.equal(inspWin.surface.uiTree.props.targetPid, null);
      assert.match(inspWin.surface.uiTree.props.errorMessage ?? '', /targetPid/i);

      os.compositor.closeWindow(monWinId);
      os.compositor.closeWindow(inspWinId);
      os.compositor.closeWindow(targetApp.windowIds[0]);
      os.scheduler.step(20);
    } finally {
      await os.shutdown();
    }
  });

  it('Group C (HTTP, WS & Spotlight): uid/pid null non-coercion, /config/system array & __proto__ rejection, /security/permissions 404, /ws 400 & 426, WS RFC 6455 minimal length 1002, Spotlight unique IDs', async () => {
    const server = createHttpServer({
      host: '127.0.0.1',
      port: 0,
      autoStartScheduler: false,
      seedSamples: true,
    });
    const addr = await server.start();
    const { port, host, url } = addr;

    const api = async (method, p, rawBody = undefined, extraHeaders = {}) => {
      const headers = { ...extraHeaders };
      let body;
      if (rawBody !== undefined) {
        if (typeof rawBody === 'string') {
          headers['Content-Type'] = headers['Content-Type'] ?? 'application/json';
          body = rawBody;
        } else {
          headers['Content-Type'] = 'application/json';
          body = JSON.stringify(rawBody);
        }
      }
      const res = await fetch(`${url}${p}`, { method, headers, body });
      const text = await res.text();
      let data = null;
      try {
        data = JSON.parse(text);
      } catch (_parseErr) {
        data = text;
      }
      return { status: res.status, headers: res.headers, data, text };
    };

    try {
      // 11. HTTP Number(null) === 0 non-coercion on /config/registry and /packages/:appId/{launch,stop}
      const nullUidPut = await api('PUT', '/api/v1/config/registry', {
        hive: 'HKLM',
        keyPath: 'Software\\OmniOS\\NullUidGuard',
        valueName: 'GuardVal',
        type: 'REG_SZ',
        data: 'AnonVirt',
        uid: null,
      });
      assert.equal(nullUidPut.status, 200);
      // Real privileged HKLM (uid 0) MUST NOT see the uid:null write!
      const privGet = await api(
        'GET',
        '/api/v1/config/registry?hive=HKLM&keyPath=Software%5COmniOS%5CNullUidGuard&valueName=GuardVal&uid=0'
      );
      assert.equal(privGet.status, 200);
      assert.equal(privGet.data.value, null);
      // Unprivileged uid:null GET reads back its own virtualized entry
      const nullUidGet = await api(
        'GET',
        '/api/v1/config/registry?hive=HKLM&keyPath=Software%5COmniOS%5CNullUidGuard&valueName=GuardVal&uid=null'
      );
      assert.equal(nullUidGet.status, 200);
      assert.equal(nullUidGet.data.value?.data, 'AnonVirt');

      // Invalid uid values rejected with 400 EINVAL
      for (const badUid of ['', '3abc', -1, 1.5, false]) {
        const badRes = await api('PUT', '/api/v1/config/registry', {
          hive: 'HKCU',
          keyPath: 'Software\\OmniOS\\BadUid',
          valueName: 'K',
          data: 'V',
          uid: badUid,
        });
        assert.equal(badRes.status, 400, `Expected 400 for uid=${JSON.stringify(badUid)}, got ${badRes.status}`);
        assert.equal(badRes.data.code, 'EINVAL');
      }
      const emptyQueryUid = await api('GET', '/api/v1/config/registry?hive=HKCU&uid=');
      assert.equal(emptyQueryUid.status, 400);
      assert.equal(emptyQueryUid.data.code, 'EINVAL');

      // Launch Inspector with pid: null does NOT coerce to PID 0
      const inspLaunchRes = await api('POST', '/api/v1/packages/com.omnios.inspector/launch', {
        pid: null,
      });
      assert.equal(inspLaunchRes.status, 200);
      const inspWin = server.os.compositor.getWindow(inspLaunchRes.data.windowIds[0]);
      assert.equal(inspWin.surface.uiTree.props.mode, 'package');
      assert.equal(inspWin.surface.uiTree.props.targetPid, null);

      // Launch with invalid pid returns 400 EINVAL
      const badLaunchPid = await api('POST', '/api/v1/packages/com.omnios.inspector/launch', {
        pid: '3abc',
      });
      assert.equal(badLaunchPid.status, 400);
      assert.equal(badLaunchPid.data.code, 'EINVAL');

      // Stop with pid: null falls back to stopping appId (NEVER kills PID 0 kernel_idle!)
      const stopNullPid = await api('POST', '/api/v1/packages/com.omnios.inspector/stop', {
        pid: null,
      });
      assert.equal(stopNullPid.status, 200);
      assert.ok(stopNullPid.data.stoppedPids.includes(inspLaunchRes.data.pid));
      const pid0State = server.os.processManager.get(0).state;
      assert.ok(
        pid0State === PROCESS_STATES.READY || pid0State === PROCESS_STATES.RUNNING,
        `PID 0 kernel_idle must stay alive, got ${pid0State}`
      );

      // Stop with invalid pid returns 400 EINVAL
      const stopBadPid = await api('POST', '/api/v1/packages/com.omnios.inspector/stop', {
        pid: '3abc',
      });
      assert.equal(stopBadPid.status, 400);
      assert.equal(stopBadPid.data.code, 'EINVAL');

      // 12. /api/v1/config/system rejects Array values/updates and prototype keys (__proto__, constructor, prototype)
      const sysArr = await api('PUT', '/api/v1/config/system', { values: ['dark'] });
      assert.equal(sysArr.status, 400);
      assert.equal(sysArr.data.code, 'EINVAL');

      const sysPrim = await api('PUT', '/api/v1/config/system', { values: 'dark' });
      assert.equal(sysPrim.status, 400);
      assert.equal(sysPrim.data.code, 'EINVAL');

      const sysUpdArr = await api('PUT', '/api/v1/config/system', { updates: ['dark'] });
      assert.equal(sysUpdArr.status, 400);

      const sysProtoRaw = await api('PUT', '/api/v1/config/system', '{"__proto__":{"polluted":true}}');
      assert.equal(sysProtoRaw.status, 400);
      assert.equal(sysProtoRaw.data.code, 'EINVAL');
      assert.equal(({}).polluted, undefined);

      const sysProtoNested = await api(
        'PUT',
        '/api/v1/config/system',
        '{"values":{"__proto__":{"polluted":true}}}'
      );
      assert.equal(sysProtoNested.status, 400);
      assert.equal(sysProtoNested.data.code, 'EINVAL');
      assert.equal(({}).polluted, undefined);

      const sysCtorKey = await api('PUT', '/api/v1/config/system', { key: 'constructor', value: 'bad' });
      assert.equal(sysCtorKey.status, 400);
      assert.equal(sysCtorKey.data.code, 'EINVAL');

      const sysPrototypeKey = await api('PUT', '/api/v1/config/system', { key: 'prototype', value: 'bad' });
      assert.equal(sysPrototypeKey.status, 400);
      assert.equal(sysPrototypeKey.data.code, 'EINVAL');

      // 13. /api/v1/security/permissions unknown promptId -> 404 ENOENT
      const unknownPrompt = await api('POST', '/api/v1/security/permissions', {
        promptId: 'prompt-does-not-exist-999',
        decision: 'allow',
      });
      assert.equal(unknownPrompt.status, 404);
      assert.equal(unknownPrompt.data.ok, false);
      assert.equal(unknownPrompt.data.code, 'ENOENT');
      assert.equal(unknownPrompt.data.error.code, 'ENOENT');

      // 14. Non-upgrade HTTP requests to /ws -> 426 Upgrade Required & malformed Upgrade without Connection -> 400
      const wsPlain = await api('GET', '/ws');
      assert.equal(wsPlain.status, 426);
      assert.equal(wsPlain.headers.get('upgrade'), 'websocket');
      assert.equal(wsPlain.headers.get('connection'), 'Upgrade');
      assert.equal(wsPlain.data.ok, false);
      assert.equal(wsPlain.data.code, 'EINVAL');
      assert.match(wsPlain.data.error.message, /upgrade required/i);

      const wsBadUpgrade = await rawTcpHttpRequest(
        host,
        port,
        `GET /ws HTTP/1.1\r\nHost: ${host}:${port}\r\nUpgrade: websocket\r\nConnection: close\r\n\r\n`
      );
      assert.equal(wsBadUpgrade.status, 400);
      const wsBadJson = JSON.parse(wsBadUpgrade.body);
      assert.equal(wsBadJson.ok, false);
      assert.equal(wsBadJson.code, 'EINVAL');

      // 15. RFC 6455 §5.2 minimal payload length encoding enforcement (-> Close 1002)
      // 15a. Non-minimal 16-bit length (len7=126 with payloadLen=10 < 126)
      const ws16 = new RawWsClient();
      try {
        const hs = await ws16.connect(host, port);
        assert.equal(hs.status, 101);
        await ws16.waitForEnvelope('compositor:snapshot');
        const mask = Buffer.from([0x11, 0x22, 0x33, 0x44]);
        const rawPayload = Buffer.from('0123456789');
        const maskedPayload = Buffer.alloc(10);
        for (let i = 0; i < 10; i += 1) maskedPayload[i] = rawPayload[i] ^ mask[i & 3];
        const bad16 = Buffer.concat([Buffer.from([0x81, 0x80 | 126, 0x00, 10]), mask, maskedPayload]);
        ws16.sendRaw(bad16);
        const close16 = await ws16.waitForClose();
        assert.equal(close16.closeCode, WS_CLOSE_CODES.PROTOCOL_ERROR);
      } finally {
        ws16.close();
      }

      // 15b. Non-minimal 64-bit length (len7=127 with bigLen=100 <= 0xffff)
      const ws64 = new RawWsClient();
      try {
        const hs = await ws64.connect(host, port);
        assert.equal(hs.status, 101);
        await ws64.waitForEnvelope('compositor:snapshot');
        const hdr64 = Buffer.alloc(10);
        hdr64[0] = 0x81;
        hdr64[1] = 0x80 | 127;
        hdr64.writeBigUInt64BE(100n, 2);
        const mask = Buffer.from([0xaa, 0xbb, 0xcc, 0xdd]);
        const maskedPayload = Buffer.alloc(100, 0x41);
        ws64.sendRaw(Buffer.concat([hdr64, mask, maskedPayload]));
        const close64 = await ws64.waitForClose();
        assert.equal(close64.closeCode, WS_CLOSE_CODES.PROTOCOL_ERROR);
      } finally {
        ws64.close();
      }

      // 16. Spotlight unique IDs when com.omnios.notes Android APK coexists with built-in OmniNotes
      const installNotes = await api('POST', '/api/v1/packages/install', {
        path: '/packages/android-notes-sharer.apk',
        grantAll: true,
      });
      assert.equal(installNotes.status, 201);

      const searchRes = await api('GET', '/api/v1/search?q=notes');
      assert.equal(searchRes.status, 200);
      const ids = searchRes.data.results.map((item) => item.id);
      assert.equal(new Set(ids).size, ids.length, `Duplicate Spotlight IDs detected: ${JSON.stringify(ids)}`);
      assert.ok(ids.includes('app:com.omnios.notes'), 'Expected installed Android app:com.omnios.notes');
      assert.ok(ids.includes('system:com.omnios.notes'), 'Expected built-in system:com.omnios.notes');
    } finally {
      await server.stop();
    }
  });

  it('Group D (CLI): clipboard set --mime & history (local + remote), shell --cwd + cd persistence, REPL --json errors, and --json=true parse errors', async () => {
    const server = createHttpServer({
      host: '127.0.0.1',
      port: 0,
      autoStartScheduler: false,
      seedSamples: false,
    });
    const addr = await server.start();

    try {
      // 17a. Local CLI clipboard set --mime text/html & application/json
      const localHtmlSet = await runCliSubprocess([
        '--json',
        'clipboard',
        'set',
        '<b>hi</b>',
        '--mime',
        'text/html',
      ]);
      assert.equal(localHtmlSet.exitCode, 0, localHtmlSet.stderr);
      const localHtmlData = JSON.parse(localHtmlSet.stdout);
      assert.equal(localHtmlData.mime, 'text/html');
      assert.equal(localHtmlData.html, '<b>hi</b>');
      assert.equal(localHtmlData.formats['text/html'], '<b>hi</b>');

      const localJsonSet = await runCliSubprocess([
        '--json',
        'clipboard',
        'set',
        '{"answer":42}',
        '--mime',
        'application/json',
      ]);
      assert.equal(localJsonSet.exitCode, 0, localJsonSet.stderr);
      const localJsonData = JSON.parse(localJsonSet.stdout);
      assert.equal(localJsonData.mime, 'application/json');
      assert.equal(localJsonData.formats['application/json'], '{"answer":42}');

      const localBadJson = await runCliSubprocess([
        '--json',
        'clipboard',
        'set',
        '{not-json',
        '--mime',
        'application/json',
      ]);
      assert.notEqual(localBadJson.exitCode, 0);
      assert.equal(JSON.parse(localBadJson.stdout).code, 'EINVAL');

      // 17b. Remote CLI clipboard set --mime text/html -> get --mime text/html -> history
      const remHtmlSet = await runCliSubprocess([
        '--remote',
        addr.url,
        'clipboard',
        'set',
        '<b>hi</b>',
        '--mime',
        'text/html',
      ]);
      assert.equal(remHtmlSet.exitCode, 0, remHtmlSet.stderr);

      const remHtmlGet = await runCliSubprocess([
        '--remote',
        addr.url,
        '--json',
        'clipboard',
        'get',
        '--mime',
        'text/html',
      ]);
      assert.equal(remHtmlGet.exitCode, 0, remHtmlGet.stderr);
      assert.equal(JSON.parse(remHtmlGet.stdout), '<b>hi</b>');

      const remHistory = await runCliSubprocess([
        '--remote',
        addr.url,
        'clipboard',
        'history',
      ]);
      assert.equal(remHistory.exitCode, 0, remHistory.stderr);
      assert.match(remHistory.stdout, /text\/html/);
      assert.match(remHistory.stdout, /<b>hi<\/b>/);

      // 18a. Local CLI shell --cwd + cd persistence across REPL lines
      const localReplCwd = await runCliSubprocess(['shell', '--cwd', '/home/user/Documents'], {
        stdin: 'pwd\ncd /tmp\npwd\nexit\n',
      });
      assert.equal(localReplCwd.exitCode, 0, localReplCwd.stderr);
      const localLines = localReplCwd.stdout
        .trim()
        .split('\n')
        .map((l) => l.trim())
        .filter(Boolean);
      assert.deepEqual(localLines, ['/home/user/Documents', '/tmp']);

      // 18b. Remote CLI shell --cwd + cd persistence across REPL lines
      const remoteReplCwd = await runCliSubprocess(
        ['--remote', addr.url, 'shell', '--cwd', '/home/user/Documents'],
        { stdin: 'pwd\ncd /tmp\npwd\nexit\n' }
      );
      assert.equal(remoteReplCwd.exitCode, 0, remoteReplCwd.stderr);
      const remoteLines = remoteReplCwd.stdout
        .trim()
        .split('\n')
        .map((l) => l.trim())
        .filter(Boolean);
      assert.deepEqual(remoteLines, ['/home/user/Documents', '/tmp']);

      // 19a. REPL --remote <unreachable> --json emits structured JSON error envelope on stdout
      const replErrJson = await runCliSubprocess(
        ['--remote', 'http://127.0.0.1:1', '--json', 'shell'],
        { stdin: 'pwd\nexit\n' }
      );
      assert.notEqual(replErrJson.exitCode, 0);
      const replErrParsed = JSON.parse(replErrJson.stdout.trim());
      assert.equal(replErrParsed.ok, false);
      assert.ok(typeof replErrParsed.code === 'string' && replErrParsed.code.length > 0);
      assert.ok(replErrParsed.error && typeof replErrParsed.error.message === 'string');

      // 19b. --json=true / --json=1 / --json=yes with unknown flag emit JSON envelope on stdout; --json=false suppresses it
      for (const flagForm of ['--json=true', '--json=1', '--json=yes']) {
        const res = await runCliSubprocess([flagForm, '--bogus-unknown-flag']);
        assert.notEqual(res.exitCode, 0);
        const parsed = JSON.parse(res.stdout);
        assert.equal(parsed.ok, false);
        assert.equal(parsed.code, 'E_CLI_ARGS');
        assert.equal(parsed.error.code, 'E_CLI_ARGS');
      }

      const jsonDisabled = await runCliSubprocess(['--json=true', '--json=false', '--bogus-unknown-flag']);
      assert.notEqual(jsonDisabled.exitCode, 0);
      assert.equal(jsonDisabled.stdout.trim(), '');
    } finally {
      await server.stop();
    }
  });
});

