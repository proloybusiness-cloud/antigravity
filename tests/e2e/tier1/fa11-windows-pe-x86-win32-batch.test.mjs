/**
 * OmniOS Tier 1 E2E Suite — FA-11: Windows Runtime
 * Covers PROJECT.md Features: F-041, F-042, F-043, F-044, F-045, F-047.
 *
 * STRICT INVARIANTS:
 * - Opaque-box only: imports ONLY Node 24 built-ins and ../lib/*.mjs.
 * - Zero skips, zero stubs, zero hardcoded app outputs (runtime nonces & operands).
 * - Clean try/finally teardown on every test.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import {
  REPO_ROOT,
  loadPublicOmniOS,
  startOmniServer,
} from '../lib/env.mjs';
import {
  buildCustomPe64Exe,
  buildCustomPe32Exe,
  buildCustomMsix,
  buildCustomMsi,
  buildBatScript,
  buildCmdScript,
} from '../lib/fixtures-android-win.mjs';

function makeNonce() {
  return crypto.randomBytes(4).toString('hex');
}

function makeOperands() {
  const b = crypto.randomBytes(2);
  const a = 19 + (b[0] % 55);
  const c = 23 + (b[1] % 55);
  return [a, c];
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function readNonEmptyFile(filePath, retries = 2) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    const buf = await fs.readFile(filePath);
    if (buf.length > 0) return buf;
    if (attempt < retries) await sleep(60);
  }
  const finalBuf = await fs.readFile(filePath);
  assert.ok(finalBuf.length > 0, `Expected non-empty package file at ${filePath}`);
  return finalBuf;
}

function extractStdout(pcb, summary) {
  const raw = summary?.stdout ?? pcb?.streams?.stdout ?? pcb?.stdout ?? '';
  if (typeof raw === 'string') return raw;
  if (Buffer.isBuffer(raw) || raw instanceof Uint8Array) return Buffer.from(raw).toString('utf8');
  if (Array.isArray(raw)) {
    return raw
      .map((chunk) => (Buffer.isBuffer(chunk) || chunk instanceof Uint8Array
        ? Buffer.from(chunk).toString('utf8')
        : String(chunk ?? '')))
      .join('');
  }
  return String(raw ?? '');
}

function extractExitCode(pcb, summary) {
  const code = summary?.exitCode ?? pcb?.stats?.exitCode ?? pcb?.exitCode;
  return code === undefined || code === null ? null : Number(code);
}

function extractInstructions(pcb, summary) {
  return Number(
    summary?.instructionsExecuted ??
    pcb?.stats?.instructionsExecuted ??
    pcb?.instructionsExecuted ??
    0
  );
}

async function runToCompletion(osHandle, pid, maxTicks = 2000) {
  const scheduler = osHandle.require('scheduler');
  const pm = osHandle.require('processManager');
  let summary = null;
  if (typeof scheduler.runUntilIdle === 'function') {
    summary = await scheduler.runUntilIdle(pid, maxTicks);
  } else {
    for (let i = 0; i < Math.ceil(maxTicks / 50); i++) {
      await scheduler.step(50);
      const cur = pm.get(pid);
      if (!cur || cur.state === 'TERMINATED' || cur.state === 'ZOMBIE') break;
    }
  }
  const pcb = pm.get(pid);
  return {
    pcb,
    summary,
    stdout: extractStdout(pcb, summary),
    exitCode: extractExitCode(pcb, summary),
    instructionsExecuted: extractInstructions(pcb, summary),
  };
}

function grantWinUserCaps(osHandle, appId) {
  const security = osHandle.require('security');
  for (const cap of ['fs.read.user', 'fs.write.user', 'clipboard.read', 'clipboard.write', 'notifications.post', 'ui.window', 'ipc.broadcast']) {
    security.setGrant(appId, cap, 'allow');
  }
}

async function installPackageHttp(api, bytes, filename) {
  let res = await api.post('/api/v1/packages/install', bytes, {
    query: { filename, grantAll: 'true' },
    headers: {
      'content-type': 'application/octet-stream',
      'x-filename': filename,
    },
  });
  if (res.status === 400 || res.status === 415 || res.status === 422) {
    const b64 = Buffer.from(bytes).toString('base64');
    res = await api.post('/api/v1/packages/install', {
      base64: b64,
      data: b64,
      filename,
      grantAll: true,
    });
  }
  assert.ok(res.ok, `Expected HTTP 2xx installing ${filename}, got ${res.status}: ${res.text}`);
  return res.json;
}

describe('Tier 1 — FA-11: Windows Runtime (PE32/PE32+, MSIX/MSI, x86/x86-64, Win32 & Batch)', () => {
  it('T1-FA11-01 [F-041/F-043]: PE32+ (x86-64) loader (sections, IAT, DIR64 relocs) & dynamic runtime-nonce computeExitSum + stdout execution', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const formatDetector = osHandle.require('formatDetector');
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');

      const nonce = makeNonce();
      const [a, b] = makeOperands();
      const expectedSum = a + b;
      const msg = `WIN64_OUT_${nonce}\n`;
      const exeBuf = buildCustomPe64Exe({
        subsystem: 3,
        message: msg,
        computeExitSum: [a, b],
        includeReloc: true,
      });

      const det = formatDetector.detect(exeBuf, `dyn64-${nonce}.exe`);
      assert.equal(det.format, 'windows-pe');
      assert.equal(det.platform, 'windows');

      const vfsPath = `/tmp/dyn64-${nonce}.exe`;
      await vfs.writeFile(vfsPath, exeBuf);

      const insp = await pkgManager.inspect(vfsPath);
      const inspJson = JSON.stringify(insp);
      assert.equal(insp.platform, 'windows');
      assert.ok(
        /64|x86_64|amd64/i.test(String(insp.arch ?? inspJson)),
        `Expected 64-bit arch in PE32+ inspection, got: ${inspJson}`
      );
      assert.ok(
        /kernel32\.dll/i.test(inspJson) && inspJson.includes('.text') && inspJson.includes('.rdata'),
        `Expected PE32+ inspection to include KERNEL32.dll, .text & .rdata, got: ${inspJson}`
      );

      const rec = await pkgManager.install(vfsPath, { grantAll: true });
      const appId = rec.appId ?? insp.appId;
      assert.ok(appId, 'Expected non-empty appId for installed PE32+ exe');

      const launched = await pkgManager.launch(appId);
      assert.ok(launched.pid > 1, 'Expected valid PID > 1');
      const run = await runToCompletion(osHandle, launched.pid);

      assert.ok(
        run.stdout.includes(`WIN64_OUT_${nonce}`),
        `Expected stdout to include WIN64_OUT_${nonce}, got: ${JSON.stringify(run.stdout)}`
      );
      assert.equal(run.exitCode, expectedSum, `Expected computed exitCode ${a}+${b}=${expectedSum}, got ${run.exitCode}`);
      assert.ok(run.instructionsExecuted > 0, 'Expected x86-64 emulator instructionsExecuted > 0');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T1-FA11-02 [F-041/F-043]: PE32 (32-bit x86, 0x010B, __stdcall, HIGHLOW relocs) inspection & live execution', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const formatDetector = osHandle.require('formatDetector');
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');

      const nonce = makeNonce();
      const expectedCode = 21 + (crypto.randomBytes(1)[0] % 90);
      const exe32 = buildCustomPe32Exe({
        subsystem: 3,
        message: `WIN32_X86_${nonce}\n`,
        exitCode: expectedCode,
        includeReloc: true,
      });

      const det = formatDetector.detect(exe32, `dyn32-${nonce}.exe`);
      assert.equal(det.format, 'windows-pe');
      assert.equal(det.platform, 'windows');

      const vfsPath = `/tmp/dyn32-${nonce}.exe`;
      await vfs.writeFile(vfsPath, exe32);

      const insp = await pkgManager.inspect(vfsPath);
      const inspJson = JSON.stringify(insp);
      assert.equal(insp.platform, 'windows');
      assert.ok(
        /x86|i386|32|pe32/i.test(String(insp.arch ?? inspJson)),
        `Expected 32-bit x86 / PE32 metadata in inspection, got: ${inspJson}`
      );

      const rec = await pkgManager.install(vfsPath, { grantAll: true });
      const appId = rec.appId ?? insp.appId;
      const launched = await pkgManager.launch(appId);
      const run = await runToCompletion(osHandle, launched.pid);

      assert.ok(
        run.stdout.includes(`WIN32_X86_${nonce}`),
        `Expected PE32 stdout to include WIN32_X86_${nonce}, got: ${JSON.stringify(run.stdout)}`
      );
      assert.equal(run.exitCode, expectedCode, `Expected PE32 exitCode ${expectedCode}, got ${run.exitCode}`);
      assert.ok(run.instructionsExecuted > 0, 'Expected x86 emulator instructionsExecuted > 0');
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T1-FA11-03 [F-044]: Win32 kernel32 file write (C:\\Users\\user\\Documents\\) & advapi32 HKCU Registry write', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');
      const configStore = osHandle.require('configStore');

      const nonce = makeNonce();
      const winPath = `C:\\Users\\user\\Documents\\win-doc-${nonce}.txt`;
      const fileContent = `FILE_TOKEN_${nonce}`;
      const subKey = `Software\\OmniTest\\Run_${nonce}`;
      const valName = `Key_${nonce}`;
      const valData = `REG_TOKEN_${nonce}`;

      const exeBuf = buildCustomPe64Exe({
        subsystem: 3,
        writeFilePath: winPath,
        writeFileContent: fileContent,
        regHive: 0x80000001, // HKEY_CURRENT_USER
        regSubKey: subKey,
        regValueName: valName,
        regValueData: valData,
        exitCode: 0,
      });

      const vfsPath = `/tmp/win32-io-${nonce}.exe`;
      await vfs.writeFile(vfsPath, exeBuf);
      const rec = await pkgManager.install(vfsPath, { grantAll: true });
      const appId = rec.appId;
      grantWinUserCaps(osHandle, appId);

      const launched = await pkgManager.launch(appId);
      const run = await runToCompletion(osHandle, launched.pid);
      assert.equal(run.exitCode, 0, `Expected exitCode 0 from Win32 I/O exe, got ${run.exitCode}`);

      const readBack = String(await vfs.readFile(`/home/user/Documents/win-doc-${nonce}.txt`, { encoding: 'utf8' }));
      assert.equal(readBack, fileContent, 'Expected C:\\Users\\user\\Documents\\ write to land in canonical /home/user/Documents/');

      const regVal = configStore.registry.getValue('HKCU', subKey, valName);
      assert.ok(regVal !== null && regVal !== undefined, `Expected HKCU\\${subKey}\\${valName} to be written by RegSetValueExA`);
      const regType = regVal?.type;
      assert.ok(
        regType === undefined || regType === 'REG_SZ' || regType === 1,
        `Expected REG_SZ type, got ${regType}`
      );
      const normalized = String(regVal?.data ?? regVal ?? '').replace(/\0+$/, '');
      assert.equal(normalized, valData, `Expected Registry value "${valData}", got "${normalized}"`);
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T1-FA11-04 [F-044]: Win32 user32 CreateWindowExA + ShowWindow real Compositor window creation', async () => {
    let srv = null;
    let ws = null;
    try {
      srv = await startOmniServer();
      ws = await srv.connectWs();

      const nonce = makeNonce();
      const title = `Win32Wnd_${nonce}`;
      const guiExe = buildCustomPe64Exe({
        subsystem: 2, // IMAGE_SUBSYSTEM_WINDOWS_GUI
        windowTitle: title,
        message: `GUI_${nonce}\n`,
        exitCode: 0,
      });

      const installed = await installPackageHttp(srv.api, guiExe, `gui-${nonce}.exe`);
      const appId = installed?.appId ?? installed?.package?.appId ?? installed?.id;
      assert.ok(appId, `Expected appId from package install, got: ${JSON.stringify(installed)}`);

      // Wait for initial WS snapshot before marking cursor
      await ws.waitForType('compositor:snapshot', { timeoutMs: 5000 }).catch(() => {});
      const cursor = ws.mark();

      const launchRes = await srv.api.post(
        `/api/v1/packages/${encodeURIComponent(appId)}/launch`,
        {},
        { expectOk: true }
      );
      assert.ok((launchRes.json?.pid ?? launchRes.json?.process?.pid) > 1);

      const createdEv = await ws.waitForMessage(
        (m) => m?.type === 'compositor:window_created' && JSON.stringify(m.payload ?? {}).includes(title),
        { since: cursor, timeoutMs: 8000 }
      );
      const winPayload = createdEv.payload?.window ?? createdEv.payload;
      assert.ok(
        String(winPayload?.title ?? JSON.stringify(winPayload)).includes(title),
        `Expected window title "${title}", got: ${JSON.stringify(winPayload)}`
      );
      assert.equal(winPayload?.platform, 'windows');
    } finally {
      if (ws) await ws.close().catch(() => {});
      if (srv) await srv.stop().catch(() => {});
    }
  });

  it('T1-FA11-05 [F-042]: Windows .msix (AppxManifest.xml + AppxBlockMap.xml + embedded PE64) launch & .msi OLE CFBF inspection', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const formatDetector = osHandle.require('formatDetector');
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');

      const nonce = makeNonce();
      const [a, b] = makeOperands();
      const expectedSum = a + b;

      const msixBuf = buildCustomMsix({
        identityName: `OmniOS.Msix_${nonce}`,
        displayName: `MsixApp ${nonce}`,
        executable: 'app.exe',
        exeOptions: {
          subsystem: 3,
          message: `MSIX_OUT_${nonce}\n`,
          computeExitSum: [a, b],
        },
      });

      const msixDet = formatDetector.detect(msixBuf, `pkg-${nonce}.msix`);
      assert.equal(msixDet.format, 'windows-msix');
      assert.equal(msixDet.platform, 'windows');

      const msixVfs = `/tmp/pkg-${nonce}.msix`;
      await vfs.writeFile(msixVfs, msixBuf);
      const msixInsp = await pkgManager.inspect(msixVfs);
      assert.ok(
        JSON.stringify(msixInsp).includes(nonce),
        `Expected MSIX AppxManifest metadata containing ${nonce}, got: ${JSON.stringify(msixInsp)}`
      );

      const msixRec = await pkgManager.install(msixVfs, { grantAll: true });
      const msixAppId = msixRec.appId ?? msixInsp.appId;
      const launched = await pkgManager.launch(msixAppId);
      const run = await runToCompletion(osHandle, launched.pid);
      assert.ok(
        run.stdout.includes(`MSIX_OUT_${nonce}`),
        `Expected MSIX stdout to include MSIX_OUT_${nonce}, got: ${JSON.stringify(run.stdout)}`
      );
      assert.equal(run.exitCode, expectedSum, `Expected MSIX computed exitCode ${expectedSum}, got ${run.exitCode}`);

      // .msi OLE CFBF inspection
      const msiBuf = buildCustomMsi({
        productName: `OmniMsi_${nonce}`,
        productVersion: '2.4.1',
        manufacturer: 'OmniTestCorp',
      });
      const msiDet = formatDetector.detect(msiBuf, `setup-${nonce}.msi`);
      assert.equal(msiDet.format, 'windows-msi');
      assert.equal(msiDet.platform, 'windows');

      const msiVfs = `/tmp/setup-${nonce}.msi`;
      await vfs.writeFile(msiVfs, msiBuf);
      const msiInsp = await pkgManager.inspect(msiVfs);
      const msiJson = JSON.stringify(msiInsp);
      assert.equal(msiInsp.platform, 'windows');
      assert.ok(
        msiJson.includes(`OmniMsi_${nonce}`) ||
        msiJson.includes('SummaryInformation') ||
        msiJson.includes('MsiMetadata'),
        `Expected MSI OLE CFBF inspection metadata, got: ${msiJson}`
      );
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T1-FA11-06 [F-045]: Windows .bat & .cmd script execution (SET /A, ECHO, file redirection >, EXIT /B)', async () => {
    let osHandle = null;
    try {
      osHandle = await loadPublicOmniOS();
      const formatDetector = osHandle.require('formatDetector');
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');

      const nonce = makeNonce();
      const [a, b] = makeOperands();
      const expectedCode = 11 + (crypto.randomBytes(1)[0] % 40);

      const batText = buildBatScript({
        vars: { TAG: `BAT_${nonce}` },
        computeA: a,
        computeB: b,
        computeVar: 'TOTAL',
        echoMessage: 'MSG_%TAG%',
        outputFile: `C:\\Users\\user\\Documents\\bat-${nonce}.txt`,
        outputContent: `BAT_FILE_${nonce}`,
        exitCode: expectedCode,
      });
      const batBuf = Buffer.from(batText, 'utf8');

      const det = formatDetector.detect(batBuf, `run-${nonce}.bat`);
      assert.equal(det.format, 'windows-bat');
      assert.equal(det.platform, 'windows');

      const batVfs = `/tmp/run-${nonce}.bat`;
      await vfs.writeFile(batVfs, batBuf);
      const batRec = await pkgManager.install(batVfs, { grantAll: true });
      grantWinUserCaps(osHandle, batRec.appId);

      const batLaunched = await pkgManager.launch(batRec.appId);
      const batRun = await runToCompletion(osHandle, batLaunched.pid);
      assert.ok(
        batRun.stdout.includes(`TOTAL=${a + b}`),
        `Expected .bat stdout to include TOTAL=${a + b}, got: ${JSON.stringify(batRun.stdout)}`
      );
      assert.ok(
        batRun.stdout.includes(`MSG_BAT_${nonce}`),
        `Expected .bat stdout to expand %TAG% -> MSG_BAT_${nonce}, got: ${JSON.stringify(batRun.stdout)}`
      );
      assert.equal(batRun.exitCode, expectedCode, `Expected .bat exitCode ${expectedCode}, got ${batRun.exitCode}`);

      const redirected = String(await vfs.readFile(`/home/user/Documents/bat-${nonce}.txt`, { encoding: 'utf8' })).trim();
      assert.equal(redirected, `BAT_FILE_${nonce}`, 'Expected .bat redirection to write to canonical /home/user/Documents/');

      // Also verify .cmd script execution
      const cmdText = buildCmdScript({
        computeA: a + 1,
        computeB: b,
        computeVar: 'CSUM',
        exitCode: 0,
      });
      const cmdVfs = `/tmp/run-${nonce}.cmd`;
      await vfs.writeFile(cmdVfs, Buffer.from(cmdText, 'utf8'));
      const cmdRec = await pkgManager.install(cmdVfs, { grantAll: true });
      const cmdLaunched = await pkgManager.launch(cmdRec.appId);
      const cmdRun = await runToCompletion(osHandle, cmdLaunched.pid);
      assert.ok(
        cmdRun.stdout.includes(`CSUM=${a + 1 + b}`),
        `Expected .cmd stdout to include CSUM=${a + 1 + b}, got: ${JSON.stringify(cmdRun.stdout)}`
      );
      assert.equal(cmdRun.exitCode, 0);
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });

  it('T1-FA11-07 [F-047]: SDK sample EXEs packages/win-sysinfo.exe & packages/win-notepad.exe inspect and run cleanly', async () => {
    let osHandle = null;
    try {
      // Boot public OS FIRST so absent os/os.mjs fails loudly with E_OMNIOS_NOT_IMPLEMENTED
      osHandle = await loadPublicOmniOS();
      const formatDetector = osHandle.require('formatDetector');
      const vfs = osHandle.require('vfs');
      const pkgManager = osHandle.require('pkgManager');
      const compositor = osHandle.require('compositor');

      for (const sampleName of ['win-sysinfo.exe', 'win-notepad.exe']) {
        const buf = await readNonEmptyFile(path.join(REPO_ROOT, 'packages', sampleName));
        assert.equal(buf[0], 0x4d, `Expected MZ byte 0 in ${sampleName}`);
        assert.equal(buf[1], 0x5a, `Expected MZ byte 1 in ${sampleName}`);

        const det = formatDetector.detect(buf, sampleName);
        assert.equal(det.format, 'windows-pe');
        assert.equal(det.platform, 'windows');

        const vfsPath = `/tmp/${sampleName}`;
        await vfs.writeFile(vfsPath, buf);
        const insp = await pkgManager.inspect(vfsPath);
        assert.equal(insp.platform, 'windows');

        const rec = await pkgManager.install(vfsPath, { grantAll: true });
        const appId = rec.appId ?? insp.appId;
        grantWinUserCaps(osHandle, appId);

        const launched = await pkgManager.launch(appId);
        assert.ok(launched.pid > 1, `Expected valid PID > 1 launching ${sampleName}`);
        const run = await runToCompletion(osHandle, launched.pid, 400);

        assert.ok(run.instructionsExecuted > 0, `Expected ${sampleName} to execute > 0 x86-64 instructions`);
        const sig = run.pcb?.exitSignal ?? run.pcb?.signal ?? run.summary?.signal ?? null;
        assert.ok(sig !== 'SIGSEGV' && sig !== 'SIGILL', `${sampleName} faulted with signal ${sig}`);

        const wins = compositor.getSnapshot().windows ?? [];
        const hasWin = (Array.isArray(launched.windowIds) && launched.windowIds.length > 0) ||
          wins.some((w) => w.pid === launched.pid || w.appId === appId);

        if (sampleName === 'win-notepad.exe') {
          assert.ok(hasWin, 'Expected win-notepad.exe to create a real Compositor window');
        } else {
          // win-sysinfo.exe may legitimately be either a GUI app or a Console (CUI) utility emitting real stdout
          const hasStdout = run.stdout.trim().length > 0;
          const cleanExit = run.exitCode === null || run.exitCode === 0;
          assert.ok(
            hasWin || (hasStdout && cleanExit),
            `Expected ${sampleName} to either create a real Compositor window or emit non-empty stdout with clean exit (hasWin=${hasWin}, exitCode=${run.exitCode}, stdout=${JSON.stringify(run.stdout)})`
          );
        }

        if (hasWin || (run.pcb && run.pcb.state !== 'TERMINATED' && run.pcb.state !== 'ZOMBIE')) {
          await pkgManager.stop(launched.pid);
        }
      }
    } finally {
      if (osHandle) await osHandle.shutdown().catch(() => {});
    }
  });
});
