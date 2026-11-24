/**
 * OmniOS Milestone M2 Comprehensive Unit & Cross-Module Integration Test Suite
 * Covers ALL 20 M2 features (F-016 through F-035) across 15 suites (incl. Iter 2 A1–A10 & B1–B6
 * and Iter 3 C1–C6 & D1–D4 hardening/security regressions) with zero mocking of M1/M2 subsystems,
 * real WAL SQLite persistence, real OmniKernel 6-daemon boot/recover, and external Python 3
 * (`plistlib` & `zipfile`) cross-verification.
 */

import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { types as utilTypes } from 'node:util';
import { execFileSync } from 'node:child_process';

// M1 Core Imports
import {
  ERROR_CODES,
  OmniOSError,
  VfsError,
  FormatError,
  SecurityError,
  ProcessError,
  QuotaExceededError,
} from '../../os/common/errors.mjs';
import { crc32 } from '../../os/common/binary.mjs';
import { SqliteStorage } from '../../os/common/storage-sqlite.mjs';
import { KernelEventBus } from '../../os/kernel/event-bus.mjs';
import { ProcessManager, PROCESS_STATES } from '../../os/kernel/process.mjs';
import { ServiceManager } from '../../os/kernel/services.mjs';
import { SyscallDispatcher } from '../../os/kernel/syscalls.mjs';
import { PROT_READ, PROT_WRITE, PROT_EXEC } from '../../os/kernel/vmm.mjs';
import { OmniKernel, KERNEL_STATES } from '../../os/kernel/kernel.mjs';

// M2A Imports
import {
  ROOT_UID,
  ROOT_GID,
  DEFAULT_USER_UID,
  DEFAULT_USER_GID,
  SANDBOX_UID_BASE,
  ACCESS_MODES,
  SPECIAL_BITS,
  isWithinRoot,
  UserManager,
} from '../../os/security/users.mjs';
import {
  CAPABILITIES,
  ALL_CAPABILITIES,
  PERMISSION_STATES,
  mapNativePermission,
  mapNativePermissions,
  PermissionBroker,
  registerSecurityService,
} from '../../os/security/permissions.mjs';
import {
  PLATFORMS,
  MAX_PATH_LENGTH,
  isPathWithinRoot,
  PathTranslator,
} from '../../os/vfs/path-translator.mjs';
import {
  makeStatObject,
  makeDirentObject,
  ProcFsMount,
  DevFsMount,
  TmpFsMount,
  VirtualMountManager,
} from '../../os/vfs/virtual-mounts.mjs';
import {
  MAX_SYMLINK_DEPTH,
  OPEN_FLAGS,
  SEEK_WHENCE,
  VFS,
  registerVfsService,
} from '../../os/vfs/vfs.mjs';
import {
  REGISTRY_HIVES,
  REGISTRY_TYPES,
  CANONICAL_SHELL_MODES,
  CANONICAL_SYSTEM_KEYS,
  SYSTEM_SYNC_MAP,
  MAX_REG_KEY_PATH_CHARS,
  MAX_REG_KEY_DEPTH,
  MAX_REG_SEGMENT_CHARS,
  MAX_REG_VALUE_NAME_CHARS,
  UnifiedConfigStore,
  createConfigService,
  registerConfigService,
  registerConfigSyscalls,
} from '../../os/store/unified-config.mjs';

// M2B Imports
import { IPCManager } from '../../os/ipc/ipc.mjs';
import { IntentRouter } from '../../os/ipc/router.mjs';
import { SharedClipboard } from '../../os/ipc/clipboard.mjs';
import {
  NotificationCenter,
  createIpcBrokerService,
  registerIpcBrokerService,
} from '../../os/ipc/notifications.mjs';
import {
  SHELL_MODES,
  WINDOW_STATES,
  DEFAULT_MENU_BAR,
  normalizeShellMode,
  Compositor,
  registerCompositorService,
} from '../../os/compositor/compositor.mjs';
import {
  ZIP_METHODS,
  ZIP_FLAGS,
  ZIP_ERROR_CODES,
  MAX_ZIP_PATH_DEPTH,
  validateZipEntryName,
  listZipEntries,
  extractZipEntry,
  readZip,
  createZip,
} from '../../os/pkg/zip.mjs';
import {
  PACKAGE_FORMATS,
  FormatDetector,
  detectFormat,
} from '../../os/pkg/format-detector.mjs';
import {
  PackageManager,
  registerPackageService,
} from '../../os/pkg/package-manager.mjs';

// ============================================================================
// Shared Hygiene & Helpers
// ============================================================================

const tempDirs = [];
const unhandledRejections = [];

const onUnhandledRejection = (reason) => {
  unhandledRejections.push(reason);
};
process.on('unhandledRejection', onUnhandledRejection);

function makeTempDir(prefix = 'omnios-m2-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function makeWorkExecContext({ totalWork = 50, exitCode = 0, onEvent = null, onStep = null, onDispose = null } = {}) {
  let remaining = totalWork;
  const receivedEvents = [];
  let disposed = 0;
  return {
    receivedEvents,
    get disposeCount() {
      return disposed;
    },
    step(budget) {
      if (onStep) {
        const res = onStep(budget, remaining);
        if (res) return res;
      }
      const run = Math.min(budget, remaining);
      remaining -= run;
      if (remaining <= 0) {
        return { status: 'EXITED', instructionsExecuted: run, exitCode };
      }
      return { status: 'YIELD', instructionsExecuted: run };
    },
    deliverEvent(evt) {
      receivedEvents.push(evt);
      if (onEvent) return onEvent(evt);
    },
    getDebugState() {
      return { arch: 'test', pc: totalWork - remaining, sp: 0, registers: {}, instructionsExecuted: totalWork - remaining };
    },
    dispose() {
      disposed += 1;
      onDispose?.();
    },
  };
}

function runPython(script, inputJson = null) {
  const opts = {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  };
  if (inputJson !== null) {
    opts.input = typeof inputJson === 'string' ? inputJson : JSON.stringify(inputJson);
  }
  return execFileSync('python3', ['-c', script], opts);
}

// Binary fixture builders (authentic byte headers)
function buildPeFixture({ pe32Plus = true, isDll = false, machine = null } = {}) {
  const peOffset = 0x80;
  const buf = new Uint8Array(peOffset + 64);
  const view = new DataView(buf.buffer);
  buf[0] = 0x4d; // 'M'
  buf[1] = 0x5a; // 'Z'
  view.setUint32(0x3c, peOffset, true);
  buf[peOffset] = 0x50; // 'P'
  buf[peOffset + 1] = 0x45; // 'E'
  buf[peOffset + 2] = 0x00;
  buf[peOffset + 3] = 0x00;
  const mach = machine ?? (pe32Plus ? 0x8664 : 0x014c);
  view.setUint16(peOffset + 4, mach, true);
  view.setUint16(peOffset + 6, 2, true); // NumberOfSections
  view.setUint16(peOffset + 20, pe32Plus ? 240 : 224, true); // SizeOfOptionalHeader
  view.setUint16(peOffset + 22, isDll ? 0x2002 : 0x0002, true); // Characteristics
  view.setUint16(peOffset + 24, pe32Plus ? 0x020b : 0x010b, true); // Optional Magic
  return buf;
}

function buildMachOFixture(kind = 'macho64') {
  if (kind === 'macho64') {
    const buf = new Uint8Array(64);
    const view = new DataView(buf.buffer);
    view.setUint32(0, 0xfeedfacf, true);
    view.setUint32(4, 0x0100000c, true); // ARM64
    view.setUint32(8, 0, true);
    view.setUint32(12, 2, true); // MH_EXECUTE
    view.setUint32(16, 1, true); // ncmds
    return buf;
  }
  if (kind === 'macho32') {
    const buf = new Uint8Array(64);
    const view = new DataView(buf.buffer);
    view.setUint32(0, 0xfeedface, true);
    view.setUint32(4, 0x00000007, true); // x86
    view.setUint32(8, 3, true);
    view.setUint32(12, 2, true);
    view.setUint32(16, 1, true);
    return buf;
  }
  if (kind === 'fat32') {
    const buf = new Uint8Array(8 + 2 * 20);
    const view = new DataView(buf.buffer);
    view.setUint32(0, 0xcafebabe, false);
    view.setUint32(4, 2, false); // nfat_arch = 2
    view.setUint32(8, 0x0100000c, false); // ARM64
    view.setUint32(12, 0, false);
    view.setUint32(28, 0x01000007, false); // x86_64
    view.setUint32(32, 3, false);
    return buf;
  }
  if (kind === 'fat64') {
    const buf = new Uint8Array(8 + 1 * 32);
    const view = new DataView(buf.buffer);
    view.setUint32(0, 0xcafebabf, false);
    view.setUint32(4, 1, false);
    view.setUint32(8, 0x0100000c, false);
    view.setUint32(12, 0, false);
    return buf;
  }
  throw new Error(`Unknown kind: ${kind}`);
}

function buildDmgFixture({ xmlOffset = 128n, xmlLength = 64n } = {}) {
  const buf = new Uint8Array(1024);
  const view = new DataView(buf.buffer);
  const tail = buf.byteLength - 512;
  view.setUint32(tail, 0x6b6f6c79, false); // 'koly'
  view.setUint32(tail + 4, 4, false); // version
  view.setUint32(tail + 8, 512, false); // HeaderSize
  view.setBigUint64(tail + 0xd8, xmlOffset, false); // Apple UDIF koly spec XMLOffset (+0xD8)
  view.setBigUint64(tail + 0xe0, xmlLength, false); // Apple UDIF koly spec XMLLength (+0xE0)
  return buf;
}

function buildPkgXarFixture() {
  const buf = new Uint8Array(64);
  const view = new DataView(buf.buffer);
  view.setUint32(0, 0x78617221, false); // 'xar!'
  view.setUint16(4, 28, false); // headerSize
  view.setUint16(6, 1, false); // version
  return buf;
}

function buildMsiCfbfFixture() {
  const buf = new Uint8Array(512);
  buf.set([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], 0);
  return buf;
}

function buildWasmFixture() {
  return new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
}

function buildJavaClassFixture(majorVersion = 65) {
  const buf = new Uint8Array(64);
  const view = new DataView(buf.buffer);
  view.setUint32(0, 0xcafebabe, false);
  view.setUint16(4, 0, false); // minor_version
  view.setUint16(6, majorVersion, false); // major_version (e.g., 52 = Java 8, 65 = Java 21)
  return buf;
}

function buildApkFixture(extraEntries = []) {
  return createZip([
    { name: 'AndroidManifest.xml', data: '<manifest package="com.omnios.calc"/>' },
    { name: 'classes.dex', data: new Uint8Array([0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00]) },
    ...extraEntries,
  ]);
}

function buildMsixFixture() {
  return createZip([
    { name: 'AppxManifest.xml', data: '<Package><Identity Name="WinNotes"/></Package>' },
    { name: 'AppxBlockMap.xml', data: '<BlockMap/>' },
    { name: 'WinNotes.exe', data: buildPeFixture({ pe32Plus: true }) },
  ]);
}

function buildIpaFixture() {
  return createZip([
    { name: 'Payload/WeatherIsland.app/Info.plist', data: '<plist version="1.0"><dict/></plist>' },
    { name: 'Payload/WeatherIsland.app/WeatherIsland', data: buildMachOFixture('macho64') },
  ]);
}

function buildMacosAppFixture() {
  return createZip([
    { name: 'OmniStudio.app/Contents/Info.plist', data: '<plist version="1.0"><dict/></plist>' },
    { name: 'OmniStudio.app/Contents/MacOS/OmniStudio', data: buildMachOFixture('fat32') },
  ]);
}

function buildUappFixture() {
  return createZip([
    { name: 'omnios.manifest.json', data: JSON.stringify({ appId: 'universal.canvas', version: '1.0.0' }) },
    { name: 'main.wasm', data: buildWasmFixture() },
  ]);
}

after(() => {
  process.off('unhandledRejection', onUnhandledRejection);
  for (const dir of tempDirs) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  assert.equal(
    unhandledRejections.length,
    0,
    `Expected zero unhandled promise rejections across M2 suite, got ${unhandledRejections.length}: ${unhandledRejections.map((r) => String(r)).join('; ')}`
  );
});

// ============================================================================
// SUITE 1: os/security/users.mjs (F-027)
// ============================================================================

describe('Suite 1: os/security/users.mjs — Users, Groups, Sandbox UIDs & POSIX ACLs (F-027)', () => {
  it('seeds built-in root(0), user(1000), groups and supports custom group membership', () => {
    const um = new UserManager();
    try {
      const root = um.getUserByUid(ROOT_UID);
      assert.equal(root.uid, 0);
      assert.equal(root.gid, 0);
      assert.equal(root.username, 'root');
      assert.deepEqual(root.gids, [0, 10, 20]);

      const user = um.getUserByUid(DEFAULT_USER_UID);
      assert.equal(user.uid, 1000);
      assert.equal(user.gid, 1000);
      assert.equal(user.username, 'user');
      assert.deepEqual(user.gids, [20, 1000]);

      const grp = um.createGroup({ name: 'developers' });
      assert.ok(grp.gid >= 100);
      assert.equal(um.addUserToGroup(1000, 'developers'), true);
      assert.ok(um.getUserGroups(1000).includes(grp.gid));
      assert.equal(um.removeUserFromGroup(1000, grp.gid), true);
      assert.equal(um.deleteGroup(grp.gid), true);

      assert.throws(() => um.deleteGroup(ROOT_GID), (err) => err instanceof SecurityError && err.code === ERROR_CODES.EPERM);
      assert.throws(() => um.deleteGroup('wheel'), (err) => err instanceof SecurityError && err.code === ERROR_CODES.EPERM);
    } finally {
      um.close();
    }
  });

  it('allocates idempotent 10000+ app sandbox UIDs and releases them cleanly', () => {
    const um = new UserManager();
    try {
      const appA = um.allocateAppUid('com.acme.notes', {
        platform: 'android',
        sandboxRoot: '/var/appdata/android/com.acme.notes',
        strictSandbox: true,
      });
      assert.ok(appA.uid >= SANDBOX_UID_BASE);
      assert.equal(appA.gid, appA.uid);
      assert.equal(appA.appId, 'com.acme.notes');
      assert.equal(appA.sandboxRoot, '/var/appdata/android/com.acme.notes');
      assert.equal(appA.strictSandbox, true);
      assert.ok(um.getGroup(appA.gid));

      // Idempotent repeat allocation returns identical UID
      const appARepeat = um.allocateSandboxUid('com.acme.notes', { platform: 'android' });
      assert.equal(appARepeat.uid, appA.uid);

      const appB = um.allocateAppUid('com.acme.notes2', {
        platform: 'ios',
        containerUuid: 'UUID-B-1234',
        strictSandbox: true,
      });
      assert.equal(appB.uid, appA.uid + 1);

      assert.equal(um.releaseAppUid('com.acme.notes'), true);
      assert.equal(um.getUserByAppId('com.acme.notes'), null);
      assert.equal(um.getGroup(appA.gid), null);
      assert.equal(um.removeAppUser('com.acme.notes'), false);
    } finally {
      um.close();
    }
  });

  it('enforces strict no-fallthrough POSIX ACLs, root bypass, chmod/chown, and sticky bit 0o1000', () => {
    const um = new UserManager();
    try {
      // Strict POSIX: owner matches uid=1000, mode=0o077 denies owner (NO fallthrough to group/other!)
      const ownerDeniedTarget = { uid: 1000, gid: 20, mode: 0o077 };
      assert.equal(um.canRead({ uid: 1000 }, ownerDeniedTarget), false);
      assert.equal(um.canWrite({ uid: 1000 }, ownerDeniedTarget), false);
      assert.equal(um.canExec({ uid: 1000 }, ownerDeniedTarget), false);
      assert.equal(um.canRead({ uid: 0 }, ownerDeniedTarget), true); // root bypass

      // Strict POSIX: group matches gid=20 (user 1000 is in staff=20), mode=0o707 denies group (NO fallthrough to other!)
      const groupDeniedTarget = { uid: 9999, gid: 20, mode: 0o707 };
      assert.equal(um.canRead({ uid: 1000 }, groupDeniedTarget), false);
      assert.equal(um.canWrite({ uid: 1000 }, groupDeniedTarget), false);
      // Non-owner, non-group falls into other (0o7) -> allowed
      const app = um.allocateAppUid('com.other.reader', { platform: 'universal' });
      assert.equal(um.canRead({ uid: app.uid }, groupDeniedTarget), true);

      // chmod / chown rules
      assert.equal(um.canChmod({ uid: 1000 }, { uid: 1000, gid: 1000, mode: 0o644 }), true);
      assert.equal(um.canChmod({ uid: app.uid }, { uid: 1000, gid: 1000, mode: 0o644 }), false);
      assert.equal(um.canChown({ uid: 1000 }, { uid: 1000, gid: 1000, mode: 0o644 }, 1000, 20), true);
      assert.equal(um.canChown({ uid: 1000 }, { uid: 1000, gid: 1000, mode: 0o644 }, 0, 0), false);
      assert.equal(um.canChown({ uid: 0 }, { uid: 1000, gid: 1000, mode: 0o644 }, app.uid, app.gid), true);

      // Sticky bit 0o1777
      const stickyDir = { uid: 0, gid: 0, mode: 0o777 | SPECIAL_BITS.S_ISVTX };
      const userFile = { uid: 1000, gid: 1000, mode: 0o666 };
      assert.equal(um.canDeleteInDir({ uid: 1000 }, stickyDir, userFile), true); // entry owner
      assert.equal(um.canDeleteInDir({ uid: 0 }, stickyDir, userFile), true); // root / dir owner
      assert.equal(um.canDeleteInDir({ uid: app.uid }, stickyDir, userFile), false); // other user blocked by sticky bit

      // Non-sticky world-writable dir allows delete
      const nonStickyDir = { uid: 0, gid: 0, mode: 0o777 };
      assert.equal(um.canDeleteInDir({ uid: app.uid }, nonStickyDir, userFile), true);
      assert.equal(um.checkAccess({ uid: app.uid }, userFile, ACCESS_MODES.F_OK), true);
    } finally {
      um.close();
    }
  });

  it('enforces cross-app /var/appdata/* sandbox isolation and strict prefix-boundary defense', () => {
    const um = new UserManager();
    try {
      const app1 = um.allocateAppUid('com.test.app', {
        platform: 'android',
        sandboxRoot: '/var/appdata/android/com.test.app',
        strictSandbox: false,
      });
      const app2 = um.allocateAppUid('com.test.app2', {
        platform: 'android',
        sandboxRoot: '/var/appdata/android/com.test.app2',
        strictSandbox: true,
      });

      assert.equal(isWithinRoot('/var/appdata/android/com.test.app/db.sqlite', '/var/appdata/android/com.test.app'), true);
      assert.equal(isWithinRoot('/var/appdata/android/com.test.app2/secret', '/var/appdata/android/com.test.app'), false);

      // App1 can access own container & shared /home/user, CANNOT access App2 container or /root
      assert.equal(um.checkSandboxAccess({ uid: app1.uid }, '/var/appdata/android/com.test.app/prefs.xml').allowed, true);
      assert.equal(um.checkSandboxAccess({ uid: app1.uid }, '/home/user/Documents/shared.txt').allowed, true);
      assert.equal(um.checkSandboxAccess({ uid: app1.uid }, '/var/appdata/android/com.test.app2/secret').allowed, false);
      assert.equal(um.checkSandboxAccess({ uid: app1.uid }, '/root/.secret').allowed, false);

      assert.throws(
        () => um.assertSandboxAccess({ uid: app1.uid }, '/var/appdata/android/com.test.app2/secret'),
        (err) => err instanceof SecurityError && err.code === ERROR_CODES.EACCES && err.details?.violation === ERROR_CODES.E_SANDBOX_VIOLATION
      );

      // App2 has strictSandbox=true -> confined strictly to its own sandboxRoot
      assert.equal(um.checkSandboxAccess({ uid: app2.uid }, '/var/appdata/android/com.test.app2/data.bin').allowed, true);
      assert.equal(um.checkSandboxAccess({ uid: app2.uid }, '/home/user/Documents/shared.txt').allowed, false);
    } finally {
      um.close();
    }
  });

  it('persists users, groups, and sandbox UIDs across WAL SQLite close & reopen', () => {
    const dir = makeTempDir('omnios-m2-users-');
    const dbPath = path.join(dir, 'users.sqlite');

    const s1 = new SqliteStorage(dbPath);
    const um1 = new UserManager({ storage: s1 });
    const app1 = um1.allocateAppUid('com.persist.one', {
      platform: 'macos',
      sandboxRoot: '/var/appdata/macos/com.persist.one',
    });
    const customGrp = um1.createGroup({ name: 'audio' });
    um1.addUserToGroup(1000, 'audio');
    s1.close();

    const s2 = new SqliteStorage(dbPath);
    try {
      const um2 = new UserManager({ storage: s2 });
      const loaded = um2.getUserByAppId('com.persist.one');
      assert.ok(loaded);
      assert.equal(loaded.uid, app1.uid);
      assert.equal(loaded.sandboxRoot, '/var/appdata/macos/com.persist.one');
      assert.ok(um2.getUserGroups(1000).includes(customGrp.gid));

      // Next allocation continues monotonically above existing UID
      const app2 = um2.allocateAppUid('com.persist.two', { platform: 'windows' });
      assert.equal(app2.uid, app1.uid + 1);
    } finally {
      s2.close();
    }
  });
});

// ============================================================================
// SUITE 2: os/security/permissions.mjs (F-028)
// ============================================================================

describe('Suite 2: os/security/permissions.mjs — Permission Broker, 5-Ecosystem Maps & Audit Log (F-028)', () => {
  it('defines all 14 canonical capabilities and maps all 5 ecosystems accurately', () => {
    assert.equal(ALL_CAPABILITIES.length, 14);
    assert.equal(new Set(ALL_CAPABILITIES).size, 14);

    // Android (full + short suffix)
    assert.equal(mapNativePermission('android.permission.CAMERA', 'android'), CAPABILITIES.CAMERA_DEVICE);
    assert.equal(mapNativePermission('READ_EXTERNAL_STORAGE', 'android'), CAPABILITIES.FS_READ_USER);
    assert.equal(mapNativePermission('android.permission.POST_NOTIFICATIONS', 'android'), CAPABILITIES.NOTIFICATIONS_POST);
    assert.equal(mapNativePermission('android.permission.WRITE_SECURE_SETTINGS', 'android'), CAPABILITIES.REGISTRY_SYSTEM_WRITE);

    // iOS TCC
    assert.equal(mapNativePermission('kTCCServiceCamera', 'ios'), CAPABILITIES.CAMERA_DEVICE);
    assert.equal(mapNativePermission('NSLocationWhenInUseUsageDescription', 'ios'), CAPABILITIES.LOCATION_DEVICE);
    assert.equal(mapNativePermission('kTCCServicePasteboard', 'ios'), CAPABILITIES.CLIPBOARD_READ);
    assert.equal(mapNativePermission('UNUserNotificationCenter', 'ios'), CAPABILITIES.NOTIFICATIONS_POST);

    // macOS Gatekeeper & entitlements
    assert.equal(mapNativePermission('com.apple.security.files.user-selected.read-write', 'macos'), CAPABILITIES.FS_WRITE_USER);
    assert.equal(mapNativePermission('com.apple.security.network.client', 'macos'), CAPABILITIES.NETWORK_OUTBOUND);
    assert.equal(mapNativePermission('com.apple.security.gatekeeper.quarantine', 'macos'), CAPABILITIES.PROCESS_SPAWN);
    assert.equal(mapNativePermission('com.apple.security.system-configuration', 'macos'), CAPABILITIES.REGISTRY_SYSTEM_WRITE);

    // Windows UAC / MSIX (incl. multi-cap requireAdministrator)
    assert.equal(mapNativePermission('asInvoker', 'windows'), CAPABILITIES.UI_WINDOW);
    assert.equal(mapNativePermission('webcam', 'windows'), CAPABILITIES.CAMERA_DEVICE);
    const winMulti = mapNativePermissions(['requireAdministrator', 'toastNotifications', 'BOGUS_PERM'], 'windows');
    assert.ok(winMulti.capabilities.includes(CAPABILITIES.REGISTRY_SYSTEM_WRITE));
    assert.ok(winMulti.capabilities.includes(CAPABILITIES.FS_WRITE_SYSTEM));
    assert.ok(winMulti.capabilities.includes(CAPABILITIES.NOTIFICATIONS_POST));
    assert.deepEqual(winMulti.unmapped, ['BOGUS_PERM']);

    // WASI / Universal
    assert.equal(mapNativePermission('RIGHT_FD_READ', 'wasi'), CAPABILITIES.FS_READ_USER);
    assert.equal(mapNativePermission('wasi:fd_write', 'universal'), CAPABILITIES.FS_WRITE_USER);
    assert.equal(mapNativePermission('wasi:sock_connect', 'wasi'), CAPABILITIES.NETWORK_OUTBOUND);
    assert.equal(mapNativePermission('omni:ui.window', 'universal'), CAPABILITIES.UI_WINDOW);
  });

  it('enforces allow/deny/prompt, async promptHandler, resolvePrompt, policyOverride, and fail-closed invariants', async () => {
    const bus = new KernelEventBus();
    const broker = new PermissionBroker({ eventBus: bus, promptTimeoutMs: 60 });
    try {
      // Explicit allow / deny grants
      broker.setGrant('app.cam', CAPABILITIES.CAMERA_DEVICE, PERMISSION_STATES.ALLOW);
      const allowRes = await broker.checkPermission({
        appId: 'app.cam',
        pid: 42,
        platform: 'android',
        nativePermission: 'android.permission.CAMERA',
      });
      assert.equal(allowRes.granted, true);
      assert.equal(allowRes.policy, 'allow');

      broker.setGrant('app.cam', CAPABILITIES.LOCATION_DEVICE, PERMISSION_STATES.DENY);
      await assert.rejects(
        () => broker.assertPermission({ appId: 'app.cam', platform: 'ios', nativePermission: 'kTCCServiceLocation' }),
        (err) => err instanceof SecurityError && err.code === ERROR_CODES.E_PERMISSION_DENIED
      );

      // Async promptHandler returning 'pending' + external resolvePrompt('allow')
      let capturedPromptId = null;
      broker.setPromptHandler(async (prompt) => {
        capturedPromptId = prompt.promptId;
        setTimeout(() => {
          assert.equal(broker.getPendingPrompts().length, 1);
          const resolved = broker.resolvePrompt(prompt.promptId, 'allow');
          assert.equal(resolved.ok, true);
          assert.equal(resolved.granted, true);
        }, 5);
        return 'pending';
      });

      const promptRes = await broker.checkPermission({
        appId: 'app.prompted',
        pid: 101,
        platform: 'macos',
        capability: CAPABILITIES.CLIPBOARD_READ,
      });
      assert.equal(promptRes.granted, true);
      assert.equal(promptRes.policy, 'prompt');
      assert.equal(promptRes.reason, 'prompt_allowed');
      assert.ok(capturedPromptId);
      // Persisted grant now resolves as allow without prompting again
      assert.equal(broker.getGrant('app.prompted', CAPABILITIES.CLIPBOARD_READ)?.state, 'allow');

      // Fail-closed: promptHandler throws error -> denied with prompt_handler_error
      broker.setPromptHandler(async () => {
        throw new Error('UI modal crashed');
      });
      const errRes = await broker.checkPermission({
        appId: 'app.crash',
        platform: 'android',
        capability: CAPABILITIES.NOTIFICATIONS_POST,
      });
      assert.equal(errRes.granted, false);
      assert.equal(errRes.reason, 'prompt_handler_error');

      // Fail-closed: prompt timeout (.unref() timer)
      broker.setPromptHandler(null);
      const timeoutRes = await broker.checkPermission({
        appId: 'app.timeout',
        platform: 'ios',
        capability: CAPABILITIES.CAMERA_DEVICE,
        timeoutMs: 15,
      });
      assert.equal(timeoutRes.granted, false);
      assert.equal(timeoutRes.reason, 'prompt_timeout');

      // Fail-closed: unknown capability & unmapped native permission
      const unknownCap = await broker.checkPermission({ appId: 'app.bad', capability: 'root.godmode' });
      assert.equal(unknownCap.granted, false);
      assert.equal(unknownCap.reason, 'unknown_capability');

      const unmapped = await broker.checkPermission({
        appId: 'app.bad',
        platform: 'android',
        nativePermission: 'android.permission.NOT_REAL',
      });
      assert.equal(unmapped.granted, false);
      assert.equal(unmapped.reason, 'unmapped_native_permission');

      // Policy override (deterministic string, function, and failing function -> fail closed)
      broker.setPolicyOverride('allow');
      const ovAllow = await broker.checkPermission({ appId: 'app.ov', capability: CAPABILITIES.FS_WRITE_SYSTEM });
      assert.equal(ovAllow.granted, true);
      assert.equal(ovAllow.reason, 'policy_override');

      broker.setPolicyOverride(() => {
        throw new Error('override boom');
      });
      const ovBoom = await broker.checkPermission({ appId: 'app.ov', capability: CAPABILITIES.UI_WINDOW });
      assert.equal(ovBoom.granted, false);
      assert.equal(ovBoom.reason, 'policy_override_error');
      broker.setPolicyOverride(null);
    } finally {
      broker.close();
    }
  });

  it('persists hostile-object-safe security_audit rows in WAL SQLite and integrates with securityd daemon', async () => {
    const dir = makeTempDir('omnios-m2-sec-');
    const dbPath = path.join(dir, 'sec.sqlite');

    const kernel = new OmniKernel({ dbPath });
    const um = new UserManager({ kernel });
    const pb = new PermissionBroker({ kernel, userManager: um });
    registerSecurityService(kernel.serviceManager, { userManager: um, permissionBroker: pb, kernel });

    await kernel.boot();
    assert.equal(kernel.serviceManager.getStatus('securityd').state, 'RUNNING');
    assert.equal((await kernel.serviceManager.checkHealth('securityd')).healthy, true);

    // Hostile context object with circular ref, BigInt, throwing getter, Date(NaN), Uint8Array
    const hostileCtx = {
      big: 98765432109876543210n,
      badDate: new Date(NaN),
      bytes: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
    };
    hostileCtx.self = hostileCtx;
    Object.defineProperty(hostileCtx, 'bomb', {
      enumerable: true,
      get() {
        throw new Error('getter explosion');
      },
    });
    Object.defineProperty(hostileCtx, '__proto__', {
      enumerable: true,
      value: 'pollute-attempt',
    });

    const res = await pb.checkPermission({
      appId: 'com.hostile.audit',
      pid: 77,
      platform: 'windows',
      capability: CAPABILITIES.UI_WINDOW,
      context: hostileCtx,
    });
    assert.equal(res.granted, true);
    assert.ok(res.auditId >= 1);

    // Stopping securityd MUST NOT close shared kernel.storage
    await kernel.serviceManager.stop('securityd');
    assert.equal(kernel.storage.isOpen, true);
    await kernel.shutdown();

    // Reopen DB directly and confirm audit log & grants survived
    const reopened = new SqliteStorage(dbPath);
    try {
      const pb2 = new PermissionBroker({ storage: reopened });
      const logs = pb2.getAuditLog({ appId: 'com.hostile.audit', limit: 10 });
      assert.equal(logs.length, 1);
      assert.equal(logs[0].granted, true);
      assert.equal(logs[0].context.big, '98765432109876543210');
      assert.equal(logs[0].context.self, '[Circular]');
      assert.equal(logs[0].context.bomb, '[Unreadable]');
      assert.equal(logs[0].context.badDate, null);
    } finally {
      reopened.close();
    }
  });

  it('M7 Item B: selects interactive vs headless prompt timeouts via registerInteractiveSource / hasInteractivePromptConsumer', async () => {
    // Invalid interactive timeout is rejected fail-closed
    assert.throws(
      () => new PermissionBroker({ interactivePromptTimeoutMs: -1 }),
      (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
    );
    assert.throws(
      () => new PermissionBroker({ interactivePromptTimeoutMs: Number.NaN }),
      (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
    );

    const bus = new KernelEventBus();
    const broker = new PermissionBroker({ eventBus: bus, interactivePromptTimeoutMs: 400 });
    assert.throws(
      () => broker.registerInteractiveSource('not-a-function'),
      (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
    );

    // Headless: no promptHandler and no interactive source
    assert.equal(broker.hasInteractivePromptConsumer(), false);
    const headlessStart = Date.now();
    const headlessRes = await broker.checkPermission({
      appId: 'app.headless',
      platform: 'android',
      capability: CAPABILITIES.CAMERA_DEVICE,
      timeoutMs: 0,
    });
    assert.equal(headlessRes.granted, false);
    assert.equal(headlessRes.reason, 'prompt_timeout');
    assert.ok(Date.now() - headlessStart < 200, 'timeoutMs: 0 must settle immediately when headless');
    assert.equal(broker.getPendingPrompts().length, 0);

    // A throwing predicate is ignored (treated as non-interactive)
    const unregThrow = broker.registerInteractiveSource(() => {
      throw new Error('predicate boom');
    });
    assert.equal(broker.hasInteractivePromptConsumer(), false);
    unregThrow();

    // Live interactive source -> default timeout becomes interactivePromptTimeoutMs (400ms),
    // so the prompt is still pending after 60ms and can be resolved by the UI.
    let live = true;
    const unregister = broker.registerInteractiveSource(() => live);
    assert.equal(broker.hasInteractivePromptConsumer(), true);
    const pendingPromise = broker.checkPermission({
      appId: 'app.interactive',
      platform: 'windows',
      capability: CAPABILITIES.CLIPBOARD_READ,
    });
    await new Promise((r) => setTimeout(r, 60));
    const pending = broker.getPendingPrompts();
    assert.equal(pending.length, 1, 'interactive prompt must remain pending awaiting the UI');
    const resolved = broker.resolvePrompt(pending[0].promptId, 'allow');
    assert.equal(resolved.ok, true);
    const interactiveRes = await pendingPromise;
    assert.equal(interactiveRes.granted, true);
    assert.equal(interactiveRes.reason, 'prompt_allowed');

    // Unresolved interactive prompt times out after interactivePromptTimeoutMs (not the 2500ms headless default)
    const tStart = Date.now();
    const timedOut = await broker.checkPermission({
      appId: 'app.interactive.slow',
      platform: 'ios',
      capability: CAPABILITIES.LOCATION_DEVICE,
    });
    const elapsed = Date.now() - tStart;
    assert.equal(timedOut.reason, 'prompt_timeout');
    assert.ok(elapsed >= 350 && elapsed < 2400, `interactive timeout must be ~400ms (got ${elapsed}ms)`);

    // Source goes inactive / unregistered -> back to headless
    live = false;
    assert.equal(broker.hasInteractivePromptConsumer(), false);
    live = true;
    unregister();
    assert.equal(broker.hasInteractivePromptConsumer(), false);

    // An explicit constructor promptTimeoutMs always wins over the interactive default
    const explicitBroker = new PermissionBroker({ eventBus: bus, promptTimeoutMs: 30, interactivePromptTimeoutMs: 5000 });
    explicitBroker.registerInteractiveSource(() => true);
    const eStart = Date.now();
    const explicitRes = await explicitBroker.checkPermission({
      appId: 'app.explicit',
      platform: 'macos',
      capability: CAPABILITIES.NOTIFICATIONS_POST,
    });
    assert.equal(explicitRes.reason, 'prompt_timeout');
    assert.ok(Date.now() - eStart < 1000, 'explicit promptTimeoutMs must override interactive timeout');
  });
});

// ============================================================================
// SUITE 3: os/vfs/path-translator.mjs (F-017, F-018)
// ============================================================================

describe('Suite 3: os/vfs/path-translator.mjs — 4-Platform PathTranslator & Traversal Jail (F-017, F-018)', () => {
  it('translates Shared User Space identically across all 4 platforms and respects specificity', () => {
    const pt = new PathTranslator();

    const sharedTargets = ['Documents/report.txt', 'Downloads/pkg.zip', 'Desktop/todo.md', 'Pictures/hero.png'];
    for (const rel of sharedTargets) {
      const expected = `/home/user/${rel}`;
      const win = pt.toCanonical(`C:\\Users\\user\\${rel.replace(/\//g, '\\')}`, { platform: PLATFORMS.WINDOWS });
      const mac = pt.toCanonical(`/Users/user/${rel}`, { platform: PLATFORMS.MACOS });
      const and1 = pt.toCanonical(`/sdcard/${rel}`, { platform: PLATFORMS.ANDROID });
      const and2 = pt.toCanonical(`/storage/emulated/0/${rel}`, { platform: PLATFORMS.ANDROID });
      const ios = pt.toCanonical(`/var/mobile/${rel}`, { platform: PLATFORMS.IOS });

      assert.equal(win.canonicalPath, expected);
      assert.equal(mac.canonicalPath, expected);
      assert.equal(and1.canonicalPath, expected);
      assert.equal(and2.canonicalPath, expected);
      assert.equal(ios.canonicalPath, expected);

      assert.equal(win.caseInsensitive, true);
      assert.equal(mac.caseInsensitive, true);
      assert.equal(and1.caseInsensitive, false);
      assert.equal(ios.caseInsensitive, false);
    }

    // Prefix specificity: AppData before C:\Users\user; Library before /Users/user
    assert.equal(
      pt.toCanonical('c:\\USERS\\USER\\AppData\\Roaming\\MyApp\\cfg.ini', { platform: 'windows' }).canonicalPath,
      '/var/appdata/windows/Roaming/MyApp/cfg.ini'
    );
    assert.equal(
      pt.toCanonical('/Users/user/Library/Preferences/com.apple.test.plist', { platform: 'macos' }).canonicalPath,
      '/var/appdata/macos/Library/Preferences/com.apple.test.plist'
    );

    // Other platform roots & reverse toPlatform()
    assert.equal(pt.toCanonical('C:\\Windows\\System32\\cmd.exe', { platform: 'windows' }).canonicalPath, '/system/windows/System32/cmd.exe');
    assert.equal(pt.toCanonical('C:\\Program Files\\OmniApp\\app.exe', { platform: 'windows' }).canonicalPath, '/apps/windows/OmniApp/app.exe');
    assert.equal(pt.toCanonical('Z:\\etc\\hosts', { platform: 'windows' }).canonicalPath, '/etc/hosts');
    assert.equal(pt.toCanonical('/Applications/Studio.app', { platform: 'macos' }).canonicalPath, '/apps/macos/Studio.app');
    assert.equal(pt.toCanonical('/data/data/com.demo.calc/files/db', { platform: 'android' }).canonicalPath, '/var/appdata/android/com.demo.calc/files/db');
    assert.equal(pt.toCanonical('/var/mobile/Containers/Data/Application/UUID-1/tmp/a', { platform: 'ios' }).canonicalPath, '/var/appdata/ios/UUID-1/tmp/a');

    // Bidirectional reverse round-trip
    assert.equal(pt.toPlatform('/home/user/Documents/note.txt', 'windows'), 'C:\\Users\\user\\Documents\\note.txt');
    assert.equal(pt.toPlatform('/home/user/Documents/note.txt', 'macos'), '/Users/user/Documents/note.txt');
    assert.equal(pt.toPlatform('/home/user/Documents/note.txt', 'android'), '/sdcard/Documents/note.txt');
    assert.equal(pt.toPlatform('/home/user/Documents/note.txt', 'ios'), '/var/mobile/Documents/note.txt');
    assert.equal(pt.toPlatform('/var/appdata/android/com.x/a', 'android'), '/data/data/com.x/a');
    assert.equal(pt.toPlatform('/var/appdata/ios/UUID-1/a', 'ios'), '/var/mobile/Containers/Data/Application/UUID-1/a');
  });

  it('rejects NUL/control chars with EINVAL and blocks inherent container + sandboxRoot traversals', () => {
    const pt = new PathTranslator();

    // NUL, control char, empty, >4096 chars -> EINVAL
    for (const bad of ['', '/home/user/a\0b', '/home/user/line\nbreak', '/home/user/' + 'a'.repeat(4100)]) {
      assert.throws(() => pt.toCanonical(bad), (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL);
    }

    // Inherent Android container escape
    assert.throws(
      () => pt.toCanonical('/data/data/com.app/../../etc/passwd', { platform: 'android' }),
      (err) => err instanceof VfsError && err.code === ERROR_CODES.EACCES && err.details?.violation === ERROR_CODES.E_PATH_TRAVERSAL
    );

    // Inherent iOS container escape
    assert.throws(
      () => pt.toCanonical('/var/mobile/Containers/Data/Application/UUID-1/../../../etc/passwd', { platform: 'ios' }),
      (err) => err instanceof VfsError && err.code === ERROR_CODES.EACCES && err.details?.violation === ERROR_CODES.E_PATH_TRAVERSAL
    );

    // Explicit sandboxRoot escape (both final escape and intermediate pop-out back into sandbox)
    const jail = '/var/appdata/windows/my-app';
    assert.throws(
      () => pt.toCanonical('/var/appdata/windows/my-app/../other-app/secret', { sandboxRoot: jail }),
      (err) => err instanceof VfsError && err.code === ERROR_CODES.EACCES && err.details?.violation === ERROR_CODES.E_PATH_TRAVERSAL
    );
    assert.throws(
      () => pt.toCanonical('/var/appdata/windows/my-app/sub/../../my-app/ok', { sandboxRoot: jail }),
      (err) => err instanceof VfsError && err.code === ERROR_CODES.EACCES && err.details?.violation === ERROR_CODES.E_PATH_TRAVERSAL
    );
    // Valid path inside sandboxRoot succeeds
    assert.equal(
      pt.toCanonical('/var/appdata/windows/my-app/sub/../ok.txt', { sandboxRoot: jail }).canonicalPath,
      '/var/appdata/windows/my-app/ok.txt'
    );
  });
});

// ============================================================================
// SUITE 4: os/vfs/virtual-mounts.mjs (F-020)
// ============================================================================

describe('Suite 4: os/vfs/virtual-mounts.mjs — /proc, /dev & In-Memory /tmp (F-020)', () => {
  it('exposes live /proc/* reflecting real OmniKernel/ProcessManager/VMM state', async () => {
    const kernel = new OmniKernel();
    const vfs = new VFS({ kernel });
    registerVfsService(kernel.serviceManager, vfs, { kernel });
    await kernel.boot();

    try {
      const pcb = kernel.processManager.spawn({
        name: 'proc-inspector',
        appId: 'com.test.proc',
        platform: 'macos',
        arch: 'arm64',
        cwd: '/home/user/Documents',
        args: ['proc-inspector', '--flag', '42'],
        executionContext: makeWorkExecContext(),
      });
      // Map real VMM guard region (__PAGEZERO) and executable/data pages
      pcb.addressSpace.reserveGuard(0x0, 0x100000000, '__PAGEZERO');
      const codeBase = pcb.addressSpace.mmap(0x100000000, 8192, PROT_READ | PROT_EXEC, '__TEXT');
      const dataBase = pcb.addressSpace.mmap(0x100010000, 4096, PROT_READ | PROT_WRITE, '__DATA');
      assert.ok(codeBase >= 0x100000000 && dataBase > codeBase);

      const uptime = vfs.readFile('/proc/uptime', { encoding: 'utf8' });
      assert.match(uptime, /^\d+\.\d+\s+\d+\.\d+\n$/);

      const version = vfs.readFile('/proc/version', { encoding: 'utf8' });
      assert.ok(version.includes('OmniOS'));

      // Verify /proc/meminfo reports real non-zero mapped pages matching ProcessManager
      const agg = kernel.processManager.getAggregateMemoryStats();
      assert.ok(agg.totalMappedPages >= 3);
      const meminfo = vfs.readFile('/proc/meminfo', { encoding: 'utf8' });
      assert.ok(meminfo.includes(`MappedPages:\t${agg.totalMappedPages}`));
      assert.ok(meminfo.includes(`UsedBytes:\t${agg.totalUsedBytes}`));

      const status = vfs.readFile(`/proc/${pcb.pid}/status`, { encoding: 'utf8' });
      assert.ok(status.includes(`Name:\tproc-inspector`));
      assert.ok(status.includes(`Pid:\t${pcb.pid}`));
      assert.ok(status.includes(`Platform:\tmacos`));
      assert.ok(status.includes(`MappedPages:\t3`));

      const cmdline = vfs.readFile(`/proc/${pcb.pid}/cmdline`, { encoding: 'utf8' });
      assert.equal(cmdline, 'proc-inspector\x00--flag\x0042\n');

      const cwd = vfs.readFile(`/proc/${pcb.pid}/cwd`, { encoding: 'utf8' });
      assert.equal(cwd, '/home/user/Documents\n');

      const maps = vfs.readFile(`/proc/${pcb.pid}/maps`, { encoding: 'utf8' });
      assert.ok(maps.includes('__PAGEZERO'));
      assert.ok(maps.includes('__TEXT'));
      assert.ok(maps.includes('__DATA'));
      assert.ok(maps.includes('r-xp'));
      assert.ok(maps.includes('rw-p'));

      // /proc is read-only
      assert.throws(() => vfs.writeFile('/proc/uptime', 'hack'), (err) => err instanceof VfsError && err.code === ERROR_CODES.EACCES);

      // Killed PID transitions to ZOMBIE in /proc, then disappears once reaped (TERMINATED)
      kernel.processManager.kill(pcb.pid, 'SIGKILL');
      assert.ok(vfs.readFile(`/proc/${pcb.pid}/status`, { encoding: 'utf8' }).includes('State:\tZOMBIE'));
      kernel.processManager.reap(pcb.pid);
      assert.throws(() => vfs.stat(`/proc/${pcb.pid}/status`), (err) => err instanceof VfsError && err.code === ERROR_CODES.ENOENT);
    } finally {
      await kernel.shutdown();
    }
  });

  it('implements /dev/{null,zero,urandom} as type=device and isolated in-memory /tmp with sticky bit & ENOSPC', () => {
    const um = new UserManager();
    const vfs = new VFS({ userManager: um, maxTmpBytes: 1024 });
    try {
      for (const dev of ['/dev/null', '/dev/zero', '/dev/urandom']) {
        const st = vfs.stat(dev);
        assert.equal(st.type, 'device');
      }

      // /dev/null
      vfs.writeFile('/dev/null', 'discard me');
      assert.equal(vfs.readFile('/dev/null').byteLength, 0);

      // /dev/zero
      const zeros = vfs.readFile('/dev/zero', { length: 64 });
      assert.equal(zeros.byteLength, 64);
      assert.ok(zeros.every((b) => b === 0));

      // /dev/urandom
      const r1 = vfs.readFile('/dev/urandom', { length: 32 });
      const r2 = vfs.readFile('/dev/urandom', { length: 32 });
      assert.equal(r1.byteLength, 32);
      assert.notDeepEqual(r1, r2);

      // In-memory /tmp: sticky bit 0o1777, host isolation, ENOSPC
      const tmpStat = vfs.stat('/tmp');
      assert.equal(tmpStat.mode, 0o1777);

      const uniqueName = `omnios-mem-only-${Date.now()}-${Math.random().toString(16).slice(2)}.tmp`;
      vfs.writeFile(`/tmp/${uniqueName}`, 'ephemeral-data', { uid: 1000, gid: 1000 });
      assert.equal(fs.existsSync(path.join(os.tmpdir(), uniqueName)), false, 'VFS /tmp must NEVER touch host /tmp');

      // Another user (sandbox UID) cannot unlink UID 1000's file inside sticky /tmp
      const app = um.allocateAppUid('com.tmp.attacker', { platform: 'universal' });
      assert.throws(
        () => vfs.unlink(`/tmp/${uniqueName}`, { uid: app.uid, gid: app.gid }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EACCES
      );
      // Owner CAN unlink
      vfs.unlink(`/tmp/${uniqueName}`, { uid: 1000, gid: 1000 });

      // ENOSPC when exceeding maxTmpBytes (1024)
      assert.throws(
        () => vfs.writeFile('/tmp/too-big.bin', new Uint8Array(2048), { uid: 1000, gid: 1000 }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.ENOSPC
      );

      // Verify VirtualMountManager directly reports 4 mounts
      const vmMgr = new VirtualMountManager();
      assert.equal(vmMgr.listMounts().length, 4);
    } finally {
      vfs.close();
      um.close();
    }
  });
});

// ============================================================================
// SUITE 5: os/vfs/vfs.mjs (F-016, F-018, F-019)
// ============================================================================

describe('Suite 5: os/vfs/vfs.mjs — Persistent POSIX VFS, Shared User Space, Symlinks & FDs (F-016, F-018, F-019)', () => {
  it('persists across WAL SQLite reopen and shares identical canonical inodes across all 4 platforms', () => {
    const dir = makeTempDir('omnios-m2-vfs-');
    const dbPath = path.join(dir, 'vfs.sqlite');

    const s1 = new SqliteStorage(dbPath);
    const vfs1 = new VFS({ storage: s1 });
    vfs1.writeFile('C:\\Users\\user\\Documents\\SharedPlan.txt', 'Unified 4-platform doc', {
      platform: 'windows',
      uid: 1000,
      gid: 1000,
    });
    vfs1.setXattr('/home/user/Documents/SharedPlan.txt', 'user.origin', 'windows', { uid: 1000, gid: 1000 });
    const winStat = vfs1.stat('C:\\Users\\user\\Documents\\SharedPlan.txt', { platform: 'windows' });

    // All 4 platforms + POSIX read identical inode & data
    const macStat = vfs1.stat('/Users/user/Documents/SharedPlan.txt', { platform: 'macos' });
    const andStat = vfs1.stat('/sdcard/Documents/SharedPlan.txt', { platform: 'android' });
    const and2Stat = vfs1.stat('/storage/emulated/0/Documents/SharedPlan.txt', { platform: 'android' });
    const iosStat = vfs1.stat('/var/mobile/Documents/SharedPlan.txt', { platform: 'ios' });
    const posixStat = vfs1.stat('/home/user/Documents/SharedPlan.txt', { platform: 'posix' });

    assert.equal(macStat.ino, winStat.ino);
    assert.equal(andStat.ino, winStat.ino);
    assert.equal(and2Stat.ino, winStat.ino);
    assert.equal(iosStat.ino, winStat.ino);
    assert.equal(posixStat.ino, winStat.ino);
    assert.equal(vfs1.readFile('/var/mobile/Documents/SharedPlan.txt', { platform: 'ios', encoding: 'utf8' }), 'Unified 4-platform doc');
    s1.close();

    // Reopen from disk WAL SQLite
    const s2 = new SqliteStorage(dbPath);
    try {
      const vfs2 = new VFS({ storage: s2 });
      assert.equal(vfs2.stat('/home/user/Documents/SharedPlan.txt').ino, winStat.ino);
      assert.equal(vfs2.readFile('/home/user/Documents/SharedPlan.txt', { encoding: 'utf8' }), 'Unified 4-platform doc');
      assert.equal(new TextDecoder().decode(vfs2.getXattr('/home/user/Documents/SharedPlan.txt', 'user.origin')), 'windows');
    } finally {
      s2.close();
    }
  });

  it('preserves creation case for Windows/macOS case-insensitive lookup and in-place case-only rename', () => {
    const vfs = new VFS();
    try {
      vfs.writeFile('C:\\Users\\user\\Documents\\MixedCase.TXT', 'hello-ci', {
        platform: 'windows',
        uid: 1000,
        gid: 1000,
      });
      const origIno = vfs.stat('/home/user/Documents/MixedCase.TXT').ino;

      // Windows & macOS find case-insensitively while POSIX is case-sensitive
      assert.equal(vfs.readFile('C:\\Users\\user\\Documents\\mixedcase.txt', { platform: 'windows', encoding: 'utf8' }), 'hello-ci');
      assert.equal(vfs.readFile('/Users/user/Documents/MIXEDCASE.TXT', { platform: 'macos', encoding: 'utf8' }), 'hello-ci');
      assert.throws(() => vfs.stat('/home/user/Documents/mixedcase.txt', { platform: 'posix' }), (e) => e.code === ERROR_CODES.ENOENT);

      // Directory preserves original creation case
      const namesBefore = vfs.readdir('/home/user/Documents', { namesOnly: true });
      assert.ok(namesBefore.includes('MixedCase.TXT'));

      // Case-only rename on Windows preserves exact inode!
      vfs.rename('C:\\Users\\user\\Documents\\MixedCase.TXT', 'C:\\Users\\user\\Documents\\README.txt', {
        platform: 'windows',
        uid: 1000,
        gid: 1000,
      });
      vfs.rename('C:\\Users\\user\\Documents\\README.txt', 'C:\\Users\\user\\Documents\\readme.txt', {
        platform: 'windows',
        uid: 1000,
        gid: 1000,
      });
      assert.equal(vfs.stat('/home/user/Documents/readme.txt').ino, origIno);
      assert.ok(vfs.readdir('/home/user/Documents', { namesOnly: true }).includes('readme.txt'));
    } finally {
      vfs.close();
    }
  });

  it('enforces symlink depth 16 OK / depth 17 ELOOP, relative, dangling, cross-mount & sandbox escape defense', () => {
    const vfs = new VFS();
    try {
      assert.equal(MAX_SYMLINK_DEPTH, 16);
      vfs.mkdir('/home/user/links', { recursive: true, uid: 1000, gid: 1000 });
      vfs.writeFile('/home/user/links/target.txt', 'bullseye', { uid: 1000, gid: 1000 });

      // Build symlink chain link1 -> target, link2 -> link1, ..., link17 -> link16
      vfs.symlink('/home/user/links/target.txt', '/home/user/links/l1', { uid: 1000, gid: 1000 });
      for (let i = 2; i <= 17; i += 1) {
        vfs.symlink(`/home/user/links/l${i - 1}`, `/home/user/links/l${i}`, { uid: 1000, gid: 1000 });
      }
      assert.equal(vfs.readFile('/home/user/links/l16', { encoding: 'utf8' }), 'bullseye');
      assert.throws(
        () => vfs.readFile('/home/user/links/l17'),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.ELOOP
      );

      // Relative symlink
      vfs.mkdir('/home/user/links/sub', { uid: 1000, gid: 1000 });
      vfs.symlink('../target.txt', '/home/user/links/sub/rel', { uid: 1000, gid: 1000 });
      assert.equal(vfs.readFile('/home/user/links/sub/rel', { encoding: 'utf8' }), 'bullseye');

      // Dangling symlink
      vfs.symlink('/home/user/links/does-not-exist', '/home/user/links/dangling', { uid: 1000, gid: 1000 });
      const lst = vfs.lstat('/home/user/links/dangling');
      assert.equal(lst.type, 'symlink');
      assert.equal(vfs.readlink('/home/user/links/dangling'), '/home/user/links/does-not-exist');
      assert.throws(() => vfs.stat('/home/user/links/dangling'), (e) => e.code === ERROR_CODES.ENOENT);

      // Cross-mount symlink into /tmp
      vfs.writeFile('/tmp/cross.txt', 'from-tmp', { uid: 1000, gid: 1000 });
      vfs.symlink('/tmp/cross.txt', '/home/user/links/to_tmp', { uid: 1000, gid: 1000 });
      assert.equal(vfs.readFile('/home/user/links/to_tmp', { encoding: 'utf8' }), 'from-tmp');

      // Sandbox escape via symlink pointing outside sandboxRoot -> EACCES / E_PATH_TRAVERSAL
      vfs.mkdir('/var/appdata/android/com.jail', { recursive: true, uid: 0, gid: 0 });
      vfs.symlink('/etc', '/var/appdata/android/com.jail/escape', { uid: 0, gid: 0 });
      assert.throws(
        () => vfs.stat('/var/appdata/android/com.jail/escape', { sandboxRoot: '/var/appdata/android/com.jail' }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EACCES
      );
    } finally {
      vfs.close();
    }
  });

  it('enforces POSIX error codes, FDs + EMFILE + exit auto-close, BLOB isolation, prototype keys, events & vfsd', async () => {
    const dir = makeTempDir('omnios-m2-vfsd-');
    const kernel = new OmniKernel({ dbPath: path.join(dir, 'vfsd.sqlite') });
    const um = new UserManager({ kernel });
    const vfs = new VFS({ kernel, userManager: um });
    registerSecurityService(kernel.serviceManager, { userManager: um, kernel });
    registerVfsService(kernel.serviceManager, vfs, { kernel, deps: ['securityd'] });

    const events = [];
    kernel.eventBus.on('vfs:changed', (e) => events.push(e));
    await kernel.boot();

    try {
      // Subtree rename EINVAL, non-empty rmdir ENOTEMPTY, unlink dir EISDIR, readdir file ENOTDIR
      vfs.mkdir('/home/user/tree/child', { recursive: true, uid: 1000, gid: 1000 });
      vfs.writeFile('/home/user/tree/child/f.txt', 'data', { uid: 1000, gid: 1000 });
      assert.throws(() => vfs.rename('/home/user/tree', '/home/user/tree/child/into-self', { uid: 1000, gid: 1000 }), (e) => e.code === ERROR_CODES.EINVAL);
      assert.throws(() => vfs.rmdir('/home/user/tree', { uid: 1000, gid: 1000 }), (e) => e.code === ERROR_CODES.ENOTEMPTY);
      assert.throws(() => vfs.unlink('/home/user/tree', { uid: 1000, gid: 1000 }), (e) => e.code === ERROR_CODES.EISDIR);
      assert.throws(() => vfs.readdir('/home/user/tree/child/f.txt'), (e) => e.code === ERROR_CODES.ENOTDIR);

      // Defensive .slice() BLOB isolation
      const origBuf = new Uint8Array([1, 2, 3, 4]);
      vfs.writeFile('/home/user/iso.bin', origBuf, { uid: 1000, gid: 1000 });
      origBuf[0] = 99;
      const readBack = vfs.readFile('/home/user/iso.bin');
      assert.deepEqual(readBack, new Uint8Array([1, 2, 3, 4]));
      readBack[1] = 88;
      assert.deepEqual(vfs.readFile('/home/user/iso.bin'), new Uint8Array([1, 2, 3, 4]));

      // Prototype-key filenames
      vfs.mkdir('/home/user/proto', { uid: 1000, gid: 1000 });
      vfs.writeFile('/home/user/proto/__proto__', 'safe-proto', { uid: 1000, gid: 1000 });
      vfs.writeFile('/home/user/proto/constructor', 'safe-ctor', { uid: 1000, gid: 1000 });
      assert.equal(vfs.readFile('/home/user/proto/__proto__', { encoding: 'utf8' }), 'safe-proto');
      const protoNames = vfs.readdir('/home/user/proto', { namesOnly: true });
      assert.deepEqual(protoNames, ['__proto__', 'constructor']);

      // Open / read / write / seek / close + ProcessManager FD quota EMFILE + exit auto-close
      const pcb = kernel.processManager.spawn({
        name: 'fd-worker',
        uid: 1000,
        gid: 1000,
        quotas: { maxOpenFds: 5 }, // FDs 0,1,2 already used -> 2 slots left!
        executionContext: makeWorkExecContext(),
      });
      const h1 = vfs.open('/home/user/fdtest.txt', OPEN_FLAGS.O_RDWR | OPEN_FLAGS.O_CREAT | OPEN_FLAGS.O_TRUNC, {
        pid: pcb.pid,
        uid: 1000,
        gid: 1000,
      });
      vfs.write(h1, 'HelloWorld');
      assert.equal(vfs.seek(h1, 5, SEEK_WHENCE.SEEK_SET), 5);
      assert.equal(new TextDecoder().decode(vfs.read(h1, 5)), 'World');
      assert.equal(vfs.seek(h1, -10, SEEK_WHENCE.SEEK_END), 0);
      assert.equal(new TextDecoder().decode(vfs.read(h1, 5)), 'Hello');

      const h2 = vfs.open('/home/user/iso.bin', 'r', { pid: pcb.pid, uid: 1000, gid: 1000 });
      // 3rd user FD exceeds maxOpenFds=5 (0,1,2,3,4 occupied) -> EMFILE!
      assert.throws(
        () => vfs.open('/home/user/iso.bin', 'r', { pid: pcb.pid, uid: 1000, gid: 1000 }),
        (err) => err.code === ERROR_CODES.EMFILE
      );

      // Killing process auto-closes all open FDs
      kernel.processManager.kill(pcb.pid, 'SIGKILL');
      assert.equal(h1.closed, true);
      assert.equal(h2.closed, true);
      assert.throws(() => vfs.read(h1, 1), (err) => err instanceof VfsError && err.code === ERROR_CODES.EBADF);

      assert.ok(events.some((e) => e.op === 'write' && e.path === '/home/user/iso.bin'));

      // vfsd stop clears ephemeral /tmp without closing shared kernel.storage
      vfs.writeFile('/tmp/gone-on-stop.txt', 'temp', { uid: 1000, gid: 1000 });
      await kernel.serviceManager.stop('vfsd');
      assert.equal(kernel.storage.isOpen, true);
      await kernel.serviceManager.start('vfsd');
      assert.throws(() => vfs.stat('/tmp/gone-on-stop.txt'), (e) => e.code === ERROR_CODES.ENOENT);
      assert.equal(vfs.readFile('/home/user/fdtest.txt', { encoding: 'utf8' }), 'HelloWorld');
    } finally {
      await kernel.shutdown();
    }
  });
});

// ============================================================================
// SUITE 6: os/store/unified-config.mjs (F-021, F-022)
// ============================================================================

describe('Suite 6: os/store/unified-config.mjs — Registry, Defaults/Plist, SharedPrefs & 8-Key Sync (F-021, F-022)', () => {
  it('supports all 5 Registry hives + aliases, all 6 types (BigInt QWORD JSON-safe), merged HKCR, HKLM virtualization & B-tree deleteKey', () => {
    const cfg = new UnifiedConfigStore();
    try {
      // All 5 hives + long aliases
      const pairs = [
        ['HKCR', 'HKEY_CLASSES_ROOT'],
        ['HKCU', 'HKEY_CURRENT_USER'],
        ['HKLM', 'HKEY_LOCAL_MACHINE'],
        ['HKU', 'HKEY_USERS'],
        ['HKCC', 'HKEY_CURRENT_CONFIG'],
      ];
      for (const [shortHive, longHive] of pairs) {
        cfg.registry.setValue(shortHive, 'OmniTest\\HiveCheck', 'Ping', REGISTRY_TYPES.REG_SZ, shortHive);
        assert.equal(cfg.registry.getValue(longHive, 'OmniTest\\HiveCheck', 'Ping')?.data, shortHive);
      }

      // All 6 types + REG_QWORD BigInt + JSON.stringify safety
      const binIn = new Uint8Array([0x01, 0x23, 0x45, 0x67]);
      cfg.registry.setValue('HKCU', 'Software\\Types', 'Sz', REGISTRY_TYPES.REG_SZ, 'hello');
      cfg.registry.setValue('HKCU', 'Software\\Types', 'Exp', REGISTRY_TYPES.REG_EXPAND_SZ, '%SystemRoot%\\bin');
      cfg.registry.setValue('HKCU', 'Software\\Types', 'Bin', REGISTRY_TYPES.REG_BINARY, binIn);
      cfg.registry.setValue('HKCU', 'Software\\Types', 'Dw', REGISTRY_TYPES.REG_DWORD, 0xdeadbeef);
      cfg.registry.setValue('HKCU', 'Software\\Types', 'Multi', REGISTRY_TYPES.REG_MULTI_SZ, ['one', 'two']);
      cfg.registry.setValue('HKCU', 'Software\\Types', 'Qw', REGISTRY_TYPES.REG_QWORD, 0xffffffffffffffffn);
      cfg.registry.setValue('HKCU', 'Software\\Types', '__proto__', REGISTRY_TYPES.REG_SZ, 'safe-proto');

      binIn[0] = 0xff; // Verify .slice() isolation
      assert.deepEqual(cfg.registry.getValue('HKCU', 'Software\\Types', 'Bin').data, new Uint8Array([0x01, 0x23, 0x45, 0x67]));
      assert.equal(cfg.registry.getValue('HKCU', 'Software\\Types', 'Dw').data, 0xdeadbeef);
      assert.deepEqual(cfg.registry.getValue('HKCU', 'Software\\Types', 'Multi').data, ['one', 'two']);

      const qwRec = cfg.registry.getValue('HKCU', 'Software\\Types', 'Qw');
      assert.equal(typeof qwRec.data, 'bigint');
      assert.equal(qwRec.data, 0xffffffffffffffffn);
      const qwJson = JSON.parse(JSON.stringify(qwRec));
      assert.equal(qwJson.data, '18446744073709551615');

      const enumTypes = cfg.registry.enumKey('HKCU', 'Software\\Types');
      assert.equal(Object.prototype.hasOwnProperty.call(enumTypes.values, '__proto__'), true);
      assert.equal(enumTypes.values['__proto__'].data, 'safe-proto');

      // Merged HKCR (HKCU\Software\Classes overrides HKLM\Software\Classes)
      cfg.registry.setValue('HKLM', 'Software\\Classes\\.demo', '', REGISTRY_TYPES.REG_SZ, 'GlobalProg');
      assert.equal(cfg.registry.getValue('HKCR', '.demo', '').data, 'GlobalProg');
      cfg.registry.setValue('HKCU', 'Software\\Classes\\.demo', '', REGISTRY_TYPES.REG_SZ, 'UserProg');
      assert.equal(cfg.registry.getValue('HKCR', '.demo', '').data, 'UserProg');

      // Per-app unprivileged HKLM virtualization + traversal rejection + global delete EACCES
      cfg.registry.setValue('HKLM', 'Software\\Vendor', 'License', REGISTRY_TYPES.REG_SZ, 'GLOBAL');
      const appACtx = { uid: 10001, appId: 'win.appA' };
      const appBCtx = { uid: 10002, appId: 'win.appB' };

      const virtWrite = cfg.registry.setValue('HKLM', 'Software\\Vendor', 'License', REGISTRY_TYPES.REG_SZ, 'APP_A_OVERRIDE', appACtx);
      assert.equal(virtWrite.virtualized, true);
      assert.equal(cfg.registry.getValue('HKLM', 'Software\\Vendor', 'License', appACtx).data, 'APP_A_OVERRIDE');
      assert.equal(cfg.registry.getValue('HKLM', 'Software\\Vendor', 'License', appACtx).virtualized, true);
      assert.equal(cfg.registry.getValue('HKLM', 'Software\\Vendor', 'License', appBCtx).data, 'GLOBAL');
      assert.equal(cfg.registry.getValue('HKLM', 'Software\\Vendor', 'License').data, 'GLOBAL');

      // Traversal rejected
      assert.throws(
        () => cfg.registry.setValue('HKLM', 'Software\\..\\Evil', 'X', REGISTRY_TYPES.REG_SZ, '1', appACtx),
        (err) => err instanceof SecurityError && err.code === ERROR_CODES.E_PATH_TRAVERSAL
      );
      assert.throws(
        () => cfg.registry.setValue('HKLM', 'Software\\Ok', 'X', REGISTRY_TYPES.REG_SZ, '1', { uid: 10001, appId: '..\\evil' }),
        (err) => err instanceof SecurityError && err.code === ERROR_CODES.E_PATH_TRAVERSAL
      );
      // Unprivileged global HKLM delete denied with EACCES
      assert.throws(
        () => cfg.registry.deleteValue('HKLM', 'Software\\Vendor', 'License', appBCtx),
        (err) => err instanceof SecurityError && err.code === ERROR_CODES.EACCES
      );

      // Wildcard-free B-tree deleteKey (`%` and `_` must NOT match sibling keys)
      cfg.registry.setValue('HKCU', 'Software\\App%1_Test\\Sub', 'K', REGISTRY_TYPES.REG_SZ, 'del');
      cfg.registry.setValue('HKCU', 'Software\\AppX1YTest\\Sub', 'K', REGISTRY_TYPES.REG_SZ, 'keep');
      assert.equal(cfg.registry.deleteKey('HKCU', 'Software\\App%1_Test'), true);
      assert.equal(cfg.registry.getValue('HKCU', 'Software\\App%1_Test\\Sub', 'K'), null);
      assert.equal(cfg.registry.getValue('HKCU', 'Software\\AppX1YTest\\Sub', 'K')?.data, 'keep');
    } finally {
      cfg.close();
    }
  });

  it('validates Apple NSUserDefaults, cycle guard E_CYCLIC_PLIST & external Python 3 plistlib.loads() interop', () => {
    const cfg = new UnifiedConfigStore();
    try {
      // Cyclic object rejected with E_CYCLIC_PLIST
      const cyclic = { name: 'loop' };
      cyclic.self = cyclic;
      assert.throws(
        () => cfg.defaults.set('com.omnios.bad', 'cycle', cyclic),
        (err) => err instanceof FormatError && err.code === ERROR_CODES.E_CYCLIC_PLIST
      );

      // Rich hostile domain exported to XML plist and parsed by host Python 3 plistlib.loads()
      const domain = 'com.omnios.interop.plist';
      const hostileStr = 'A\x00\x01\x07\x08\x0B\x0C\x0E\x1F\uFFFE\uFFFFB \uD800 \uDC00 \uD83D\uDE80 <tag a="1" & \'2\'> ]]> r1\r\nr2';
      const binData = new Uint8Array([0x00, 0xca, 0xfe, 0xba, 0xbe, 0xff]);
      const msDate = new Date('2026-11-21T01:28:16.789Z');
      const nested = { ok: true, arr: [1, 'two', 3.5, false] };
      Object.defineProperty(nested, '__proto__', { value: 'proto-safe', enumerable: true, writable: true, configurable: true });

      cfg.defaults.set(domain, 'hostile', hostileStr);
      cfg.defaults.set(domain, 'when', msDate);
      cfg.defaults.set(domain, 'bin', binData);
      cfg.defaults.set(domain, 'big', 9007199254740993n);
      cfg.defaults.set(domain, 'nested', nested);

      const xml = cfg.defaults.exportPlistXml(domain);
      const globalXml = cfg.defaults.exportPlistXml('NSGlobalDomain');
      assert.ok(xml.includes('2026-11-21T01:28:16Z'), 'Plist date must strip fractional milliseconds');

      const pyOut = runPython(
        `
import sys, json, plistlib, datetime
data = json.loads(sys.stdin.read())
parsed = plistlib.loads(data["xml"].encode("utf-8"))
g = plistlib.loads(data["globalXml"].encode("utf-8"))
assert parsed["bin"] == bytes([0x00, 0xca, 0xfe, 0xba, 0xbe, 0xff]), parsed["bin"]
assert parsed["big"] == 9007199254740993, parsed["big"]
assert isinstance(parsed["when"], datetime.datetime), type(parsed["when"])
assert parsed["when"].strftime("%Y-%m-%dT%H:%M:%SZ") == "2026-11-21T01:28:16Z"
assert parsed["nested"]["__proto__"] == "proto-safe"
assert "\\x00" not in parsed["hostile"]
assert "\\ufffd" in parsed["hostile"]
assert "🚀" in parsed["hostile"]
assert "AppleInterfaceStyle" in g and "OmniOSShellMode" in g
print(json.dumps({"ok": True, "globalKeys": sorted(g.keys())}))
        `,
        { xml, globalXml }
      );
      const pyRes = JSON.parse(pyOut);
      assert.equal(pyRes.ok, true);
      assert.equal(pyRes.globalKeys.length, 8);
    } finally {
      cfg.close();
    }
  });

  it('enforces atomic Android SharedPreferences rollback, live 8-key cross-platform sync, re-entrancy guard & configd', async () => {
    const dir = makeTempDir('omnios-m2-cfg-');
    const kernel = new OmniKernel({ dbPath: path.join(dir, 'cfg.sqlite') });
    const cfg = new UnifiedConfigStore({ kernel });
    registerConfigService(kernel.serviceManager, cfg, { kernel });
    await kernel.boot();

    try {
      // Atomic SharedPreferences rollback on error mid-batch
      cfg.sharedPrefs.edit('com.app.prefs', 'main', [{ op: 'put', key: 'stable', value: 'v1' }]);
      assert.throws(() => {
        cfg.sharedPrefs.edit('com.app.prefs', 'main', [
          { op: 'put', key: 'stable', value: 'v2-should-rollback' },
          { op: 'put', key: 'temp', value: 123 },
          { op: 'bogus_op', key: 'fail' },
        ]);
      }, (e) => e.code === ERROR_CODES.EINVAL);
      assert.deepEqual(cfg.sharedPrefs.getAll('com.app.prefs', 'main'), { stable: 'v1' });

      // Live atomic 8-key cross-platform sync across all 4 facades
      assert.equal(CANONICAL_SYSTEM_KEYS.length, 8);
      assert.equal(CANONICAL_SHELL_MODES.includes('unified'), true);

      // 'hybrid' alias normalizes to 'unified'
      cfg.system.set('system.shellMode', 'hybrid');
      assert.equal(cfg.system.get('system.shellMode'), 'unified');
      assert.equal(cfg.defaults.get('NSGlobalDomain', 'OmniOSShellMode'), 'unified');

      // Sync from System -> Registry + Defaults + SharedPrefs
      cfg.system.set('system.theme', 'light');
      assert.equal(cfg.registry.getValue('HKCU', 'Software\\OmniOS\\System', 'Theme').data, 'light');
      assert.equal(cfg.defaults.get('NSGlobalDomain', 'AppleInterfaceStyle'), 'light');
      assert.equal(cfg.sharedPrefs.get('com.omnios.system', 'system_settings', 'system.theme'), 'light');

      // Sync from Registry -> System + Defaults + SharedPrefs
      cfg.registry.setValue('HKCU', 'Software\\OmniOS\\System', 'Volume', REGISTRY_TYPES.REG_DWORD, 42);
      assert.equal(cfg.system.get('system.volume'), 42);
      assert.equal(cfg.defaults.get('NSGlobalDomain', 'OmniOSVolume'), 42);
      assert.equal(cfg.sharedPrefs.get('com.omnios.system', 'system_settings', 'system.volume'), 42);

      // Sync from Defaults -> System + Registry + SharedPrefs
      cfg.defaults.set('NSGlobalDomain', 'OmniOSDoNotDisturb', true);
      assert.equal(cfg.system.get('system.dnd'), true);
      assert.equal(cfg.registry.getValue('HKCU', 'Software\\OmniOS\\System', 'DoNotDisturb').data, 1);
      assert.equal(cfg.sharedPrefs.get('com.omnios.system', 'system_settings', 'system.dnd'), true);

      // Sync from SharedPrefs -> System + Registry + Defaults
      cfg.sharedPrefs.edit('com.omnios.system', 'system_settings', [
        { op: 'put', key: 'system.brightness', value: 55 },
        { op: 'put', key: 'system.wifi', value: false },
        { op: 'put', key: 'system.bluetooth', value: false },
        { op: 'put', key: 'system.locale', value: 'fr-FR' },
        { op: 'put', key: 'system.shellMode', value: 'macos' },
      ]);
      assert.equal(cfg.system.get('system.brightness'), 55);
      assert.equal(cfg.system.get('system.wifi'), false);
      assert.equal(cfg.system.get('system.bluetooth'), false);
      assert.equal(cfg.system.get('system.locale'), 'fr-FR');
      assert.equal(cfg.system.get('system.shellMode'), 'macos');
      assert.equal(cfg.defaults.get('NSGlobalDomain', 'AppleLocale'), 'fr-FR');
      assert.equal(cfg.registry.getValue('HKCU', 'Software\\OmniOS\\System', 'WifiEnabled').data, 0);
      assert.equal(cfg.registry.getValue('HKCU', 'Software\\OmniOS\\System', 'BluetoothEnabled').data, 0);

      // Verify re-entrancy guard on config:changed listener
      let emitCount = 0;
      const unsub = kernel.eventBus.on('config:changed', (evt) => {
        if (evt.canonicalKey === 'system.volume') {
          emitCount += 1;
          if (emitCount === 1) {
            // Re-entrant write to the same canonical key must NOT recurse infinitely!
            cfg.system.set('system.volume', 60);
          }
        }
      });
      cfg.system.set('system.volume', 61);
      unsub();
      assert.equal(emitCount, 1);
      assert.equal(cfg.system.get('system.volume'), 60);
      assert.ok(SYSTEM_SYNC_MAP['system.locale']);

      assert.equal((await kernel.serviceManager.checkHealth('configd')).healthy, true);
    } finally {
      await kernel.shutdown();
    }
  });
});

// ============================================================================
// SUITE 7: os/ipc/ipc.mjs (F-023)
// ============================================================================

describe('Suite 7: os/ipc/ipc.mjs — Channels, Pipes, RPC, SHM & Process Cleanup (F-023)', () => {
  it('supports named channels, pub/sub, RPC, channel request/reply, and timeout with zero unhandled rejections', async () => {
    const bus = new KernelEventBus();
    const pm = new ProcessManager({ eventBus: bus });
    const ipc = new IPCManager({ eventBus: bus, processManager: pm, defaultRpcTimeoutMs: 40 });

    const p1 = pm.spawn({ name: 'sender', executionContext: makeWorkExecContext() });
    const p2 = pm.spawn({ name: 'receiver', executionContext: makeWorkExecContext() });

    // Channels + prototype-safe name + clone isolation
    ipc.createChannel('__proto__', p1.pid);
    const seen = [];
    const unsub = ipc.subscribe('__proto__', (msg) => seen.push(msg), { pid: p2.pid });
    const payload = { nested: { v: 1 } };
    ipc.send('__proto__', p1.pid, payload);
    payload.nested.v = 999; // Mutating original must not affect queued/delivered msg
    assert.equal(seen.length, 1);
    assert.equal(seen[0].payload.nested.v, 1);
    const popped = ipc.recv('__proto__', p2.pid);
    assert.equal(popped.payload.nested.v, 1);
    unsub();

    // Register & call RPC
    ipc.registerRpc('calc.add', async ({ a, b }) => ({ sum: a + b }), { ownerPid: p2.pid });
    const rpcRes = await ipc.callRpc('calc.add', { a: 19, b: 23 }, { fromPid: p1.pid });
    assert.deepEqual(rpcRes, { sum: 42 });

    // Channel request / reply
    ipc.createChannel('xpc.echo', p2.pid);
    ipc.subscribe('xpc.echo', (msg) => {
      if (msg.type === 'request' && msg.correlationId) {
        ipc.reply(msg.correlationId, { echoed: msg.payload.msg }, { fromPid: p2.pid });
      }
    }, { pid: p2.pid });
    const reqRes = await ipc.request('xpc.echo', p1.pid, { msg: 'ping' }, { timeoutMs: 200 });
    assert.deepEqual(reqRes, { echoed: 'ping' });

    // Timeout ETIMEDOUT on slow RPC & unanswered channel request
    ipc.registerRpc('slow.rpc', () => new Promise(() => {}), { ownerPid: p2.pid });
    await assert.rejects(
      () => ipc.callRpc('slow.rpc', {}, { fromPid: p1.pid, timeoutMs: 20 }),
      (err) => err instanceof OmniOSError && err.code === ERROR_CODES.ETIMEDOUT
    );

    ipc.createChannel('blackhole', p2.pid);
    await assert.rejects(
      () => ipc.request('blackhole', p1.pid, { x: 1 }, { timeoutMs: 20 }),
      (err) => err instanceof OmniOSError && err.code === ERROR_CODES.ETIMEDOUT
    );

    ipc.stop();
  });

  it('enforces SHM bounds (ERANGE), byteOffset views, .slice() isolation, read-only EACCES, zero-fill & kill/reset cleanup', () => {
    const bus = new KernelEventBus();
    const pm = new ProcessManager({ eventBus: bus });
    const ipc = new IPCManager({ eventBus: bus, processManager: pm });

    const owner = pm.spawn({ name: 'shm-owner', executionContext: makeWorkExecContext() });
    const reader = pm.spawn({ name: 'shm-reader', executionContext: makeWorkExecContext() });

    const seg = ipc.shmCreate('framebuf', 32, owner.pid, { mode: 'r' });
    assert.equal(seg.size, 32);

    // Non-owner cannot attach rw to read-only segment -> EACCES
    assert.throws(
      () => ipc.shmAttach(seg.id, reader.pid, { mode: 'rw' }),
      (err) => err instanceof SecurityError && err.code === ERROR_CODES.EACCES
    );
    ipc.shmAttach(seg.id, reader.pid, { mode: 'r' });

    // Write using non-zero byteOffset subarray view
    const backing = new Uint8Array(64);
    backing.fill(0xaa);
    backing.set([10, 20, 30, 40, 50, 60], 12);
    const sliceView = backing.subarray(12, 18);
    ipc.shmWrite(seg.id, 4, sliceView, { pid: owner.pid });

    // Read-only attached reader cannot write -> EACCES
    assert.throws(
      () => ipc.shmWrite(seg.id, 0, new Uint8Array([1]), { pid: reader.pid }),
      (err) => err instanceof SecurityError && err.code === ERROR_CODES.EACCES
    );

    // Bounds check -> ERANGE
    assert.throws(() => ipc.shmWrite(seg.id, 30, new Uint8Array(4), { pid: owner.pid }), (e) => e.code === ERROR_CODES.ERANGE);
    assert.throws(() => ipc.shmRead(seg.id, 28, 10, { pid: reader.pid }), (e) => e.code === ERROR_CODES.ERANGE);

    // Defensive .slice() isolation on read
    const readOut = ipc.shmRead(seg.id, 4, 6, { pid: reader.pid });
    assert.deepEqual(readOut, new Uint8Array([10, 20, 30, 40, 50, 60]));
    readOut[0] = 0xff;
    assert.deepEqual(ipc.shmRead(seg.id, 4, 6, { pid: reader.pid }), new Uint8Array([10, 20, 30, 40, 50, 60]));

    // Non-owner destroy -> EPERM; owner destroy zero-fills backing buffer
    assert.throws(() => ipc.shmDestroy(seg.id, { pid: reader.pid }), (e) => e.code === ERROR_CODES.EPERM);
    const internalBuf = ipc._shmById.get(seg.id).buffer;
    assert.equal(ipc.shmDestroy(seg.id, { pid: owner.pid }), true);
    assert.ok(internalBuf.every((b) => b === 0), 'shmDestroy must zero-fill internal SHM buffer');

    // Auto-cleanup on processManager.kill()
    ipc.createChannel('owner.chan', owner.pid);
    ipc.shmCreate('owner.shm', 16, owner.pid);
    pm.kill(owner.pid, 'SIGKILL');
    assert.equal(ipc.listChannels().some((c) => c.name === 'owner.chan'), false);
    assert.equal(ipc.listShm().some((s) => s.name === 'owner.shm'), false);

    // Auto-cleanup on processManager.reset() (cleanupHooks without process:exited!)
    const pReset = pm.spawn({ name: 'reset-proc', executionContext: makeWorkExecContext() });
    ipc.createChannel('reset.chan', pReset.pid);
    ipc.shmCreate('reset.shm', 16, pReset.pid);
    ipc.registerRpc('reset.rpc', () => 'ok', { ownerPid: pReset.pid });
    pm.reset();
    assert.equal(ipc.listChannels().length, 0);
    assert.equal(ipc.listShm().length, 0);
    assert.equal(ipc._rpcs.size, 0);

    ipc.stop();
  });
});

// ============================================================================
// SUITE 8: os/ipc/router.mjs (F-024)
// ============================================================================

describe('Suite 8: os/ipc/router.mjs — Universal Intent, URL-Scheme & File-Association Router (F-024)', () => {
  it('indexes Android, Apple (with UTI), Windows HKCR (via UnifiedConfigStore) & Universal handlers and ranks matches', () => {
    const bus = new KernelEventBus();
    const cfg = new UnifiedConfigStore({ eventBus: bus });
    const router = new IntentRouter({ eventBus: bus, configStore: cfg });

    try {
      // 1. Android <intent-filter>
      router.registerHandlers('android.notes', {
        intentFilters: [
          {
            action: 'android.intent.action.SEND',
            data: [{ mimeType: 'text/plain' }],
            priority: 5,
          },
          {
            action: 'android.intent.action.VIEW',
            data: [{ scheme: 'omnios', host: 'notes' }],
            priority: 10,
          },
        ],
      });

      // 2. Apple CFBundleURLTypes + CFBundleDocumentTypes (UTI expansion!)
      router.registerHandlers('macos.editor', {
        CFBundleURLTypes: [{ CFBundleURLSchemes: ['omnistudio'], CFBundleURLName: 'OmniStudio URL' }],
        CFBundleDocumentTypes: [
          {
            CFBundleTypeName: 'Plain Text',
            LSItemContentTypes: ['public.plain-text'],
            priority: 8,
          },
        ],
      });

      // 3. Windows HKCR live indexing (ProgID + direct + URL Protocol)
      cfg.registry.setValue('HKCR', '.txt', '', REGISTRY_TYPES.REG_SZ, 'OmniTxtFile');
      cfg.registry.setValue('HKCR', '.txt', 'Content Type', REGISTRY_TYPES.REG_SZ, 'text/plain');
      cfg.registry.setValue('HKCR', 'OmniTxtFile', 'OmniOSAppId', REGISTRY_TYPES.REG_SZ, 'win.notepad');
      cfg.registry.setValue('HKCR', 'winapp', 'URL Protocol', REGISTRY_TYPES.REG_SZ, '');
      cfg.registry.setValue('HKCR', 'winapp', 'OmniOSAppId', REGISTRY_TYPES.REG_SZ, 'win.notepad');
      const indexed = router.indexRegistryAssociations(cfg);
      assert.equal(indexed.indexed, 2);

      // 4. Universal handler
      router.registerHandlers('universal.viewer', [
        { actions: ['view'], extensions: ['.md'], mimeTypes: ['text/markdown'], platform: 'universal' },
      ]);

      // Ranked resolution across all 4 platforms
      const txtCandidates = router.resolve({ action: 'view', uri: 'file:///home/user/Documents/readme.txt' });
      const txtAppIds = txtCandidates.map((c) => c.appId);
      assert.ok(txtAppIds.includes('macos.editor'));
      assert.ok(txtAppIds.includes('win.notepad'));

      assert.equal(router.resolve({ uri: 'omnistudio://open/project1' })[0].appId, 'macos.editor');
      assert.equal(router.resolve({ uri: 'winapp://launch' })[0].appId, 'win.notepad');
      assert.equal(router.resolve({ action: 'view', uri: 'omnios://notes/42' })[0].appId, 'android.notes');
      assert.equal(router.resolve({ action: 'view', uri: 'C:\\Users\\user\\README.md' })[0].appId, 'universal.viewer');

      // Malformed URIs never crash
      assert.deepEqual(router.resolve({ uri: ':::://///bad\0uri' }), []);
      assert.deepEqual(router.resolve({ uri: 'a'.repeat(5000) }), []);
    } finally {
      cfg.close();
    }
  });

  it('handles DELIVERED, CHOOSER_REQUIRED + intent:chooser + one-shot resolveChooser(setAsDefault), NO_HANDLER & unregisterApp', async () => {
    const bus = new KernelEventBus();
    const launched = [];
    const chooserEvents = [];
    bus.on('intent:chooser', (e) => chooserEvents.push(e));

    const router = new IntentRouter({
      eventBus: bus,
      launcher: async (appId, { intent }) => {
        launched.push({ appId, intent });
        return { pid: 500 + launched.length };
      },
    });

    router.registerHandlers('app.one', [{ actions: ['send'], mimeTypes: ['text/plain'], priority: 1 }]);
    router.registerHandlers('app.two', [{ actions: ['send'], mimeTypes: ['text/plain'], priority: 1 }]);
    router.registerHandlers('app.solo', [{ schemes: ['solo'] }]);

    // NO_HANDLER
    assert.equal(router.dispatch({ uri: 'nonexistent://foo' }).status, 'NO_HANDLER');

    // Single match -> DELIVERED via async launcher
    const soloRes = await router.dispatch({ uri: 'solo://go', extras: { k: 1 } });
    assert.equal(soloRes.status, 'DELIVERED');
    assert.equal(soloRes.targetAppId, 'app.solo');
    assert.equal(soloRes.launched, true);
    assert.equal(soloRes.pid, 501);

    // Multiple matches without default -> CHOOSER_REQUIRED
    const multiRes = router.dispatch({ action: 'send', mimeType: 'text/plain', extras: { text: 'hi' } });
    assert.equal(multiRes.status, 'CHOOSER_REQUIRED');
    assert.equal(multiRes.candidates.length, 2);
    assert.equal(chooserEvents.length, 1);

    // Strictly one-shot resolveChooser with setAsDefault: true
    const chosen = await router.resolveChooser(multiRes.requestId, 'app.two', { setAsDefault: true });
    assert.equal(chosen.status, 'DELIVERED');
    assert.equal(chosen.targetAppId, 'app.two');
    assert.throws(() => router.resolveChooser(multiRes.requestId, 'app.two'), (e) => e.code === ERROR_CODES.ENOENT);

    // Subsequent dispatch delivers directly to default 'app.two'
    const direct = await router.dispatch({ action: 'send', mimeType: 'text/plain' });
    assert.equal(direct.status, 'DELIVERED');
    assert.equal(direct.targetAppId, 'app.two');

    // unregisterApp scrubs default binding & handlers
    assert.equal(router.unregisterApp('app.two'), true);
    const afterUnreg = await router.dispatch({ action: 'send', mimeType: 'text/plain' });
    assert.equal(afterUnreg.status, 'DELIVERED');
    assert.equal(afterUnreg.targetAppId, 'app.one');
  });
});

// ============================================================================
// SUITE 9: os/ipc/clipboard.mjs & os/ipc/notifications.mjs (F-025, F-026)
// ============================================================================

describe('Suite 9: os/ipc/clipboard.mjs & os/ipc/notifications.mjs — Clipboard, Notifications, DND, Live Activities & ipc-brokerd (F-025, F-026)', () => {
  it('supports multi-MIME SharedClipboard, getBytes, 20-item history, deep-clone isolation & EFBIG cap', () => {
    const bus = new KernelEventBus();
    const events = [];
    bus.on('clipboard:changed', (e) => events.push(e));
    const clip = new SharedClipboard({ eventBus: bus, maxHistory: 20, maxEntryBytes: 2048 });

    const pngBytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    const rec = clip.set({
      text: 'Hello OmniOS',
      html: '<b>Hello OmniOS</b>',
      json: { nested: { count: 7 } },
      imagePng: pngBytes,
      sourceAppId: 'macos.notes',
      sourcePlatform: 'macos',
    });
    assert.equal(rec.text, 'Hello OmniOS');
    assert.equal(rec.html, '<b>Hello OmniOS</b>');
    assert.deepEqual(rec.json, { nested: { count: 7 } });
    assert.deepEqual(clip.getBytes('image/png'), pngBytes);

    // Deep-clone isolation
    rec.json.nested.count = 999;
    assert.equal(clip.get('application/json').nested.count, 7);
    const pngCopy = clip.getBytes('image/png');
    pngCopy[0] = 0x00;
    assert.equal(clip.getBytes('image/png')[0], 0x89);

    // Bounded 20-entry history
    for (let i = 1; i <= 25; i += 1) {
      clip.set({ text: `item-${i}`, sourceAppId: 'win.notepad' });
    }
    const hist = clip.history();
    assert.equal(hist.length, 20);
    assert.equal(hist[0].text, 'item-25');
    assert.equal(hist[19].text, 'item-6');

    // EFBIG cap enforcement & cyclic JSON rejection
    assert.throws(
      () => clip.set({ text: 'x'.repeat(3000) }),
      (err) => err instanceof QuotaExceededError && err.code === ERROR_CODES.EFBIG
    );
    const cyc = {};
    cyc.self = cyc;
    assert.throws(() => clip.set({ json: cyc }), (e) => e.code === ERROR_CODES.EINVAL);
    assert.ok(events.length >= 26);
  });

  it('syncs NotificationCenter live DND with UnifiedConfigStore, invokes interactive actions, runs Dynamic Island Live Activities & ipc-brokerd', async () => {
    const dir = makeTempDir('omnios-m2-broker-');
    const kernel = new OmniKernel({ dbPath: path.join(dir, 'broker.sqlite') });
    const cfg = new UnifiedConfigStore({ kernel });
    const ipc = new IPCManager({ eventBus: kernel.eventBus, processManager: kernel.processManager });
    const router = new IntentRouter({ eventBus: kernel.eventBus, processManager: kernel.processManager, configStore: cfg });
    const clip = new SharedClipboard({ eventBus: kernel.eventBus });
    const notif = new NotificationCenter({
      eventBus: kernel.eventBus,
      configStore: cfg,
      processManager: kernel.processManager,
    });

    registerConfigService(kernel.serviceManager, cfg, { kernel });
    registerIpcBrokerService(kernel.serviceManager, {
      ipc,
      router,
      clipboard: clip,
      notifications: notif,
      deps: ['configd'],
    });
    await kernel.boot();

    try {
      assert.equal((await kernel.serviceManager.checkHealth('ipc-brokerd')).healthy, true);

      // DND OFF -> normal delivers banner
      cfg.system.set('system.dnd', false);
      const n1 = notif.post({ appId: 'ios.mail', platform: 'ios', title: 'New Mail', body: 'Hello', priority: 'normal' });
      assert.equal(n1.suppressed, false);
      assert.equal(n1.deliveredBanner, true);

      // DND ON -> normal/high suppressed, urgent/critical bypass
      cfg.system.set('system.dnd', true);
      const n2 = notif.post({ appId: 'android.chat', platform: 'android', title: 'Chat', body: 'Suppressed', priority: 'normal' });
      assert.equal(n2.suppressed, true);
      assert.equal(n2.deliveredBanner, false);

      const nUrg = notif.post({ appId: 'system.alarm', platform: 'ios', title: 'Alarm', body: 'Wake up!', priority: 'urgent' });
      const nCrit = notif.post({ appId: 'system.sec', platform: 'macos', title: 'Critical', body: 'Alert!', priority: 'critical' });
      assert.equal(nUrg.suppressed, false);
      assert.equal(nUrg.deliveredBanner, true);
      assert.equal(nCrit.suppressed, false);
      assert.equal(nCrit.deliveredBanner, true);

      // Interactive action routed to live owning process ExecutionContext.deliverEvent()
      const ctx = makeWorkExecContext();
      const pcb = kernel.processManager.spawn({
        name: 'chat-daemon',
        appId: 'android.chat',
        executionContext: ctx,
      });
      const nAct = notif.post({
        appId: 'android.chat',
        platform: 'android',
        title: 'Incoming Message',
        body: 'Reply now?',
        actions: [{ id: 'reply', label: 'Quick Reply' }],
      });
      const actRes = notif.invokeAction(nAct.id, 'reply', { input: 'On my way!' });
      assert.equal(actRes.ok, true);
      assert.equal(actRes.deliveredPid, pcb.pid);
      assert.equal(ctx.receivedEvents.length, 1);
      assert.equal(ctx.receivedEvents[0].type, 'notification_action');
      assert.equal(ctx.receivedEvents[0].input, 'On my way!');

      // Dynamic Island Live Activity lifecycle
      const nLive = notif.post({
        appId: 'ios.weather',
        platform: 'ios',
        title: 'Rain Alert',
        liveActivity: {
          id: 'la-rain-1',
          title: 'Heavy Rain',
          subtitle: '12 min remaining',
          compactLeading: '🌧️',
          compactTrailing: '12m',
          progress: 0.25,
        },
      });
      assert.equal(nLive.liveActivity.id, 'la-rain-1');
      assert.equal(notif.getLiveActivities().length, 1);

      const updatedLa = notif.updateLiveActivity('la-rain-1', { progress: 0.8, compactTrailing: '3m' });
      assert.equal(updatedLa.progress, 0.8);
      assert.equal(updatedLa.compactTrailing, '3m');

      const endedLa = notif.endLiveActivity('la-rain-1');
      assert.equal(endedLa.state, 'ended');
      assert.equal(notif.getLiveActivities().length, 0);
      assert.equal(notif.getLiveActivities({ includeEnded: true }).length, 1);
      assert.throws(() => notif.updateLiveActivity('la-rain-1', { progress: 1 }), (e) => e.code === ERROR_CODES.EINVAL);

      // Dismiss & clearAll
      notif.dismiss(n1.id);
      assert.equal(notif.list().some((n) => n.id === n1.id), false);
      assert.equal(notif.list({ includeDismissed: true }).some((n) => n.id === n1.id), true);
      notif.clearAll();
      assert.equal(notif.list().length, 0);
    } finally {
      await kernel.shutdown();
    }
  });
});

// ============================================================================
// SUITE 10: os/compositor/compositor.mjs (F-029, F-030, F-031)
// ============================================================================

describe('Suite 10: os/compositor/compositor.mjs — Headless Display Server, Snap Layouts, Sync & Input Isolation (F-029, F-030, F-031)', () => {
  it('enforces maxWindows quota, dead-PID rejection, dual-mode surfaces, z-order/activeMenuBar, all 10 states & viewport reflow', () => {
    const bus = new KernelEventBus();
    const pm = new ProcessManager({ eventBus: bus });
    const comp = new Compositor({
      processManager: pm,
      eventBus: bus,
      viewport: { width: 1200, height: 800, insets: { top: 40, bottom: 60, left: 0, right: 0 } },
    });

    const p1 = pm.spawn({ name: 'mac-app', appId: 'macos.studio', platform: 'macos', quotas: { maxWindows: 2 }, executionContext: makeWorkExecContext() });
    const p2 = pm.spawn({ name: 'win-app', appId: 'win.notes', platform: 'windows', executionContext: makeWorkExecContext() });
    const deadP = pm.spawn({ name: 'dead-app', executionContext: makeWorkExecContext() });
    pm.kill(deadP.pid, 'SIGKILL');

    // Dead PID rejected BEFORE registerWindow
    assert.throws(() => comp.createWindow(deadP.pid, { title: 'Nope' }), (e) => e instanceof ProcessError && e.code === ERROR_CODES.EINVAL);
    assert.throws(() => comp.createWindow(999999, { title: 'Missing' }), (e) => e instanceof ProcessError && e.code === ERROR_CODES.ESRCH);

    const macMenu = [{ id: 'studio', label: 'Studio', items: [{ id: 'studio.build', label: 'Build' }] }];
    const w1 = comp.createWindow(p1.pid, {
      title: 'Studio',
      x: 100,
      y: 120,
      width: 500,
      height: 360,
      menuBar: macMenu,
      uiTree: { type: 'vbox', children: [{ type: 'text', text: 'v1' }] },
      drawOps: [{ op: 'clear', color: '#000' }],
    });
    const w2 = comp.createWindow(p1.pid, { title: 'Inspector' });

    // 3rd window exceeds maxWindows=2 -> QuotaExceededError(E_WINDOW_QUOTA)
    assert.throws(
      () => comp.createWindow(p1.pid, { title: 'OverQuota' }),
      (err) => err instanceof QuotaExceededError && err.code === ERROR_CODES.E_WINDOW_QUOTA
    );

    const w3 = comp.createWindow(p2.pid, { title: 'WinNotes', width: 400, height: 300 });
    assert.equal(comp.getSnapshot().focusedWindowId, w3.windowId);
    // w3 has no custom menuBar -> falls back to DEFAULT_MENU_BAR
    assert.equal(comp.getSnapshot().activeMenuBar[0].id, DEFAULT_MENU_BAR[0].id);

    // focusWindow switches zIndex & activeMenuBar
    const focusedW1 = comp.focusWindow(w1.windowId);
    assert.ok(focusedW1.zIndex > w3.zIndex);
    assert.equal(comp.getSnapshot().activeMenuBar[0].id, 'studio');

    // Dual-mode updateSurface monotonic surfaceRevision
    const r2 = comp.updateSurface(w1.windowId, {
      uiTree: { type: 'vbox', children: [{ type: 'text', text: 'v2' }] },
      appendDrawOps: [{ op: 'rect', x: 10, y: 10, w: 50, h: 50 }],
    });
    assert.equal(r2.surfaceRevision, 2);
    assert.equal(comp.getWindow(w1.windowId).surface.drawOps.length, 2);

    const r3 = comp.updateSurface(w1.windowId, { drawOps: [{ op: 'circle', x: 5, y: 5, r: 3 }] });
    assert.equal(r3.surfaceRevision, 3);
    assert.equal(comp.getWindow(w1.windowId).surface.drawOps.length, 1);

    // Move & resize update restoreBounds when normal
    comp.moveWindow(w1.windowId, 111, 222);
    comp.resizeWindow(w1.windowId, 555, 333);
    const savedNormal = comp.getWindow(w1.windowId).bounds;
    assert.deepEqual(savedNormal, { x: 111, y: 222, width: 555, height: 333 });

    // All 10 states incl. 6 Snap Layouts + chained restoreBounds preservation
    assert.equal(WINDOW_STATES.length, 10);
    // Work area: x=0, y=40, w=1200, h=700 (halfW=600, halfH=350)
    assert.deepEqual(comp.setWindowState(w1.windowId, 'snapped-left').bounds, { x: 0, y: 40, width: 600, height: 700 });
    assert.deepEqual(comp.setWindowState(w1.windowId, 'snapped-right').bounds, { x: 600, y: 40, width: 600, height: 700 });
    assert.deepEqual(comp.setWindowState(w1.windowId, 'snapped-tl').bounds, { x: 0, y: 40, width: 600, height: 350 });
    assert.deepEqual(comp.setWindowState(w1.windowId, 'snapped-tr').bounds, { x: 600, y: 40, width: 600, height: 350 });
    assert.deepEqual(comp.setWindowState(w1.windowId, 'snapped-bl').bounds, { x: 0, y: 390, width: 600, height: 350 });
    assert.deepEqual(comp.setWindowState(w1.windowId, 'snapped-br').bounds, { x: 600, y: 390, width: 600, height: 350 });
    assert.deepEqual(comp.setWindowState(w1.windowId, 'maximized').bounds, { x: 0, y: 40, width: 1200, height: 700 });
    assert.deepEqual(comp.setWindowState(w1.windowId, 'fullscreen').bounds, { x: 0, y: 0, width: 1200, height: 800 });

    // Viewport reflow dynamically adjusts snapped/fullscreen windows
    comp.setWindowState(w1.windowId, 'snapped-right');
    comp.setViewport(1600, 1000, { top: 50, bottom: 50, left: 0, right: 0 });
    assert.deepEqual(comp.getWindow(w1.windowId).bounds, { x: 800, y: 50, width: 800, height: 900 });

    // Returning to normal restores exact original savedNormal bounds across all chained transitions!
    assert.deepEqual(comp.setWindowState(w1.windowId, 'normal').bounds, savedNormal);

    // Minimizing shifts focus away
    comp.setWindowState(w1.windowId, 'minimized');
    assert.notEqual(comp.getSnapshot().focusedWindowId, w1.windowId);

    // Killing owning PID auto-destroys ALL its windows (surviving M1 pre-event pcb.windowIds.clear())
    pm.kill(p1.pid, 'SIGKILL');
    assert.equal(comp.getWindow(w1.windowId), null);
    assert.equal(comp.getWindow(w2.windowId), null);
    assert.ok(comp.getWindow(w3.windowId));
  });

  it('syncs shellMode bidirectionally with UnifiedConfigStore, isolates hostile deliverEvent & runs compositord', async () => {
    const dir = makeTempDir('omnios-m2-comp-');
    const kernel = new OmniKernel({ dbPath: path.join(dir, 'comp.sqlite') });
    const cfg = new UnifiedConfigStore({ kernel });
    const comp = new Compositor({ kernel, configStore: cfg, shellMode: 'hybrid' });
    assert.equal(comp.getSnapshot().shellMode, 'unified');
    assert.equal(normalizeShellMode('HYBRID'), 'unified');
    assert.deepEqual(SHELL_MODES, ['unified', 'windows', 'macos', 'ios', 'android']);

    registerConfigService(kernel.serviceManager, cfg, { kernel });
    registerCompositorService(kernel.serviceManager, comp, { deps: ['configd'] });
    await kernel.boot();

    try {
      assert.equal((await kernel.serviceManager.checkHealth('compositord')).healthy, true);

      // Bidirectional shellMode sync
      comp.setShellMode('ios');
      assert.equal(cfg.system.get('system.shellMode'), 'ios');
      cfg.system.set('system.shellMode', 'android');
      assert.equal(comp.getSnapshot().shellMode, 'android');

      // Fault-isolated dispatchInput across 5 hostile cases
      const inputErrors = [];
      kernel.eventBus.on('compositor:input_error', (e) => inputErrors.push(e));

      // 1. Sync throw
      const pSync = kernel.processManager.spawn({
        name: 'sync-throw',
        executionContext: makeWorkExecContext({
          onEvent() {
            throw new Error('sync boom');
          },
        }),
      });
      const wSync = comp.createWindow(pSync.pid, { title: 'SyncThrow' });
      const rSync = comp.dispatchInput(wSync.windowId, { type: 'click', targetId: 'btn' });
      assert.equal(rSync.delivered, false);

      // 2. Native rejected Promise
      const pAsync = kernel.processManager.spawn({
        name: 'async-reject',
        executionContext: makeWorkExecContext({
          onEvent() {
            return Promise.reject(new Error('native async reject'));
          },
        }),
      });
      const wAsync = comp.createWindow(pAsync.pid, { title: 'AsyncReject' });
      assert.equal(comp.dispatchInput(wAsync.windowId, { type: 'keydown', key: 'Enter' }).delivered, true);

      // 3. Cross-realm rejected Promise via node:vm
      const pRealm = kernel.processManager.spawn({
        name: 'realm-reject',
        executionContext: makeWorkExecContext({
          onEvent() {
            return vm.runInNewContext('Promise.reject(new Error("cross-realm reject"))');
          },
        }),
      });
      const wRealm = comp.createWindow(pRealm.pid, { title: 'RealmReject' });
      assert.equal(comp.dispatchInput(wRealm.windowId, { type: 'click' }).delivered, true);

      // 4. Hostile thenable with throwing `.then` getter
      const pThen = kernel.processManager.spawn({
        name: 'hostile-then',
        executionContext: makeWorkExecContext({
          onEvent() {
            return {
              get then() {
                throw new Error('then getter boom');
              },
            };
          },
        }),
      });
      const wThen = comp.createWindow(pThen.pid, { title: 'HostileThen' });
      assert.equal(comp.dispatchInput(wThen.windowId, { type: 'click' }).delivered, true);

      // 5. Throwing getter on executionContext.deliverEvent
      const pGet = kernel.processManager.spawn({
        name: 'hostile-getter',
        executionContext: {
          step: () => ({ status: 'YIELD', instructionsExecuted: 1 }),
          get deliverEvent() {
            throw new Error('deliverEvent getter boom');
          },
          getDebugState: () => ({}),
          dispose() {},
        },
      });
      const wGet = comp.createWindow(pGet.pid, { title: 'HostileGetter' });
      assert.equal(comp.dispatchInput(wGet.windowId, { type: 'click' }).delivered, false);

      // Flush microtask queue so async rejections settle into inputErrors (0 unhandled!)
      await new Promise((r) => setTimeout(r, 25));
      assert.ok(inputErrors.length >= 5);
    } finally {
      await kernel.shutdown();
    }
  });
});

// ============================================================================
// SUITE 11: os/pkg/zip.mjs (F-032)
// ============================================================================

describe('Suite 11: os/pkg/zip.mjs — PKZIP/ZIP64 Codec, Python 3 Interop & Security Defenses (F-032)', () => {
  it('passes external Python 3 zipfile.ZipFile.testzip() == None bidirectional round-trip (Classic, ZIP64, Bit 3, Bit 11, non-zero byteOffset)', () => {
    const utf8Name = 'docs/café-🚀-日本語.txt';
    const bigText = 'OmniOS cross-platform ZIP payload! '.repeat(200);
    const entries = [
      { name: 'dir/', isDirectory: true },
      { name: 'empty.bin', data: new Uint8Array(0), method: ZIP_METHODS.STORE },
      { name: 'store.bin', data: new Uint8Array([0, 1, 2, 3, 253, 254, 255]), method: ZIP_METHODS.STORE },
      { name: utf8Name, data: bigText, method: ZIP_METHODS.DEFLATE },
    ];

    const classicZip = createZip(entries, { comment: 'OmniOS Classic' });
    const zip64Buf = createZip(entries, { zip64: true, comment: 'OmniOS ZIP64' });

    // JS -> Python 3 verification + Python 3 -> JS archive generation (including streaming Data Descriptor Bit 3 & ZIP64)
    const pyOut = runPython(
      `
import sys, io, json, base64, zipfile

inp = json.loads(sys.stdin.read())
for key in ("classic", "zip64"):
    raw = base64.b64decode(inp[key])
    with zipfile.ZipFile(io.BytesIO(raw), "r") as zf:
        bad = zf.testzip()
        assert bad is None, f"{key} testzip failed on {bad}"
        assert zf.read("empty.bin") == b""
        assert zf.read("store.bin") == bytes([0, 1, 2, 3, 253, 254, 255])
        assert zf.read(inp["utf8Name"]).decode("utf-8") == inp["bigText"]

# Python -> JS: generate streaming Data Descriptor Bit 3 archive (non-seekable pipe!)
class UnseekableStream(io.RawIOBase):
    def __init__(self):
        self.chunks = []
    def writable(self): return True
    def seekable(self): return False
    def write(self, b):
        self.chunks.append(bytes(b))
        return len(b)
    def getvalue(self):
        return b"".join(self.chunks)

stream = UnseekableStream()
with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    zf.writestr("streamed/utf8-λ.txt", "Streamed with Bit 3 Data Descriptor! " * 50)
    zi = zipfile.ZipInfo("streamed/stored.bin")
    zi.compress_type = zipfile.ZIP_STORED
    zf.writestr(zi, bytes(range(32)))

# Python -> JS: ZIP64 archive
z64_bio = io.BytesIO()
with zipfile.ZipFile(z64_bio, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    with zf.open("z64/hello.txt", "w", force_zip64=True) as fh:
        fh.write(("ZIP64 from Python 3! " * 60).encode("utf-8"))

print(json.dumps({
    "ok": True,
    "ddBit3": base64.b64encode(stream.getvalue()).decode("ascii"),
    "pyZip64": base64.b64encode(z64_bio.getvalue()).decode("ascii"),
}))
      `,
      {
        classic: Buffer.from(classicZip).toString('base64'),
        zip64: Buffer.from(zip64Buf).toString('base64'),
        utf8Name,
        bigText,
      }
    );

    const parsed = JSON.parse(pyOut);
    assert.equal(parsed.ok, true);

    // Read Python Data Descriptor Bit 3 archive using a non-zero byteOffset subarray!
    const ddRaw = Buffer.from(parsed.ddBit3, 'base64');
    const padded = new Uint8Array(ddRaw.byteLength + 37);
    padded.fill(0x55);
    padded.set(ddRaw, 19);
    const subview = padded.subarray(19, 19 + ddRaw.byteLength);
    assert.equal(subview.byteOffset, 19);

    const ddZip = readZip(subview);
    assert.ok((ddZip.entries.get('streamed/utf8-λ.txt').flags & ZIP_FLAGS.DATA_DESCRIPTOR) !== 0);
    assert.equal(ddZip.readText('streamed/utf8-λ.txt'), 'Streamed with Bit 3 Data Descriptor! '.repeat(50));
    assert.deepEqual(ddZip.readBytes('streamed/stored.bin'), Uint8Array.from({ length: 32 }, (_, i) => i));

    // Read Python ZIP64 archive
    const z64Raw = Buffer.from(parsed.pyZip64, 'base64');
    const z64Arc = readZip(z64Raw);
    assert.equal(z64Arc.readText('z64/hello.txt'), 'ZIP64 from Python 3! '.repeat(60));
  });

  it('tolerates APK Signing Block v2/v3 and fake EOCD in comment, and blocks CRC corruption, ZIP-slip, ZIP-bombs & duplicate CD', () => {
    // 1. APK Signing Block v2/v3 ("APK Sig Block 42") between local entries and CD
    const baseApk = createZip([
      { name: 'AndroidManifest.xml', data: '<manifest/>' },
      { name: 'classes.dex', data: 'dex-bytes' },
    ]);
    const idx = listZipEntries(baseApk);
    const cdOffset = idx.centralDirOffset;
    const sigBlock = new Uint8Array(48);
    const sbView = new DataView(sigBlock.buffer);
    sbView.setBigUint64(0, 40n, true); // size of block excluding first 8 bytes
    sbView.setBigUint64(24, 40n, true); // trailing size
    sigBlock.set(new TextEncoder().encode('APK Sig Block 42'), 32);

    const apkWithSig = new Uint8Array(baseApk.byteLength + sigBlock.byteLength);
    apkWithSig.set(baseApk.subarray(0, cdOffset), 0);
    apkWithSig.set(sigBlock, cdOffset);
    apkWithSig.set(baseApk.subarray(cdOffset), cdOffset + sigBlock.byteLength);
    // Patch EOCD centralDirOffset (+sigBlock.byteLength)
    const eocdOff = apkWithSig.byteLength - 22;
    const apkView = new DataView(apkWithSig.buffer);
    apkView.setUint32(eocdOff + 16, cdOffset + sigBlock.byteLength, true);

    const parsedApk = readZip(apkWithSig);
    assert.equal(parsedApk.hasApkSigningBlock, true);
    assert.equal(parsedApk.readText('AndroidManifest.xml'), '<manifest/>');

    // 2. Fake EOCD inside Uint8Array archive comment (verify exact bytes written & skipped during scan)
    const fakeCommentShort = new Uint8Array([0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]);
    const withFakeShort = createZip([{ name: 'ok.txt', data: 'clean' }], { comment: fakeCommentShort });
    const shortIdx = listZipEntries(withFakeShort);
    const shortView = new DataView(withFakeShort.buffer, withFakeShort.byteOffset, withFakeShort.byteLength);
    const shortCommentLen = shortView.getUint16(shortIdx.eocdOffset + 20, true);
    assert.equal(shortCommentLen, fakeCommentShort.byteLength);
    assert.ok(shortCommentLen > 0);
    assert.deepEqual(withFakeShort.subarray(shortIdx.eocdOffset + 22), fakeCommentShort);
    assert.equal(readZip(withFakeShort).readText('ok.txt'), 'clean');

    // 24-byte Uint8Array comment embedding a fake PK\x05\x06 EOCD with non-matching commentLen (0x0099)
    // so findEocd() backward scan actively encounters and skips the fake signature before finding real EOCD
    const fakeCommentLong = new Uint8Array([
      0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00,
      0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x99, 0x00, 0x41, 0x42,
    ]);
    const withFakeLong = createZip([{ name: 'ok.txt', data: 'clean-long' }], { comment: fakeCommentLong });
    const longIdx = listZipEntries(withFakeLong);
    const longView = new DataView(withFakeLong.buffer, withFakeLong.byteOffset, withFakeLong.byteLength);
    const longCommentLen = longView.getUint16(longIdx.eocdOffset + 20, true);
    assert.equal(longCommentLen, fakeCommentLong.byteLength);
    assert.deepEqual(withFakeLong.subarray(longIdx.eocdOffset + 22), fakeCommentLong);
    assert.equal(readZip(withFakeLong).readText('ok.txt'), 'clean-long');

    // 3. Strict CRC-32 check -> E_CRC_MISMATCH
    const goodZip = createZip([{ name: 'crc.txt', data: 'integrity-checked-data', method: ZIP_METHODS.STORE }]);
    const badCrcZip = goodZip.slice();
    const entryMeta = listZipEntries(badCrcZip).entries.get('crc.txt');
    const dataPos = entryMeta.localHeaderOffset + 30 + 'crc.txt'.length;
    badCrcZip[dataPos] ^= 0xff;
    assert.throws(
      () => extractZipEntry(badCrcZip, entryMeta),
      (err) => err instanceof FormatError && err.code === ZIP_ERROR_CODES.E_CRC_MISMATCH
    );

    // 4. ZIP-slip (craft raw ZIP with '../escape.txt' in both LFH and CD)
    const slipBase = createZip([{ name: 'aa/escape.txt', data: 'evil', method: ZIP_METHODS.STORE }]);
    const slipStr = new TextEncoder().encode('aa/escape.txt');
    const dotDot = new TextEncoder().encode('../escape.txt');
    const slipZip = slipBase.slice();
    for (let i = 0; i <= slipZip.length - slipStr.length; i += 1) {
      let match = true;
      for (let j = 0; j < slipStr.length; j += 1) {
        if (slipZip[i + j] !== slipStr[j]) { match = false; break; }
      }
      if (match) slipZip.set(dotDot, i);
    }
    assert.throws(
      () => listZipEntries(slipZip),
      (err) => err instanceof FormatError && err.code === ZIP_ERROR_CODES.E_PATH_TRAVERSAL
    );

    // 5. ZIP-bomb: ratio cap & byte cap
    const zeros = new Uint8Array(256 * 1024);
    const bombZip = createZip([{ name: 'zeros.bin', data: zeros, method: ZIP_METHODS.DEFLATE }]);
    assert.throws(
      () => readZip(bombZip, { maxCompressionRatio: 20 }),
      (err) => err instanceof FormatError && err.code === ZIP_ERROR_CODES.E_ARCHIVE_BOMB
    );
    assert.throws(
      () => readZip(bombZip, { maxUncompressedBytes: 4096, maxCompressionRatio: 10000 }),
      (err) => err instanceof FormatError && err.code === ZIP_ERROR_CODES.E_ARCHIVE_BOMB
    );

    // 6. Lying-header inflated size bomb (CD claims uncompressedSize=16 while deflated payload inflates to 65536!)
    const bigPayload = new Uint8Array(65536);
    const deflated = zlib.deflateRawSync(bigPayload);
    const lyingBase = createZip([{ name: 'lie.bin', data: bigPayload, method: ZIP_METHODS.DEFLATE }]);
    const lyingIdx = listZipEntries(lyingBase, { maxCompressionRatio: 100000 });
    const lyingZip = lyingBase.slice();
    const lView = new DataView(lyingZip.buffer);
    // Patch CDFH uncompressedSize at centralDirOffset + 24 down to 16 bytes
    lView.setUint32(lyingIdx.centralDirOffset + 24, 16, true);
    lView.setUint32(lyingIdx.centralDirOffset + 16, crc32(bigPayload.subarray(0, 16)), true);
    assert.ok(deflated.byteLength > 0);
    assert.throws(
      () => {
        const arc = readZip(lyingZip, { maxCompressionRatio: 100000 });
        arc.readBytes('lie.bin');
      },
      (err) => err instanceof FormatError && err.code === ZIP_ERROR_CODES.E_ARCHIVE_BOMB
    );

    // 7. Overlapping byte ranges (entry #1's compressed data range extends past entry #2's localHeaderOffset) -> E_ARCHIVE_BOMB
    const twoFileZip = createZip([
      { name: 'a.txt', data: 'alpha-payload', method: ZIP_METHODS.STORE },
      { name: 'b.txt', data: 'bravo-payload', method: ZIP_METHODS.STORE },
    ]);
    const twoIdx = listZipEntries(twoFileZip);
    const overlapZip = twoFileZip.slice();
    const oView = new DataView(overlapZip.buffer);
    const firstCdfh = twoIdx.centralDirOffset;
    assert.equal(oView.getUint32(firstCdfh, true), 0x02014b50);
    // Extend entry #1's compressedSize (+20) so its dataEnd overlaps entry #2's localHeaderOffset
    const expandedSize = twoIdx.entries.get('b.txt').localHeaderOffset + 8;
    oView.setUint32(firstCdfh + 20, expandedSize, true);
    oView.setUint32(firstCdfh + 24, expandedSize, true);
    assert.throws(
      () => listZipEntries(overlapZip),
      (err) => err instanceof FormatError && err.code === ZIP_ERROR_CODES.E_ARCHIVE_BOMB
    );

    // 8. Duplicate Central Directory entry name -> E_MALFORMED_ZIP
    const dupZip = twoFileZip.slice();
    const dupPos = twoIdx.centralDirOffset + 46 + 5 + 46; // 'b.txt' in 2nd CDFH
    dupZip[dupPos] = 'a'.charCodeAt(0); // rename 'b.txt' -> 'a.txt'
    assert.throws(
      () => listZipEntries(dupZip),
      (err) => err instanceof FormatError && err.code === ZIP_ERROR_CODES.E_MALFORMED_ZIP
    );
  });
});

// ============================================================================
// SUITE 12: os/pkg/format-detector.mjs (F-033)
// ============================================================================

describe('Suite 12: os/pkg/format-detector.mjs — Pure Byte-Level 12-Format Auto-Detector & Fuzz Safety (F-033)', () => {
  it('detects all 12 supported package/binary formats plus unknown and guards Java .class (0xCAFEBABE)', () => {
    const detector = new FormatDetector();

    const cases = [
      { buf: buildApkFixture(), expected: PACKAGE_FORMATS.ANDROID_APK, platform: 'android' },
      { buf: buildPeFixture({ pe32Plus: true }), expected: PACKAGE_FORMATS.WINDOWS_PE, platform: 'windows' },
      { buf: buildPeFixture({ pe32Plus: false, isDll: true }), expected: PACKAGE_FORMATS.WINDOWS_PE, platform: 'windows' },
      { buf: buildMsixFixture(), expected: PACKAGE_FORMATS.WINDOWS_MSIX, platform: 'windows' },
      { buf: buildMsiCfbfFixture(), expected: PACKAGE_FORMATS.WINDOWS_MSI, platform: 'windows' },
      { buf: new TextEncoder().encode('@echo off\r\nset /a X=1+2\r\necho %X%\r\n'), expected: PACKAGE_FORMATS.WINDOWS_BAT, platform: 'windows' },
      { buf: buildIpaFixture(), expected: PACKAGE_FORMATS.IOS_IPA, platform: 'ios' },
      { buf: buildMacosAppFixture(), expected: PACKAGE_FORMATS.MACOS_APP, platform: 'macos' },
      { buf: buildMachOFixture('macho64'), expected: PACKAGE_FORMATS.MACOS_MACHO, platform: 'macos' },
      { buf: buildMachOFixture('macho32'), expected: PACKAGE_FORMATS.MACOS_MACHO, platform: 'macos' },
      { buf: buildMachOFixture('fat32'), expected: PACKAGE_FORMATS.MACOS_MACHO, platform: 'macos' },
      { buf: buildMachOFixture('fat64'), expected: PACKAGE_FORMATS.MACOS_MACHO, platform: 'macos' },
      { buf: buildDmgFixture(), expected: PACKAGE_FORMATS.MACOS_DMG, platform: 'macos' },
      { buf: buildPkgXarFixture(), expected: PACKAGE_FORMATS.MACOS_PKG, platform: 'macos' },
      { buf: buildUappFixture(), expected: PACKAGE_FORMATS.UNIVERSAL_UAPP, platform: 'universal' },
      { buf: buildWasmFixture(), expected: PACKAGE_FORMATS.UNIVERSAL_WASM, platform: 'universal' },
    ];

    for (const c of cases) {
      const res = detector.detect(c.buf, ''); // Pure byte detection (no filenameHint!)
      assert.equal(res.format, c.expected, `Failed pure-byte detection for ${c.expected}`);
      assert.equal(res.platform, c.platform);
      assert.ok(typeof res.magicHex === 'string' && res.magicHex.length > 0);
    }

    // Verify exact Apple UDIF koly spec offsets (+0xD8 XMLOffset, +0xE0 XMLLength)
    const dmgDet = detector.detect(buildDmgFixture(), '');
    assert.equal(dmgDet.format, PACKAGE_FORMATS.MACOS_DMG);
    assert.equal(dmgDet.details.xmlOffset, 128);
    assert.equal(dmgDet.details.xmlLength, 64);

    // Java .class guard: 0xCAFEBABE with majorVersion 52 & 65 MUST NOT be misclassified as Mach-O Fat!
    assert.equal(detectFormat(buildJavaClassFixture(52), 'Hello.class').format, PACKAGE_FORMATS.UNKNOWN);
    assert.equal(detectFormat(buildJavaClassFixture(65), 'Main.class').format, PACKAGE_FORMATS.UNKNOWN);

    // Unknown inputs
    assert.equal(detectFormat(new Uint8Array(0)).format, PACKAGE_FORMATS.UNKNOWN);
    assert.equal(detectFormat(new TextEncoder().encode('just plain text')).format, PACKAGE_FORMATS.UNKNOWN);
    assert.equal(detectFormat(createZip([{ name: 'notes.txt', data: 'not an app' }])).format, PACKAGE_FORMATS.UNKNOWN);
  });

  it('never crashes on truncated slices of every format or random fuzz buffers', () => {
    const samples = [
      buildApkFixture(),
      buildPeFixture(),
      buildMachOFixture('fat32'),
      buildDmgFixture(),
      buildPkgXarFixture(),
      buildMsiCfbfFixture(),
      buildWasmFixture(),
    ];
    for (const s of samples) {
      for (const cut of [0, 1, 2, 4, 7, 8, 16, 28, 32, 63, Math.floor(s.byteLength / 2)]) {
        if (cut <= s.byteLength) {
          const r = detectFormat(s.subarray(0, cut));
          assert.ok(typeof r.format === 'string');
        }
      }
    }
    for (let i = 0; i < 60; i += 1) {
      const rand = crypto.randomBytes((i * 19) % 257);
      const r = detectFormat(rand);
      assert.ok(typeof r.format === 'string');
    }
  });
});

// ============================================================================
// SUITE 13: os/pkg/package-manager.mjs & Full 6-Daemon OmniKernel Integration (F-034, F-035)
// ============================================================================

describe('Suite 13: os/pkg/package-manager.mjs & Full 6-Daemon OmniKernel End-to-End Integration (F-034, F-035)', () => {
  function wireFullOsStack(dbPath) {
    const kernel = new OmniKernel({ dbPath });
    const users = new UserManager({ kernel });
    const permissions = new PermissionBroker({ kernel, userManager: users });
    const vfs = new VFS({ kernel, userManager: users });
    const configStore = new UnifiedConfigStore({ kernel });
    const ipc = new IPCManager({ eventBus: kernel.eventBus, processManager: kernel.processManager });
    const intentRouter = new IntentRouter({
      eventBus: kernel.eventBus,
      processManager: kernel.processManager,
      configStore,
    });
    const clipboard = new SharedClipboard({ eventBus: kernel.eventBus });
    const notifications = new NotificationCenter({
      eventBus: kernel.eventBus,
      configStore,
      processManager: kernel.processManager,
    });
    const compositor = new Compositor({ kernel, configStore });
    const pkgManager = new PackageManager({
      kernel,
      vfs,
      configStore,
      ipc,
      intentRouter,
      clipboard,
      notifications,
      users,
      permissions,
      compositor,
    });

    intentRouter.setLauncher((appId, { intent }) => pkgManager.launch(appId, { intent }));

    // Register ALL 6 M2 daemons with real dependency graph
    registerSecurityService(kernel.serviceManager, { userManager: users, permissionBroker: permissions, kernel, deps: [] });
    registerVfsService(kernel.serviceManager, vfs, { kernel, deps: ['securityd'] });
    registerConfigService(kernel.serviceManager, configStore, { kernel, deps: [] });
    registerIpcBrokerService(kernel.serviceManager, { ipc, router: intentRouter, clipboard, notifications, deps: ['configd'] });
    registerCompositorService(kernel.serviceManager, compositor, { deps: ['configd'] });
    registerPackageService(kernel.serviceManager, pkgManager, { deps: ['securityd', 'vfsd', 'ipc-brokerd', 'compositord'] });

    return {
      kernel,
      users,
      permissions,
      vfs,
      configStore,
      ipc,
      intentRouter,
      clipboard,
      notifications,
      compositor,
      pkgManager,
    };
  }

  it('boots all 6 M2 daemons on OmniKernel, runs full ospm lifecycle, enforces native perms/intents/compositor/sandbox, survives panic+recover & DB reopen', async () => {
    const dir = makeTempDir('omnios-m2-e2e-');
    const dbPath = path.join(dir, 'omnios-full.sqlite');
    const os1 = wireFullOsStack(dbPath);

    // Register genuine Android & Windows runtimes implementing Contract 5
    const androidRuntime = {
      platform: 'android',
      inspectPackage(_bytes, _hint, detection) {
        return {
          format: detection.format,
          platform: 'android',
          arch: 'dalvik',
          appId: 'com.omnios.calc',
          name: 'OmniCalc',
          version: '2.1.0',
          entryPoint: 'com.omnios.calc.MainActivity',
          permissions: ['android.permission.CAMERA', 'android.permission.READ_EXTERNAL_STORAGE'],
          intents: [{ action: 'view', scheme: 'omnicalc', mimeTypes: ['text/x-expr'], priority: 10 }],
        };
      },
      createExecutionContext(pcb, appRecord, services, launchOptions) {
        const win = services.compositor.createWindow(pcb.pid, {
          appId: appRecord.appId,
          platform: appRecord.platform,
          title: appRecord.name,
          uiTree: { type: 'text', text: `Intent=${launchOptions.intent?.uri ?? 'none'}` },
        });
        return makeWorkExecContext({
          totalWork: 10000,
          onEvent(evt) {
            services.compositor.updateSurface(win.windowId, {
              uiTree: { type: 'text', text: `LastEvent=${evt.type}` },
            });
          },
        });
      },
    };

    const windowsRuntime = {
      platform: 'windows',
      inspectPackage(_bytes, _hint, detection) {
        return {
          format: detection.format,
          platform: 'windows',
          arch: 'x86_64',
          appId: 'win.admin.tool',
          name: 'WinAdminTool',
          version: '1.0.0',
          entryPoint: 'WinAdminTool.exe',
          permissions: ['requireAdministrator', 'toastNotifications'],
          intents: [{ action: 'view', extensions: ['.log'] }],
        };
      },
      createExecutionContext(pcb, appRecord, services) {
        services.compositor.createWindow(pcb.pid, {
          appId: appRecord.appId,
          platform: 'windows',
          title: appRecord.name,
        });
        return makeWorkExecContext({ totalWork: 20 });
      },
    };

    os1.pkgManager.registerRuntime('android', androidRuntime);
    os1.pkgManager.registerRuntime('windows', windowsRuntime);

    // 1. Boot full 6-daemon kernel
    const bootReport = await os1.kernel.boot();
    assert.equal(bootReport.status, KERNEL_STATES.RUNNING);
    const diag = os1.kernel.getDiagnostics();
    const svcByName = new Map(diag.services.map((s) => [s.name, s]));
    for (const svcName of ['securityd', 'vfsd', 'configd', 'ipc-brokerd', 'compositord', 'pkgd']) {
      assert.equal(svcByName.get(svcName)?.state, 'RUNNING', `Daemon ${svcName} must be RUNNING`);
      assert.equal((await os1.kernel.serviceManager.checkHealth(svcName)).healthy, true);
    }

    // 2. Register App Hub catalog entry & inspect from VFS path
    const apkBytes = buildApkFixture([{ name: 'res/layout/main.xml', data: '<LinearLayout/>' }]);
    const apkSha = crypto.createHash('sha256').update(apkBytes).digest('hex');
    os1.vfs.writeFile('/home/user/Downloads/calc.apk', apkBytes, { uid: 1000, gid: 1000 });

    os1.pkgManager.registerCatalogEntry({
      appId: 'com.omnios.calc',
      name: 'OmniCalc',
      platform: 'android',
      format: PACKAGE_FORMATS.ANDROID_APK,
      version: '2.1.0',
      sha256: apkSha,
      sizeBytes: apkBytes.byteLength,
    });
    assert.equal(os1.pkgManager.getCatalog({ platform: 'android' })[0].installed, false);

    const inspected = await os1.pkgManager.inspect('/home/user/Downloads/calc.apk');
    assert.equal(inspected.appId, 'com.omnios.calc');
    assert.equal(inspected.sha256, apkSha);
    assert.equal(inspected.runtimeAvailable, true);

    // 3. SHA-256 mismatch rejected
    await assert.rejects(
      () => os1.pkgManager.install(apkBytes, { expectedSha256: '0'.repeat(64) }),
      (err) => err instanceof SecurityError && err.code === 'E_HASH_MISMATCH'
    );

    // 4. Install Android APK + Windows MSIX (verifying multi-cap native permissions!)
    const installedApk = await os1.pkgManager.install('/home/user/Downloads/calc.apk', {
      expectedSha256: apkSha,
      grantAll: true,
    });
    assert.equal(installedApk.appId, 'com.omnios.calc');
    assert.ok(installedApk.uid >= SANDBOX_UID_BASE);
    assert.equal(os1.vfs.readFile(`${installedApk.installDir}/res/layout/main.xml`, { encoding: 'utf8' }), '<LinearLayout/>');
    assert.equal(os1.vfs.stat(installedApk.dataDir).uid, installedApk.uid);
    assert.equal(os1.pkgManager.getCatalog({ platform: 'android' })[0].installed, true);

    // Native Android permissions were mapped and granted on real PermissionBroker!
    assert.equal((await os1.permissions.checkPermission({ appId: 'com.omnios.calc', platform: 'android', nativePermission: 'android.permission.CAMERA' })).granted, true);
    assert.equal((await os1.permissions.checkPermission({ appId: 'com.omnios.calc', capability: CAPABILITIES.FS_READ_USER })).granted, true);

    // Duplicate install without overwrite -> EEXIST
    await assert.rejects(() => os1.pkgManager.install(apkBytes), (e) => e.code === ERROR_CODES.EEXIST);

    const msixBytes = buildMsixFixture();
    const installedWin = await os1.pkgManager.install(msixBytes, { grantAll: true });
    assert.equal(installedWin.appId, 'win.admin.tool');
    // Multi-cap Windows requireAdministrator expanded to BOTH registry.system.write & fs.write.system!
    assert.equal((await os1.permissions.checkPermission({ appId: 'win.admin.tool', capability: CAPABILITIES.REGISTRY_SYSTEM_WRITE })).granted, true);
    assert.equal((await os1.permissions.checkPermission({ appId: 'win.admin.tool', capability: CAPABILITIES.FS_WRITE_SYSTEM })).granted, true);
    assert.equal((await os1.permissions.checkPermission({ appId: 'win.admin.tool', capability: CAPABILITIES.NOTIFICATIONS_POST })).granted, true);

    // Sandbox isolation between installed Android app and installed Windows app in VFS
    os1.vfs.writeFile(`${installedApk.dataDir}/state.json`, '{"v":1}', { uid: installedApk.uid, gid: installedApk.gid });
    assert.throws(
      () => os1.vfs.readFile(`${installedApk.dataDir}/state.json`, { uid: installedWin.uid, gid: installedWin.gid }),
      (err) => err instanceof VfsError && err.code === ERROR_CODES.EACCES
    );

    // 5. IntentRouter cold-launches installed APK -> spawns PID, creates Compositor window, runs Scheduler!
    const dispatched = await os1.intentRouter.dispatch({ action: 'view', uri: 'omnicalc://sqrt/144' });
    assert.equal(dispatched.status, 'DELIVERED');
    assert.equal(dispatched.targetAppId, 'com.omnios.calc');
    assert.equal(dispatched.launched, true);
    assert.ok(typeof dispatched.pid === 'number');

    const windows = os1.compositor.listWindows({ pid: dispatched.pid });
    assert.equal(windows.length, 1);
    assert.equal(windows[0].surface.uiTree.text, 'Intent=omnicalc://sqrt/144');

    // Dispatch compositor input directly to launched app & step scheduler
    os1.compositor.dispatchInput(windows[0].windowId, { type: 'click', targetId: 'eq' });
    assert.equal(os1.compositor.getWindow(windows[0].windowId).surface.uiTree.text, 'LastEvent=click');
    const stepRes = os1.kernel.scheduler.step(1);
    assert.ok(stepRes.instructionsExecuted > 0);

    // 6. stop() kills process & auto-closes Compositor window
    const stopRes = os1.pkgManager.stop('com.omnios.calc');
    assert.deepEqual(stopRes.stoppedPids, [dispatched.pid]);
    assert.equal(os1.compositor.listWindows({ pid: dispatched.pid }).length, 0);

    // 7. Kernel panic & safe recovery keeps all 6 daemons healthy and preserves installed packages!
    os1.kernel.panic('E_TEST_PANIC', 'Simulated panic for M2 recovery check');
    assert.equal(os1.kernel.state, KERNEL_STATES.PANIC);
    const recReport = await os1.kernel.recover();
    assert.equal(recReport.status, KERNEL_STATES.RUNNING);
    assert.equal(os1.pkgManager.list().length, 2);
    assert.ok(os1.pkgManager.get('com.omnios.calc'));
    for (const svcName of ['securityd', 'vfsd', 'configd', 'ipc-brokerd', 'compositord', 'pkgd']) {
      assert.equal((await os1.kernel.serviceManager.checkHealth(svcName)).healthy, true);
    }

    await os1.kernel.shutdown();

    // 8. Reopen brand-new OmniKernel + 6 daemons from same SQLite DB & verify persistence + uninstall(purgeData)
    const os2 = wireFullOsStack(dbPath);
    os2.pkgManager.registerRuntime('android', androidRuntime);
    os2.pkgManager.registerRuntime('windows', windowsRuntime);
    await os2.kernel.boot();
    try {
      assert.equal(os2.pkgManager.list().length, 2);
      assert.equal(os2.pkgManager.list({ platform: 'android' }).length, 1);
      assert.equal(os2.pkgManager.get('com.omnios.calc').uid, installedApk.uid);
      assert.equal(os2.vfs.readFile(`${installedApk.dataDir}/state.json`, { encoding: 'utf8', uid: 0, gid: 0 }), '{"v":1}');

      // Persisted intents MUST be auto-re-registered into IntentRouter on SQLite DB reopen!
      const reopenedCalcIntents = os2.intentRouter.resolve({ action: 'view', uri: 'omnicalc://sqrt/144' });
      assert.equal(reopenedCalcIntents.length, 1);
      assert.equal(reopenedCalcIntents[0].appId, 'com.omnios.calc');
      const reopenedWinIntents = os2.intentRouter.resolve({ action: 'view', uri: 'file:///home/user/boot.log' });
      assert.equal(reopenedWinIntents.length, 1);
      assert.equal(reopenedWinIntents[0].appId, 'win.admin.tool');

      // Launch before uninstalling to test running-app teardown during uninstall
      const launch2 = await os2.pkgManager.launch('com.omnios.calc');
      assert.equal(os2.compositor.listWindows({ pid: launch2.pid }).length, 1);

      const uninst = await os2.pkgManager.uninstall('com.omnios.calc', { purgeData: true });
      assert.equal(uninst.removed, true);
      assert.equal(uninst.purgedData, true);
      assert.deepEqual(uninst.stoppedPids, [launch2.pid]);

      // All artifacts purged cleanly (including reopened intents)
      assert.equal(os2.pkgManager.get('com.omnios.calc'), null);
      assert.equal(os2.intentRouter.resolve({ action: 'view', uri: 'omnicalc://sqrt/144' }).length, 0);
      assert.equal(os2.compositor.listWindows({ pid: launch2.pid }).length, 0);
      assert.throws(() => os2.vfs.stat(installedApk.installDir), (e) => e.code === ERROR_CODES.ENOENT);
      assert.throws(() => os2.vfs.stat(installedApk.dataDir), (e) => e.code === ERROR_CODES.ENOENT);
      assert.equal(os2.users.getUserByAppId('com.omnios.calc'), null);
      assert.equal(os2.permissions.listGrants('com.omnios.calc').length, 0);
      assert.equal(os2.pkgManager.getCatalog({ platform: 'android' })[0].installed, false);
    } finally {
      await os2.kernel.shutdown();
    }
  });

  it('cleans up orphan PCB & window on failed launch() and rejects malformed/ZIP-slip packages safely', async () => {
    const dir = makeTempDir('omnios-m2-fault-');
    const osStack = wireFullOsStack(path.join(dir, 'fault.sqlite'));

    osStack.pkgManager.registerRuntime('universal', {
      platform: 'universal',
      inspectPackage(_bytes, _hint, detection) {
        return {
          format: detection.format,
          platform: 'universal',
          arch: 'wasm',
          appId: 'universal.crasher',
          name: 'Crasher',
          version: '0.1.0',
        };
      },
      createExecutionContext(pcb, appRecord, services) {
        // Creates a Compositor window, then crashes before returning IExecutionContext!
        services.compositor.createWindow(pcb.pid, { appId: appRecord.appId, title: 'OrphanWin' });
        throw new Error('Runtime initialization failed mid-launch');
      },
    });

    await osStack.kernel.boot();
    try {
      const uapp = buildUappFixture();
      await osStack.pkgManager.install(uapp);

      const beforeActive = osStack.kernel.processManager
        .getAll()
        .filter((p) => p.state !== PROCESS_STATES.ZOMBIE && p.state !== PROCESS_STATES.TERMINATED).length;

      await assert.rejects(
        () => osStack.pkgManager.launch('universal.crasher'),
        /Runtime initialization failed mid-launch/
      );

      // Zero orphan active PCBs AND zero orphan Compositor windows!
      const afterActive = osStack.kernel.processManager
        .getAll()
        .filter((p) => p.state !== PROCESS_STATES.ZOMBIE && p.state !== PROCESS_STATES.TERMINATED).length;
      assert.equal(afterActive, beforeActive);
      assert.equal(osStack.compositor.listWindows().length, 0);

      // Malformed / unknown binary rejected
      await assert.rejects(
        () => osStack.pkgManager.inspect(new Uint8Array([0x01, 0x02, 0x03, 0x04])),
        (err) => err instanceof FormatError && err.code === 'E_UNKNOWN_FORMAT'
      );

      // ZIP-slip package rejected at inspect/install time with E_PATH_TRAVERSAL
      const base = createZip([
        { name: 'omnios.manifest.json', data: '{}' },
        { name: 'aa/pwn.txt', data: 'bad', method: ZIP_METHODS.STORE },
      ]);
      const slip = base.slice();
      const fromBytes = new TextEncoder().encode('aa/pwn.txt');
      const toBytes = new TextEncoder().encode('../pwn.txt');
      for (let i = 0; i <= slip.length - fromBytes.length; i += 1) {
        let ok = true;
        for (let j = 0; j < fromBytes.length; j += 1) {
          if (slip[i + j] !== fromBytes[j]) { ok = false; break; }
        }
        if (ok) slip.set(toBytes, i);
      }
      await assert.rejects(
        () => osStack.pkgManager.install(slip),
        (err) => err instanceof FormatError && err.code === ERROR_CODES.E_PATH_TRAVERSAL
      );
    } finally {
      await osStack.kernel.shutdown();
    }
  });
});

// ============================================================================
// SUITE 14: Iteration 2 Hardening & Security Regressions (A1–A10 & B1–B6)
// ============================================================================

describe('Suite 14: Iteration 2 Hardening & Security Regressions (A1–A10 & B1–B6)', () => {
  function makeHostileError(tag = 'hostile') {
    const err = {};
    Object.defineProperty(err, 'name', {
      enumerable: true,
      get() {
        throw new Error(`${tag} name getter boom`);
      },
    });
    Object.defineProperty(err, 'message', {
      enumerable: true,
      get() {
        throw new Error(`${tag} message getter boom`);
      },
    });
    Object.defineProperty(err, 'code', {
      enumerable: true,
      get() {
        throw new Error(`${tag} code getter boom`);
      },
    });
    return err;
  }

  function wireStack(dbPath) {
    const kernel = new OmniKernel({ dbPath });
    const users = new UserManager({ kernel });
    const permissions = new PermissionBroker({ kernel, userManager: users });
    const vfs = new VFS({ kernel, userManager: users });
    const configStore = new UnifiedConfigStore({ kernel });
    const ipc = new IPCManager({ eventBus: kernel.eventBus, processManager: kernel.processManager });
    const intentRouter = new IntentRouter({
      eventBus: kernel.eventBus,
      processManager: kernel.processManager,
      configStore,
    });
    const clipboard = new SharedClipboard({ eventBus: kernel.eventBus });
    const notifications = new NotificationCenter({
      eventBus: kernel.eventBus,
      configStore,
      processManager: kernel.processManager,
    });
    const compositor = new Compositor({ kernel, configStore });
    const pkgManager = new PackageManager({
      kernel,
      vfs,
      configStore,
      ipc,
      intentRouter,
      clipboard,
      notifications,
      users,
      permissions,
      compositor,
    });
    intentRouter.setLauncher((appId, { intent }) => pkgManager.launch(appId, { intent }));
    registerSecurityService(kernel.serviceManager, { userManager: users, permissionBroker: permissions, kernel, deps: [] });
    registerVfsService(kernel.serviceManager, vfs, { kernel, deps: ['securityd'] });
    registerConfigService(kernel.serviceManager, configStore, { kernel, deps: [] });
    registerIpcBrokerService(kernel.serviceManager, { ipc, router: intentRouter, clipboard, notifications, deps: ['configd'] });
    registerCompositorService(kernel.serviceManager, compositor, { deps: ['configd'] });
    registerPackageService(kernel.serviceManager, pkgManager, { deps: ['securityd', 'vfsd', 'ipc-brokerd', 'compositord'] });
    return { kernel, users, permissions, vfs, configStore, ipc, intentRouter, clipboard, notifications, compositor, pkgManager };
  }

  it('A1 & A2: blocks explicitSandboxRoot/ctx.sandboxRoot widening across UID 10000+ containers, rejects .. traversal & normalizes ///', () => {
    const um = new UserManager();
    const vfs = new VFS({ userManager: um });
    try {
      const appA = um.allocateAppUid('com.reg.appa', {
        platform: 'android',
        sandboxRoot: '/var/appdata/android/com.reg.appa',
        strictSandbox: false,
      });
      const appB = um.allocateAppUid('com.reg.appb', {
        platform: 'android',
        sandboxRoot: '/var/appdata/android/com.reg.appb',
        strictSandbox: true,
      });

      // Provision App A and App B containers (make App B dir & file world-accessible 0o777!)
      vfs.mkdir(appA.sandboxRoot, { recursive: true, mode: 0o755, uid: 0, gid: 0 });
      vfs.chown(appA.sandboxRoot, appA.uid, appA.gid, { uid: 0, gid: 0 });
      vfs.mkdir(`${appA.sandboxRoot}/sub`, { mode: 0o755, uid: appA.uid, gid: appA.gid });
      vfs.writeFile(`${appA.sandboxRoot}/sub/ok.txt`, 'a-sub', { mode: 0o644, uid: appA.uid, gid: appA.gid });
      vfs.writeFile(`${appA.sandboxRoot}/other.txt`, 'a-other', { mode: 0o644, uid: appA.uid, gid: appA.gid });

      vfs.mkdir(appB.sandboxRoot, { recursive: true, mode: 0o777, uid: 0, gid: 0 });
      vfs.chmod(appB.sandboxRoot, 0o777, { uid: 0, gid: 0 });
      vfs.writeFile(`${appB.sandboxRoot}/open.txt`, 'secret-b', { mode: 0o777, uid: 0, gid: 0 });
      vfs.chmod(`${appB.sandboxRoot}/open.txt`, 0o777, { uid: 0, gid: 0 });

      // A1: explicitSandboxRoot cannot widen UID 10000+ isolation on UserManager
      const widenParent = um.checkSandboxAccess(appA.uid, `${appB.sandboxRoot}/open.txt`, {
        explicitSandboxRoot: '/var/appdata',
      });
      assert.equal(widenParent.allowed, false);
      assert.equal(widenParent.reason, 'cross_app_sandbox_violation');

      const widenOther = um.checkSandboxAccess(
        { uid: appA.uid, sandboxRoot: appB.sandboxRoot },
        `${appB.sandboxRoot}/open.txt`
      );
      assert.equal(widenOther.allowed, false);

      const widenRootHome = um.checkSandboxAccess(appA.uid, '/root/.secret', {
        explicitSandboxRoot: '/',
      });
      assert.equal(widenRootHome.allowed, false);
      assert.equal(widenRootHome.reason, 'root_home_denied');

      // Persisted strictSandbox: true cannot be loosened by caller actor object
      const loosenStrict = um.checkSandboxAccess(
        { uid: appB.uid, strictSandbox: false },
        '/home/user/Documents/shared.txt',
        { explicitSandboxRoot: '/' }
      );
      assert.equal(loosenStrict.allowed, false);

      // A1: live VFS.readFile rejects ctx.sandboxRoot widening even on 0o777 file
      assert.throws(
        () =>
          vfs.readFile(`${appB.sandboxRoot}/open.txt`, {
            uid: appA.uid,
            gid: appA.gid,
            sandboxRoot: appB.sandboxRoot,
          }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EACCES
      );
      assert.throws(
        () =>
          vfs.readFile(`${appB.sandboxRoot}/open.txt`, {
            uid: appA.uid,
            gid: appA.gid,
            sandboxRoot: '/var/appdata',
          }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EACCES
      );

      // Tightening (intersecting) inside own container still works cleanly
      assert.equal(
        vfs.readFile(`${appA.sandboxRoot}/sub/ok.txt`, {
          uid: appA.uid,
          gid: appA.gid,
          sandboxRoot: `${appA.sandboxRoot}/sub`,
          encoding: 'utf8',
        }),
        'a-sub'
      );
      assert.throws(
        () =>
          vfs.readFile(`${appA.sandboxRoot}/other.txt`, {
            uid: appA.uid,
            gid: appA.gid,
            sandboxRoot: `${appA.sandboxRoot}/sub`,
          }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EACCES
      );

      // A2: checkSandboxAccess rejects '..' traversal with reason='path_traversal'
      const travApp = um.checkSandboxAccess(
        appA.uid,
        '/var/appdata/android/com.reg.appa/../com.reg.appb/open.txt'
      );
      assert.equal(travApp.allowed, false);
      assert.equal(travApp.reason, 'path_traversal');

      const travUser = um.checkSandboxAccess(1000, '/home/user/../etc/passwd', {
        explicitSandboxRoot: '/home/user',
      });
      assert.equal(travUser.allowed, false);
      assert.equal(travUser.reason, 'path_traversal');

      // A2: '///' normalizes cleanly to '/' under explicitSandboxRoot: '/'
      const slashesRoot = um.checkSandboxAccess(1000, '///', { explicitSandboxRoot: '/' });
      assert.equal(slashesRoot.allowed, true);
      const multiSlashes = um.checkSandboxAccess(1000, '///home///user/./docs///', {
        explicitSandboxRoot: '/home/user',
      });
      assert.equal(multiSlashes.allowed, true);
    } finally {
      vfs.close();
      um.close();
    }
  });

  it('A3: isolates unprivileged HKLM VirtualStore from HKCU/HKCR & case-distinct appIds while preserving 3-layer HKCR overlay', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'omnios-m2-a3-'));
    const dbPath = path.join(dir, 'a3-config.sqlite');
    let s1 = null;
    let s2 = null;
    try {
      s1 = new SqliteStorage(dbPath);
      const cfg = new UnifiedConfigStore({ storage: s1 });
      const appACtx = { uid: 10001, appId: 'com.vendor.appA' };
      const appBCtx = { uid: 10002, appId: 'com.vendor.appB' };

      // App A writes unprivileged HKLM value -> stored in isolated internal VirtualStore
      const wRes = cfg.registry.setValue('HKLM', 'Software\\SharedVendor', 'SecretA', REGISTRY_TYPES.REG_SZ, 'only-A', appACtx);
      assert.equal(wRes.virtualized, true);
      assert.equal(cfg.registry.getValue('HKLM', 'Software\\SharedVendor', 'SecretA', appACtx)?.data, 'only-A');

      // App B CANNOT read App A's VirtualStore via HKCU, HKCR, or HKLM
      assert.equal(
        cfg.registry.getValue(
          'HKCU',
          'Software\\Classes\\VirtualStore\\MACHINE\\com.vendor.appA\\Software\\SharedVendor',
          'SecretA',
          appBCtx
        ),
        null
      );
      assert.equal(
        cfg.registry.getValue(
          'HKCR',
          'VirtualStore\\MACHINE\\com.vendor.appA\\Software\\SharedVendor',
          'SecretA',
          appBCtx
        ),
        null
      );
      assert.equal(cfg.registry.getValue('HKLM', 'Software\\SharedVendor', 'SecretA', appBCtx), null);

      // Direct access to internal VirtualStore hive is rejected
      assert.throws(
        () => cfg.registry.getValue('__VIRTUALSTORE__', 'MACHINE', 'SecretA', appBCtx),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );

      // 'VirtualStore' MUST NOT appear in HKCR root or HKCU\Software\Classes enumKey
      const hkcrRootB = cfg.registry.enumKey('HKCR', '', appBCtx);
      assert.equal(hkcrRootB.subkeys.some((k) => k.toLowerCase() === 'virtualstore'), false);
      const hkcrRootA = cfg.registry.enumKey('HKCR', '', appACtx);
      assert.equal(hkcrRootA.subkeys.some((k) => k.toLowerCase() === 'virtualstore'), false);
      const hkcuClasses = cfg.registry.enumKey('HKCU', 'Software\\Classes', appBCtx);
      assert.equal(hkcuClasses.subkeys.some((k) => k.toLowerCase() === 'virtualstore'), false);

      // Case-distinct appIds ('appA' vs 'APPA') stay strictly isolated
      const lowerCtx = { uid: 10003, appId: 'appA' };
      const upperCtx = { uid: 10004, appId: 'APPA' };
      cfg.registry.setValue('HKLM', 'Software\\CaseIso', 'Secret', REGISTRY_TYPES.REG_SZ, 'from-lower', lowerCtx);
      assert.equal(cfg.registry.getValue('HKLM', 'Software\\CaseIso', 'Secret', upperCtx), null);
      cfg.registry.setValue('HKLM', 'Software\\CaseIso', 'Secret', REGISTRY_TYPES.REG_SZ, 'from-upper', upperCtx);
      assert.equal(cfg.registry.getValue('HKLM', 'Software\\CaseIso', 'Secret', lowerCtx)?.data, 'from-lower');
      assert.equal(cfg.registry.getValue('HKLM', 'Software\\CaseIso', 'Secret', upperCtx)?.data, 'from-upper');

      // HKCR 3-layer overlay (HKCU\Software\Classes > VirtualStore > HKLM\Software\Classes) still works!
      cfg.registry.setValue('HKLM', 'Software\\Classes\\.a3ext', '', REGISTRY_TYPES.REG_SZ, 'GlobalHklm');
      assert.equal(cfg.registry.getValue('HKCR', '.a3ext', '', appACtx)?.data, 'GlobalHklm');
      assert.equal(cfg.registry.getValue('HKCR', '.a3ext', '', appBCtx)?.data, 'GlobalHklm');

      cfg.registry.setValue('HKLM', 'Software\\Classes\\.a3ext', '', REGISTRY_TYPES.REG_SZ, 'VirtualAppA', appACtx);
      assert.equal(cfg.registry.getValue('HKCR', '.a3ext', '', appACtx)?.data, 'VirtualAppA');
      assert.equal(cfg.registry.getValue('HKCR', '.a3ext', '', appACtx)?.virtualized, true);
      assert.equal(cfg.registry.getValue('HKCR', '.a3ext', '', appBCtx)?.data, 'GlobalHklm');

      cfg.registry.setValue('HKCU', 'Software\\Classes\\.a3ext', '', REGISTRY_TYPES.REG_SZ, 'UserHkcu', appACtx);
      assert.equal(cfg.registry.getValue('HKCR', '.a3ext', '', appACtx)?.data, 'UserHkcu');
      assert.equal(cfg.registry.getValue('HKCR', '.a3ext', '', appBCtx)?.data, 'UserHkcu');

      s1.close();
      s1 = null;

      // Verify VirtualStore case-distinct isolation persists across WAL SQLite reopen
      s2 = new SqliteStorage(dbPath);
      const cfg2 = new UnifiedConfigStore({ storage: s2 });
      assert.equal(cfg2.registry.getValue('HKLM', 'Software\\CaseIso', 'Secret', lowerCtx)?.data, 'from-lower');
      assert.equal(cfg2.registry.getValue('HKLM', 'Software\\CaseIso', 'Secret', upperCtx)?.data, 'from-upper');
      assert.equal(cfg2.registry.getValue('HKLM', 'Software\\SharedVendor', 'SecretA', appACtx)?.data, 'only-A');
      assert.equal(cfg2.registry.getValue('HKLM', 'Software\\SharedVendor', 'SecretA', appBCtx), null);
    } finally {
      if (s1?.isOpen) s1.close();
      if (s2?.isOpen) s2.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('A4: PathTranslator blocks intermediate container/sandbox escapes and accepts valid 4-platform & case-insensitive sandboxed paths', () => {
    const pt = new PathTranslator();
    const isTraversalErr = (err) =>
      err instanceof VfsError &&
      err.code === ERROR_CODES.EACCES &&
      err.details?.violation === ERROR_CODES.E_PATH_TRAVERSAL;

    // Blocked Android & iOS container-escape bypasses via leading junk + '..'
    assert.throws(() => pt.toCanonical('/tmp/../data/data/com.a/../com.b', { platform: 'android' }), isTraversalErr);
    assert.throws(() => pt.toCanonical('/data/./../data/data/com.a/../com.b', { platform: 'android' }), isTraversalErr);
    assert.throws(
      () => pt.toCanonical('/tmp/../var/mobile/Containers/Data/Application/u1/../u2', { platform: 'ios' }),
      isTraversalErr
    );

    // Blocked Windows intermediate sandboxRoot escapes (Z:\, D:\, C:\foo\..\Users\user, C:\Users\..\Users\user)
    assert.throws(
      () => pt.toCanonical('Z:\\home\\user\\..\\outside\\..\\user\\x', { platform: 'windows', sandboxRoot: '/home/user' }),
      isTraversalErr
    );
    assert.throws(
      () => pt.toCanonical('D:\\app\\..\\outside\\..\\app\\x', { platform: 'windows', sandboxRoot: '/mnt/d/app' }),
      isTraversalErr
    );
    assert.throws(
      () => pt.toCanonical('C:\\foo\\..\\Users\\user\\..\\outside\\..\\user\\x', { platform: 'windows', sandboxRoot: '/home/user' }),
      isTraversalErr
    );
    assert.throws(
      () => pt.toCanonical('C:\\Users\\..\\Users\\user\\..\\outside\\..\\user\\x', { platform: 'windows', sandboxRoot: '/home/user' }),
      isTraversalErr
    );

    // Accepted valid platform paths under sandboxRoot
    assert.equal(
      pt.toCanonical('/data/user/0/com.app/files/ok.txt', {
        platform: 'android',
        sandboxRoot: '/var/appdata/android/com.app',
      }).canonicalPath,
      '/var/appdata/android/com.app/files/ok.txt'
    );
    assert.equal(
      pt.toCanonical('/system/bin/sh', {
        platform: 'android',
        sandboxRoot: '/system/android',
      }).canonicalPath,
      '/system/android/bin/sh'
    );
    assert.equal(
      pt.toCanonical('/var/mobile/Documents/note.txt', {
        platform: 'ios',
        sandboxRoot: '/home/user/Documents',
      }).canonicalPath,
      '/home/user/Documents/note.txt'
    );
    assert.equal(
      pt.toCanonical('/System/Library/Core.framework', {
        platform: 'macos',
        sandboxRoot: '/system/macos',
      }).canonicalPath,
      '/system/macos/Library/Core.framework'
    );

    // Accepted Windows & macOS case-insensitive sandboxRoot matching
    assert.equal(
      pt.toCanonical('C:\\Users\\user\\AppData\\myapp\\cfg.ini', {
        platform: 'windows',
        sandboxRoot: '/var/appdata/windows/MyApp',
      }).canonicalPath,
      '/var/appdata/windows/myapp/cfg.ini'
    );
    assert.equal(
      pt.toCanonical('/Users/user/Library/myapp/prefs.plist', {
        platform: 'macos',
        sandboxRoot: '/var/appdata/macos/Library/MyApp',
      }).canonicalPath,
      '/var/appdata/macos/Library/myapp/prefs.plist'
    );
  });

  it('A5 & A6: /tmp handle huge-offset ENOSPC pre-allocation guard & sandboxed VFS.mkdir({ recursive: true })', () => {
    const um = new UserManager();
    const vfs = new VFS({ userManager: um, maxStorageBytes: 64 * 1024, maxTmpBytes: 64 });
    try {
      // A5: huge offsets on /tmp handle throw VfsError(ENOSPC) immediately without RangeError/OOM
      const h = vfs.open('/tmp/huge_off.bin', 'w', { uid: 1000, gid: 1000 });
      assert.throws(
        () => h.write(new Uint8Array([1]), Number.MAX_SAFE_INTEGER - 10),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.ENOSPC
      );
      assert.throws(
        () => h.write(new Uint8Array([1]), 100 * 1024 ** 3),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.ENOSPC
      );
      // Small valid write still works after rejected huge writes
      assert.equal(h.write(new Uint8Array([1, 2, 3]), 0).bytesWritten, 3);
      h.close();

      // A6: VFS.mkdir({ recursive: true }) inside sandboxed containers (uid >= 10000, strictSandbox, explicit sandboxRoot)
      const appAnd = um.allocateAppUid('com.mkdir.and', {
        platform: 'android',
        sandboxRoot: '/var/appdata/android/com.mkdir.and',
        strictSandbox: false,
      });
      const appIos = um.allocateAppUid('com.mkdir.ios', {
        platform: 'ios',
        containerUuid: 'UUID-MK-1',
        sandboxRoot: '/var/appdata/ios/UUID-MK-1',
        strictSandbox: true,
      });
      vfs.mkdir(appAnd.sandboxRoot, { recursive: true, uid: 0, gid: 0 });
      vfs.chown(appAnd.sandboxRoot, appAnd.uid, appAnd.gid, { uid: 0, gid: 0 });
      vfs.mkdir(appIos.sandboxRoot, { recursive: true, uid: 0, gid: 0 });
      vfs.chown(appIos.sandboxRoot, appIos.uid, appIos.gid, { uid: 0, gid: 0 });

      vfs.mkdir('/data/data/com.mkdir.and/files/sub/deep', {
        recursive: true,
        platform: 'android',
        uid: appAnd.uid,
        gid: appAnd.gid,
      });
      assert.equal(vfs.stat('/var/appdata/android/com.mkdir.and/files/sub/deep', { uid: appAnd.uid, gid: appAnd.gid }).type, 'dir');

      vfs.mkdir('/var/mobile/Containers/Data/Application/UUID-MK-1/Documents/nested/leaf', {
        recursive: true,
        platform: 'ios',
        uid: appIos.uid,
        gid: appIos.gid,
      });
      assert.equal(vfs.stat('/var/appdata/ios/UUID-MK-1/Documents/nested/leaf', { uid: appIos.uid, gid: appIos.gid }).type, 'dir');

      vfs.mkdir('/home/user/Documents/proj/src/lib', {
        recursive: true,
        uid: 1000,
        gid: 1000,
        sandboxRoot: '/home/user/Documents',
      });
      assert.equal(vfs.stat('/home/user/Documents/proj/src/lib', { uid: 1000, gid: 1000 }).type, 'dir');

      // Escapes outside sandbox are still rejected with EACCES
      assert.throws(
        () =>
          vfs.mkdir('/var/appdata/android/com.other/sub', {
            recursive: true,
            uid: appAnd.uid,
            gid: appAnd.gid,
          }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EACCES
      );
      assert.throws(
        () =>
          vfs.mkdir('/home/user/escape/sub', {
            recursive: true,
            uid: appIos.uid,
            gid: appIos.gid,
          }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EACCES
      );
      assert.throws(
        () =>
          vfs.mkdir('/home/user/Downloads/escape', {
            recursive: true,
            uid: 1000,
            gid: 1000,
            sandboxRoot: '/home/user/Documents',
          }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EACCES
      );
    } finally {
      vfs.close();
      um.close();
    }
  });

  it('A7, A8 & A9: open-unlinked-FD POSIX contract (SQLite + /tmp), EMFILE/dead-PID open() safety + O_TRUNC event & atomic _crossMountRename()', async () => {
    // A7: Open-unlinked-FD contract on BOTH SQLite and /tmp
    const storage = new SqliteStorage(':memory:');
    const vfsA7 = new VFS({ storage, maxTmpBytes: 64 });
    try {
      // 1) SQLite mount
      vfsA7.writeFile('/home/user/unlinked_sql.txt', 'hello-sqlite', { uid: 1000, gid: 1000 });
      const sqlIno = vfsA7.stat('/home/user/unlinked_sql.txt').ino;
      const hSql = vfsA7.open('/home/user/unlinked_sql.txt', 'r+', { uid: 1000, gid: 1000 });
      vfsA7.unlink('/home/user/unlinked_sql.txt', { uid: 1000, gid: 1000 });

      assert.throws(() => vfsA7.stat('/home/user/unlinked_sql.txt'), (e) => e.code === ERROR_CODES.ENOENT);
      assert.equal(new TextDecoder().decode(hSql.read(32)), 'hello-sqlite');
      assert.equal(hSql.write(new TextEncoder().encode('!'), 12).bytesWritten, 1);
      assert.equal(hSql.stat().nlink, 0);
      assert.equal(hSql.stat().size, 13);
      hSql.seek(0, SEEK_WHENCE.SEEK_SET);
      assert.equal(new TextDecoder().decode(hSql.read(32)), 'hello-sqlite!');
      // Inode row deferred while open
      assert.equal(storage.get('SELECT nlink FROM vfs_inodes WHERE ino = ?', sqlIno)?.nlink, 0);
      hSql.close();
      // Inode reclaimed after final close!
      assert.equal(storage.get('SELECT ino FROM vfs_inodes WHERE ino = ?', sqlIno), null);

      // 2) /tmp mount (including /tmp quota reclamation on final close)
      vfsA7.writeFile('/tmp/unlinked_tmp.txt', 'hello-tmp-1234', { uid: 1000, gid: 1000 }); // 14 bytes
      const hTmp = vfsA7.open('/tmp/unlinked_tmp.txt', 'r+', { uid: 1000, gid: 1000 });
      vfsA7.unlink('/tmp/unlinked_tmp.txt', { uid: 1000, gid: 1000 });

      assert.throws(() => vfsA7.stat('/tmp/unlinked_tmp.txt'), (e) => e.code === ERROR_CODES.ENOENT);
      assert.equal(new TextDecoder().decode(hTmp.read(32)), 'hello-tmp-1234');
      assert.equal(hTmp.write(new TextEncoder().encode('!!'), 14).bytesWritten, 2); // now 16 bytes
      assert.equal(hTmp.stat().nlink, 0);
      assert.equal(hTmp.stat().size, 16);
      hTmp.seek(0, SEEK_WHENCE.SEEK_SET);
      assert.equal(new TextDecoder().decode(hTmp.read(32)), 'hello-tmp-1234!!');

      // Quota (64 bytes) still accounts for the 16-byte open unlinked /tmp file -> 55 bytes throws ENOSPC
      assert.throws(
        () => vfsA7.writeFile('/tmp/quota_probe.bin', new Uint8Array(55), { uid: 1000, gid: 1000 }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.ENOSPC
      );
      hTmp.close();
      // Closing reclaims /tmp quota -> 55 bytes now fits cleanly!
      vfsA7.writeFile('/tmp/quota_probe.bin', new Uint8Array(55), { uid: 1000, gid: 1000 });
      assert.equal(vfsA7.stat('/tmp/quota_probe.bin').size, 55);
    } finally {
      vfsA7.close();
      if (storage.isOpen) storage.close();
    }

    // A8: VFS.open(..., 'w', { pid }) at maxOpenFds (EMFILE) or on dead PID (EINVAL) preserves data & emits vfs:changed on O_TRUNC
    const kernel = new OmniKernel();
    const vfsA8 = new VFS({ kernel });
    registerVfsService(kernel.serviceManager, vfsA8, { kernel });
    const vfsEvents = [];
    kernel.eventBus.on('vfs:changed', (e) => vfsEvents.push(e));
    await kernel.boot();
    try {
      vfsA8.writeFile('/home/user/precious.txt', 'DO-NOT-TRUNCATE', { uid: 1000, gid: 1000 });
      const pcb = kernel.processManager.spawn({
        name: 'fd-quota-test',
        uid: 1000,
        gid: 1000,
        quotas: { maxOpenFds: 4 }, // FDs 0,1,2 occupied -> 1 slot left
        executionContext: makeWorkExecContext(),
      });
      const held = vfsA8.open('/home/user/precious.txt', 'r', { pid: pcb.pid, uid: 1000, gid: 1000 });

      // At EMFILE: existing file must NOT be truncated, new file must NOT be created
      assert.throws(
        () => vfsA8.open('/home/user/precious.txt', 'w', { pid: pcb.pid, uid: 1000, gid: 1000 }),
        (err) => err instanceof QuotaExceededError && err.code === ERROR_CODES.EMFILE
      );
      assert.equal(vfsA8.readFile('/home/user/precious.txt', { encoding: 'utf8' }), 'DO-NOT-TRUNCATE');

      assert.throws(
        () => vfsA8.open('/home/user/no_orphan_emfile.txt', 'w', { pid: pcb.pid, uid: 1000, gid: 1000 }),
        (err) => err instanceof QuotaExceededError && err.code === ERROR_CODES.EMFILE
      );
      assert.throws(() => vfsA8.stat('/home/user/no_orphan_emfile.txt'), (e) => e.code === ERROR_CODES.ENOENT);

      // Kill process -> ZOMBIE PID: open('w') throws EINVAL without truncating or creating orphan
      held.close();
      kernel.processManager.kill(pcb.pid, 'SIGKILL');
      assert.throws(
        () => vfsA8.open('/home/user/precious.txt', 'w', { pid: pcb.pid, uid: 1000, gid: 1000 }),
        (err) => err instanceof ProcessError && err.code === ERROR_CODES.EINVAL
      );
      assert.equal(vfsA8.readFile('/home/user/precious.txt', { encoding: 'utf8' }), 'DO-NOT-TRUNCATE');
      assert.throws(
        () => vfsA8.open('/home/user/no_orphan_dead.txt', 'w', { pid: pcb.pid, uid: 1000, gid: 1000 }),
        (err) => err instanceof ProcessError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(() => vfsA8.stat('/home/user/no_orphan_dead.txt'), (e) => e.code === ERROR_CODES.ENOENT);

      // Valid O_TRUNC emits vfs:changed with op='write', size=0
      vfsEvents.length = 0;
      const truncHandle = vfsA8.open('/home/user/precious.txt', 'w', { uid: 1000, gid: 1000 });
      truncHandle.close();
      assert.equal(vfsA8.readFile('/home/user/precious.txt', { encoding: 'utf8' }), '');
      assert.ok(
        vfsEvents.some((e) => e.op === 'write' && e.path === '/home/user/precious.txt' && e.size === 0),
        'Expected vfs:changed event on O_TRUNC'
      );
    } finally {
      await kernel.shutdown();
    }

    // A9: _crossMountRename() preserves existing destination on ENOSPC (both directions) & allows root symlink move preserving (uid, gid)
    const vfsTmpToSql = new VFS({ maxStorageBytes: 50, maxTmpBytes: 4096 });
    const vfsSqlToTmp = new VFS({ maxStorageBytes: 4096, maxTmpBytes: 12 });
    const vfsSym = new VFS();
    try {
      // Direction 1: /tmp -> SQLite ENOSPC preserves existing SQLite destination
      vfsTmpToSql.writeFile('/home/user/keep_sql.txt', 'keep-sql-ok', { uid: 1000, gid: 1000 });
      vfsTmpToSql.writeFile('/tmp/too_big_sql.txt', 'X'.repeat(100), { uid: 1000, gid: 1000 });
      assert.throws(
        () => vfsTmpToSql.rename('/tmp/too_big_sql.txt', '/home/user/keep_sql.txt', { uid: 1000, gid: 1000 }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.ENOSPC
      );
      assert.equal(vfsTmpToSql.readFile('/home/user/keep_sql.txt', { encoding: 'utf8' }), 'keep-sql-ok');
      assert.equal(vfsTmpToSql.stat('/tmp/too_big_sql.txt').size, 100);

      // Direction 2: SQLite -> /tmp ENOSPC preserves existing /tmp destination
      vfsSqlToTmp.writeFile('/tmp/keep_tmp.txt', 'keep-tmp', { uid: 1000, gid: 1000 });
      vfsSqlToTmp.writeFile('/home/user/too_big_tmp.txt', 'Y'.repeat(30), { uid: 1000, gid: 1000 });
      assert.throws(
        () => vfsSqlToTmp.rename('/home/user/too_big_tmp.txt', '/tmp/keep_tmp.txt', { uid: 1000, gid: 1000 }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.ENOSPC
      );
      assert.equal(vfsSqlToTmp.readFile('/tmp/keep_tmp.txt', { encoding: 'utf8' }), 'keep-tmp');
      assert.equal(vfsSqlToTmp.stat('/home/user/too_big_tmp.txt').size, 30);

      // Root moves user-owned symlink from /tmp into /etc preserving (uid, gid)
      vfsSym.symlink('/home/user/target', '/tmp/user_sym', { uid: 1000, gid: 1000 });
      vfsSym.rename('/tmp/user_sym', '/etc/moved_sym', { uid: 0, gid: 0 });
      assert.throws(() => vfsSym.lstat('/tmp/user_sym'), (e) => e.code === ERROR_CODES.ENOENT);
      const movedStat = vfsSym.lstat('/etc/moved_sym');
      assert.equal(movedStat.type, 'symlink');
      assert.equal(movedStat.uid, 1000);
      assert.equal(movedStat.gid, 1000);
      assert.equal(vfsSym.readlink('/etc/moved_sym'), '/home/user/target');
    } finally {
      vfsTmpToSql.close();
      vfsSqlToTmp.close();
      vfsSym.close();
    }
  });

  it('A10: PermissionBroker isolates hostile & revoked Proxy contexts; UnifiedConfigStore rejects BigInt with EINVAL & blocks non-canonical re-entrancy', async () => {
    const bus = new KernelEventBus();
    const pb = new PermissionBroker({ eventBus: bus, promptHandler: () => 'deny_once' });
    const cfg = new UnifiedConfigStore({ eventBus: bus });
    try {
      const trapProxy = new Proxy(
        {},
        {
          getPrototypeOf() {
            throw new Error('proto trap boom');
          },
        }
      );
      const rev = Proxy.revocable({ secret: 1 }, {});
      rev.revoke();

      // 1. Prompt flow with hostile & revoked Proxy
      const p1 = await pb.checkPermission({
        appId: 'com.proxy.app',
        capability: CAPABILITIES.CAMERA_DEVICE,
        context: trapProxy,
      });
      assert.equal(p1.granted, false);
      assert.equal(p1.policy, 'prompt');

      const p2 = await pb.checkPermission({
        appId: 'com.proxy.app',
        capability: CAPABILITIES.LOCATION_DEVICE,
        context: rev.proxy,
      });
      assert.equal(p2.granted, false);
      assert.equal(p2.policy, 'prompt');

      // 2. policyOverride: 'allow' (both string and function) with hostile & revoked Proxy
      pb.setPolicyOverride('allow');
      const oStr1 = await pb.checkPermission({
        appId: 'com.proxy.ov',
        capability: CAPABILITIES.CAMERA_DEVICE,
        context: trapProxy,
      });
      assert.equal(oStr1.granted, true);
      assert.equal(oStr1.reason, 'policy_override');

      const oStr2 = await pb.checkPermission({
        appId: 'com.proxy.ov',
        capability: CAPABILITIES.CLIPBOARD_READ,
        context: rev.proxy,
      });
      assert.equal(oStr2.granted, true);
      assert.equal(oStr2.reason, 'policy_override');

      pb.setPolicyOverride(() => 'allow');
      const o1 = await pb.checkPermission({
        appId: 'com.proxy.ov',
        capability: CAPABILITIES.CAMERA_DEVICE,
        context: trapProxy,
      });
      assert.equal(o1.granted, true);
      assert.equal(o1.reason, 'policy_override');

      const o2 = await pb.checkPermission({
        appId: 'com.proxy.ov',
        capability: CAPABILITIES.CLIPBOARD_READ,
        context: rev.proxy,
      });
      assert.equal(o2.granted, true);
      assert.equal(o2.reason, 'policy_override');
      pb.setPolicyOverride(null);

      // Audit rows must all be cleanly persisted & JSON-serializable
      const auditRows = pb.getAuditLog({ appId: 'com.proxy.ov', limit: 10 });
      assert.equal(auditRows.length, 4);
      assert.doesNotThrow(() => JSON.stringify(auditRows));

      // 3. UnifiedConfigStore.system.set('custom.bigint', 123n) throws typed OmniOSError(EINVAL)
      assert.throws(
        () => cfg.system.set('custom.bigint', 123n),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );

      // 4. _emitConfigChanged blocks synchronous infinite recursion on non-canonical keys (system & case-insensitive registry)
      let sysEmitCount = 0;
      const unsubSys = bus.on('config:changed', (ev) => {
        if (ev.key === 'custom.loop') {
          sysEmitCount += 1;
          cfg.system.set('custom.loop', ev.value + 1);
        }
      });
      cfg.system.set('custom.loop', 0);
      unsubSys();
      assert.equal(sysEmitCount, 1);
      assert.equal(cfg.system.get('custom.loop'), 1);

      let regEmitCount = 0;
      const unsubReg = bus.on('config:changed', (ev) => {
        if (ev.source === 'registry' && String(ev.key).toLowerCase().includes('loopkey')) {
          regEmitCount += 1;
          cfg.registry.setValue('HKCU', 'software\\loopkey', 'val', REGISTRY_TYPES.REG_DWORD, regEmitCount);
        }
      });
      cfg.registry.setValue('HKCU', 'Software\\LoopKey', 'Val', REGISTRY_TYPES.REG_DWORD, 0);
      unsubReg();
      assert.equal(regEmitCount, 1);
    } finally {
      pb.close();
      cfg.close();
    }
  });

  it('B1 & B2: rejects ZIP-bombs eagerly across listZipEntries/FormatDetector/inspect, blocks LFH-only encryption, encodes Uint8Array comments, fixes DMG koly 0xd8/0xe0 & malformed PE', async () => {
    const detector = new FormatDetector();
    const pkgMgr = new PackageManager();
    try {
      // B1.1: High-ratio deflate ZIP-bomb APK (2 MiB zeros -> ~2 KiB)
      const ratioBombApk = createZip([
        { name: 'AndroidManifest.xml', data: '<manifest/>' },
        { name: 'classes.dex', data: new Uint8Array(2 * 1024 * 1024), method: ZIP_METHODS.DEFLATE },
      ]);
      assert.throws(
        () => listZipEntries(ratioBombApk),
        (err) => err instanceof FormatError && err.code === ZIP_ERROR_CODES.E_ARCHIVE_BOMB
      );
      assert.throws(
        () => detector.detect(ratioBombApk, 'bomb.apk', { strictZip: true }),
        (err) => err instanceof FormatError && err.code === ZIP_ERROR_CODES.E_ARCHIVE_BOMB
      );
      const nonStrictRatio = detector.detect(ratioBombApk, 'bomb.apk', { strictZip: false });
      assert.equal(nonStrictRatio.format, PACKAGE_FORMATS.UNKNOWN);
      assert.equal(nonStrictRatio.details?.errorCode, ZIP_ERROR_CODES.E_ARCHIVE_BOMB);
      await assert.rejects(
        () => pkgMgr.inspect(ratioBombApk, 'bomb.apk'),
        (err) => err instanceof FormatError && err.code === ZIP_ERROR_CODES.E_ARCHIVE_BOMB
      );

      // B1.2: >64 MiB declared-size ZIP-bomb APK (patch CDFH uncompressedSize to 100 MiB on DEFLATE entry)
      const baseApk = createZip([
        { name: 'AndroidManifest.xml', data: '<manifest/>'.repeat(10), method: ZIP_METHODS.DEFLATE },
        { name: 'classes.dex', data: 'small', method: ZIP_METHODS.STORE },
      ]);
      const baseIdx = listZipEntries(baseApk);
      const declaredBomb = baseApk.slice();
      const dbView = new DataView(declaredBomb.buffer);
      dbView.setUint32(baseIdx.centralDirOffset + 24, 100 * 1024 * 1024, true); // 100 MiB > 64 MiB maxEntryBytes
      assert.throws(
        () => listZipEntries(declaredBomb),
        (err) => err instanceof FormatError && err.code === ZIP_ERROR_CODES.E_ARCHIVE_BOMB
      );
      assert.throws(
        () => detector.detect(declaredBomb, 'declared-bomb.apk', { strictZip: true }),
        (err) => err instanceof FormatError && err.code === ZIP_ERROR_CODES.E_ARCHIVE_BOMB
      );
      const nonStrictDecl = detector.detect(declaredBomb, 'declared-bomb.apk', { strictZip: false });
      assert.equal(nonStrictDecl.format, PACKAGE_FORMATS.UNKNOWN);
      assert.equal(nonStrictDecl.details?.errorCode, ZIP_ERROR_CODES.E_ARCHIVE_BOMB);
      await assert.rejects(
        () => pkgMgr.inspect(declaredBomb, 'declared-bomb.apk'),
        (err) => err instanceof FormatError && err.code === ZIP_ERROR_CODES.E_ARCHIVE_BOMB
      );

      // B1.3: LFH-only encrypted bit 0 (0x0001) throws FormatError(E_ENCRYPTED_BINARY)
      const encBase = createZip([{ name: 'secret.txt', data: '', method: ZIP_METHODS.STORE }]);
      const encIdx = listZipEntries(encBase);
      const lfhOnlyEnc = encBase.slice();
      const lfhView = new DataView(lfhOnlyEnc.buffer);
      const lfhOff = encIdx.entries.get('secret.txt').localHeaderOffset;
      lfhView.setUint16(lfhOff + 6, lfhView.getUint16(lfhOff + 6, true) | ZIP_FLAGS.ENCRYPTED, true);
      assert.throws(
        () => listZipEntries(lfhOnlyEnc),
        (err) => err instanceof FormatError && err.code === ZIP_ERROR_CODES.E_ENCRYPTED_BINARY
      );
      assert.throws(
        () => readZip(lfhOnlyEnc),
        (err) => err instanceof FormatError && err.code === ZIP_ERROR_CODES.E_ENCRYPTED_BINARY
      );

      // B1.4: createZip() encodes Uint8Array archive comment & per-entry comment
      const binComment = new Uint8Array([0x4f, 0x6d, 0x6e, 0x69, 0x00, 0x01, 0x02, 0x03]);
      const entryComment = new Uint8Array([0x65, 0x6e, 0x74, 0x72, 0x79]);
      const zBin = createZip([{ name: 'a.txt', data: 'ok', comment: entryComment }], { comment: binComment });
      const zBinIdx = listZipEntries(zBin);
      const zBinView = new DataView(zBin.buffer, zBin.byteOffset, zBin.byteLength);
      assert.equal(zBinView.getUint16(zBinIdx.eocdOffset + 20, true), binComment.byteLength);
      assert.deepEqual(zBin.subarray(zBinIdx.eocdOffset + 22), binComment);
      assert.equal(zBinIdx.entries.get('a.txt').comment, 'entry');

      // B2.1: UDIF .dmg koly at 0xd8/0xe0 decodes exact xmlOffset & xmlLength
      const dmgCustom = buildDmgFixture({ xmlOffset: 4096n, xmlLength: 2048n });
      const dmgDet = detector.detect(dmgCustom);
      assert.equal(dmgDet.format, PACKAGE_FORMATS.MACOS_DMG);
      assert.equal(dmgDet.details.xmlOffset, 4096);
      assert.equal(dmgDet.details.xmlLength, 2048);

      // B2.2: detectPe() rejects numberOfSections = 500 > 96
      const peManySec = buildPeFixture({ pe32Plus: true });
      new DataView(peManySec.buffer).setUint16(0x80 + 6, 500, true);
      assert.equal(detector.detect(peManySec).format, PACKAGE_FORMATS.UNKNOWN);

      // B2.3: detectPe() rejects truncated OptionalHeader (peOffset + 24, sizeOfOptionalHeader = 240)
      const peTrunc = new Uint8Array(0x80 + 24);
      const ptView = new DataView(peTrunc.buffer);
      peTrunc[0] = 0x4d;
      peTrunc[1] = 0x5a;
      ptView.setUint32(0x3c, 0x80, true);
      peTrunc.set([0x50, 0x45, 0x00, 0x00], 0x80);
      ptView.setUint16(0x80 + 4, 0x8664, true);
      ptView.setUint16(0x80 + 6, 2, true);
      ptView.setUint16(0x80 + 20, 240, true); // declares 240B OptionalHeader, but buffer ends right at peOffset + 24!
      assert.equal(detector.detect(peTrunc).format, PACKAGE_FORMATS.UNKNOWN);
    } finally {
      pkgMgr.dispose();
    }
  });

  it('B3: hostile error objects (throwing .message/.code/.name getters) produce 0 unhandledRejections & preserve full fault isolation', async () => {
    const beforeUnhandled = unhandledRejections.length;
    const bus = new KernelEventBus();
    const pm = new ProcessManager({ eventBus: bus });
    const ipc = new IPCManager({ eventBus: bus, processManager: pm, defaultRpcTimeoutMs: 2000 });
    const router = new IntentRouter({ eventBus: bus, processManager: pm });
    const clip = new SharedClipboard({ eventBus: bus });

    try {
      // 1. IPCManager.callRpc: async hostile reject resolves immediately as OmniOSError (NO timeout hang!)
      ipc.registerRpc('hostile.async', async () => {
        throw makeHostileError('rpc-async');
      });
      const t0 = Date.now();
      await assert.rejects(
        () => ipc.callRpc('hostile.async', {}, { timeoutMs: 2000 }),
        (err) => err instanceof OmniOSError && err.code !== ERROR_CODES.ETIMEDOUT
      );
      assert.ok(Date.now() - t0 < 500, 'Hostile async RPC rejection must settle immediately without hanging');

      // 2. IPCManager.send: hostile sync & async subscribers isolated; subsequent subscriber still called
      ipc.createChannel('ch.hostile', 0);
      let sub3Called = false;
      ipc.subscribe('ch.hostile', () => {
        throw makeHostileError('sub-sync');
      });
      ipc.subscribe('ch.hostile', async () => {
        throw makeHostileError('sub-async');
      });
      ipc.subscribe('ch.hostile', (msg) => {
        sub3Called = msg.payload?.ok === true;
      });
      assert.doesNotThrow(() => ipc.send('ch.hostile', 0, { ok: true }));
      assert.equal(sub3Called, true);

      // 3. IntentRouter._deliver: hostile sync & async deliverEvent throws isolated
      pm.spawn({
        name: 'hostile-router-sync',
        appId: 'app.router.sync',
        executionContext: makeWorkExecContext({
          onEvent() {
            throw makeHostileError('router-sync');
          },
        }),
      });
      pm.spawn({
        name: 'hostile-router-async',
        appId: 'app.router.async',
        executionContext: makeWorkExecContext({
          async onEvent() {
            throw makeHostileError('router-async');
          },
        }),
      });
      router.registerHandlers('app.router.sync', [{ schemes: ['hsync'] }]);
      router.registerHandlers('app.router.async', [{ schemes: ['hasync'] }]);
      const rSync = await router.dispatch({ uri: 'hsync://go' });
      assert.equal(rSync.status, 'DELIVERED');
      const rAsync = await router.dispatch({ uri: 'hasync://go' });
      assert.equal(rAsync.status, 'DELIVERED');

      // 4. NotificationCenter({ onAction }).invokeAction: hostile sync/async deliverEvent & onAction throws isolated
      pm.spawn({
        name: 'hostile-notif-sync',
        appId: 'app.notif.hostile.sync',
        executionContext: makeWorkExecContext({
          onEvent() {
            throw makeHostileError('notif-deliver-sync');
          },
        }),
      });
      pm.spawn({
        name: 'hostile-notif-async',
        appId: 'app.notif.hostile.async',
        executionContext: makeWorkExecContext({
          async onEvent() {
            throw makeHostileError('notif-deliver-async');
          },
        }),
      });

      let onActionSyncCalls = 0;
      const notifSync = new NotificationCenter({
        eventBus: bus,
        processManager: pm,
        onAction() {
          onActionSyncCalls += 1;
          throw makeHostileError('notif-onaction-sync');
        },
      });
      const nHostileSync = notifSync.post({
        appId: 'app.notif.hostile.sync',
        title: 'Alert Sync',
        actions: [{ id: 'act-sync', label: 'Act Sync' }],
      });
      const actSyncRes = notifSync.invokeAction(nHostileSync.id, 'act-sync');
      assert.equal(actSyncRes.ok, true);
      assert.equal(onActionSyncCalls, 1);

      let onActionAsyncCalls = 0;
      const notifAsync = new NotificationCenter({
        eventBus: bus,
        processManager: pm,
        async onAction() {
          onActionAsyncCalls += 1;
          throw makeHostileError('notif-onaction-async');
        },
      });
      const nHostileAsync = notifAsync.post({
        appId: 'app.notif.hostile.async',
        title: 'Alert Async',
        actions: [{ id: 'act-async', label: 'Act Async' }],
      });
      const actAsyncRes = notifAsync.invokeAction(nHostileAsync.id, 'act-async');
      assert.equal(actAsyncRes.ok, true);
      assert.equal(onActionAsyncCalls, 1);

      // 5. SharedClipboard: hostile getter throws typed OmniOSError(EINVAL)
      const hostileJson = {};
      Object.defineProperty(hostileJson, 'boom', {
        enumerable: true,
        get() {
          throw new Error('clipboard getter boom');
        },
      });
      assert.throws(
        () => clip.set({ json: hostileJson }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );

      // Flush microtask & macrotask queue to confirm 0 unhandled rejections
      await new Promise((r) => setTimeout(r, 30));
      assert.equal(unhandledRejections.length, beforeUnhandled);
    } finally {
      ipc.stop();
    }
  });

  it('B4: PackageManager rejects prototype appIds, rolls back install() atomically, cleans PCB on hostile launch(), re-registers intents on reopen & clears stale intents on upgrade', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'omnios-m2-b4-'));
    const dbPath = path.join(dir, 'b4.sqlite');
    let os1 = null;
    let os2 = null;

    try {
      os1 = wireStack(dbPath);
      let inspectAppId = 'com.b4.app';
      let inspectVersion = '1.0.0';
      let inspectIntents = [{ action: 'view', scheme: 'b4v1' }];
      let failInstallHook = false;
      let throwHostileOnLaunch = false;

      os1.pkgManager.registerRuntime('universal', {
        platform: 'universal',
        inspectPackage(_bytes, _hint, detection) {
          return {
            format: detection.format,
            platform: 'universal',
            arch: 'wasm',
            appId: inspectAppId,
            name: 'B4TestApp',
            version: inspectVersion,
            permissions: ['wasi:fd_read', 'omni:ui.window'],
            intents: inspectIntents,
          };
        },
        installPackage() {
          if (failInstallHook) {
            throw new OmniOSError('Simulated installPackage failure', { code: ERROR_CODES.EINVAL });
          }
          return null;
        },
        createExecutionContext(pcb, appRecord, services) {
          services.compositor.createWindow(pcb.pid, { appId: appRecord.appId, title: 'B4Win' });
          if (throwHostileOnLaunch) {
            throw makeHostileError('launch-hostile');
          }
          return makeWorkExecContext({ totalWork: 100 });
        },
      });

      await os1.kernel.boot();

      const makePkg = (fileName, content) =>
        createZip([
          { name: 'omnios.manifest.json', data: JSON.stringify({ appId: inspectAppId, version: inspectVersion }) },
          { name: 'main.wasm', data: buildWasmFixture() },
          { name: fileName, data: content, method: ZIP_METHODS.STORE },
        ]);

      // 1. Reject prototype appIds ('__proto__', 'constructor', 'prototype') with SecurityError
      for (const badId of ['__proto__', 'constructor', 'prototype']) {
        inspectAppId = badId;
        await assert.rejects(
          () => os1.pkgManager.install(makePkg('a.txt', 'x')),
          (err) => err instanceof SecurityError
        );
      }
      assert.equal(os1.pkgManager.list().length, 0);

      // 2. Atomic fresh install() rollback when intentRouter.registerHandlers throws after DB commit
      inspectAppId = 'com.b4.rollback';
      inspectVersion = '1.0.0';
      inspectIntents = [{ action: 'view', scheme: 'b4rb' }];
      const origReg = os1.intentRouter.registerHandlers.bind(os1.intentRouter);
      os1.intentRouter.registerHandlers = () => {
        throw new OmniOSError('Intent router exploded', { code: ERROR_CODES.EINVAL });
      };
      try {
        await assert.rejects(
          () => os1.pkgManager.install(makePkg('rb.txt', 'data'), { grantAll: true }),
          /Intent router exploded/
        );
      } finally {
        os1.intentRouter.registerHandlers = origReg;
      }
      assert.equal(os1.pkgManager.get('com.b4.rollback'), null);
      assert.equal(
        os1.kernel.storage.get('SELECT app_id FROM installed_packages WHERE app_id = ?', 'com.b4.rollback'),
        null
      );
      assert.equal(os1.permissions.listGrants('com.b4.rollback').length, 0);
      assert.equal(os1.users.getUserByAppId('com.b4.rollback'), null);
      assert.throws(() => os1.vfs.stat('/apps/universal/com.b4.rollback'), (e) => e.code === ERROR_CODES.ENOENT);
      assert.throws(() => os1.vfs.stat('/var/appdata/universal/com.b4.rollback'), (e) => e.code === ERROR_CODES.ENOENT);

      // 3. Atomic overwrite: true preserves intact v1 installDir on BOTH corrupt-CRC ZIP & throwing installPackage
      inspectAppId = 'com.b4.persist';
      inspectVersion = '1.0.0';
      inspectIntents = [{ action: 'view', scheme: 'persistv1' }];
      const v1Pkg = makePkg('v1.txt', 'intact-v1-payload');
      const v1Rec = await os1.pkgManager.install(v1Pkg, { grantAll: true });
      assert.equal(os1.vfs.readFile(`${v1Rec.installDir}/v1.txt`, { encoding: 'utf8' }), 'intact-v1-payload');

      // 3a. Corrupt-CRC v2 ZIP fails before touching v1 installDir
      inspectVersion = '2.0.0';
      const v2Corrupt = makePkg('v2.txt', 'bad-crc-v2').slice();
      const v2Meta = listZipEntries(v2Corrupt).entries.get('v2.txt');
      v2Corrupt[v2Meta.localHeaderOffset + 30 + 'v2.txt'.length] ^= 0xff;
      await assert.rejects(
        () => os1.pkgManager.install(v2Corrupt, { overwrite: true }),
        (err) => err instanceof FormatError && err.code === ZIP_ERROR_CODES.E_CRC_MISMATCH
      );
      assert.equal(os1.pkgManager.get('com.b4.persist').version, '1.0.0');
      assert.equal(os1.vfs.readFile(`${v1Rec.installDir}/v1.txt`, { encoding: 'utf8' }), 'intact-v1-payload');

      // 3b. Failing runtime.installPackage rolls back renamed backup to restore intact v1 installDir
      failInstallHook = true;
      await assert.rejects(
        () => os1.pkgManager.install(makePkg('v2.txt', 'good-zip-bad-hook'), { overwrite: true }),
        /Simulated installPackage failure/
      );
      failInstallHook = false;
      assert.equal(os1.pkgManager.get('com.b4.persist').version, '1.0.0');
      assert.equal(os1.vfs.readFile(`${v1Rec.installDir}/v1.txt`, { encoding: 'utf8' }), 'intact-v1-payload');
      assert.equal(os1.intentRouter.resolve({ uri: 'persistv1://check' })[0]?.appId, 'com.b4.persist');

      // 4. launch() cleans up PCB & window on hostile error getter
      const activeBefore = os1.kernel.processManager
        .getAll()
        .filter((p) => p.state !== PROCESS_STATES.ZOMBIE && p.state !== PROCESS_STATES.TERMINATED).length;
      throwHostileOnLaunch = true;
      let launchThrew = false;
      try {
        await os1.pkgManager.launch('com.b4.persist');
      } catch {
        launchThrew = true;
      }
      throwHostileOnLaunch = false;
      assert.equal(launchThrew, true);
      const activeAfter = os1.kernel.processManager
        .getAll()
        .filter((p) => p.state !== PROCESS_STATES.ZOMBIE && p.state !== PROCESS_STATES.TERMINATED).length;
      assert.equal(activeAfter, activeBefore, 'Hostile launch() error must NOT leak active/CREATED PCB');
      assert.equal(os1.compositor.listWindows().length, 0);

      // 5. Upgrade with empty intents clears stale v1 intents, then install a second persisted-intent app for reopen check
      inspectVersion = '2.0.0';
      inspectIntents = [];
      await os1.pkgManager.install(makePkg('v2.txt', 'upgraded-v2'), { overwrite: true });
      assert.equal(os1.pkgManager.get('com.b4.persist').version, '2.0.0');
      assert.equal(os1.intentRouter.resolve({ uri: 'persistv1://check' }).length, 0);

      inspectAppId = 'com.b4.reopen';
      inspectVersion = '1.0.0';
      inspectIntents = [{ action: 'view', scheme: 'reopenapp' }];
      await os1.pkgManager.install(makePkg('reopen.txt', 'hi'), { grantAll: true });
      assert.equal(os1.intentRouter.resolve({ uri: 'reopenapp://open' })[0]?.appId, 'com.b4.reopen');

      await os1.kernel.shutdown();
      os1 = null;

      // 6. SQLite DB reopen automatically re-registers persisted intents in init()
      os2 = wireStack(dbPath);
      await os2.kernel.boot();
      const reopenedMatches = os2.intentRouter.resolve({ action: 'view', uri: 'reopenapp://open' });
      assert.equal(reopenedMatches.length, 1);
      assert.equal(reopenedMatches[0].appId, 'com.b4.reopen');
      // Upgraded app with empty intents remains cleared after reopen too
      assert.equal(os2.intentRouter.resolve({ uri: 'persistv1://check' }).length, 0);
    } finally {
      if (os1) await os1.kernel.shutdown();
      if (os2) await os2.kernel.shutdown();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('B5 & B6: IntentRouter disqualifies file associations on non-file/opaque schemes + deduplicates HKCR; Compositor createWindow leaks zero quota slots on hostile title', () => {
    const bus = new KernelEventBus();
    const cfg = new UnifiedConfigStore({ eventBus: bus });
    const router = new IntentRouter({ eventBus: bus, configStore: cfg });
    const pm = new ProcessManager({ eventBus: bus });
    const comp = new Compositor({ processManager: pm, eventBus: bus });

    try {
      // B5.1: File associations (.txt, .com) MUST NOT hijack custom/https/opaque URL schemes
      router.registerHandlers('ios.myapp', {
        CFBundleURLTypes: [{ CFBundleURLSchemes: ['myapp'] }],
      });
      router.registerHandlers('android.calc', {
        intentFilters: [{ action: 'view', data: [{ scheme: 'omnicalc' }] }],
      });
      router.registerHandlers('win.notepad', {
        fileAssociations: ['.txt', '.com'],
      });

      const myappRes = router.resolve({ action: 'view', uri: 'myapp://open/report.txt' });
      assert.deepEqual(myappRes.map((r) => r.appId), ['ios.myapp']);

      const calcRes = router.resolve({ action: 'view', uri: 'omnicalc://export/result.txt' });
      assert.deepEqual(calcRes.map((r) => r.appId), ['android.calc']);

      const httpsRes = router.resolve({ action: 'view', uri: 'https://example.com/notes.txt' });
      assert.deepEqual(httpsRes, []);

      const mailtoRes = router.resolve({ action: 'view', uri: 'mailto:user@example.com' });
      assert.deepEqual(mailtoRes, []);

      // Valid file:// URI still resolves file-association handler
      const fileRes = router.resolve({ action: 'view', uri: 'file:///home/user/report.txt' });
      assert.deepEqual(fileRes.map((r) => r.appId), ['win.notepad']);

      // B5.2: Repeated indexRegistryAssociations() creates zero duplicate handlers
      cfg.registry.setValue('HKCR', '.note', '', REGISTRY_TYPES.REG_SZ, 'NoteProg');
      cfg.registry.setValue('HKCR', 'NoteProg', 'OmniOSAppId', REGISTRY_TYPES.REG_SZ, 'win.noteapp');
      cfg.registry.setValue('HKCR', 'noteurl', 'URL Protocol', REGISTRY_TYPES.REG_SZ, '');
      cfg.registry.setValue('HKCR', 'noteurl', 'OmniOSAppId', REGISTRY_TYPES.REG_SZ, 'win.noteapp');

      router.indexRegistryAssociations(cfg);
      const countAfter1 = router.listHandlers('win.noteapp')[0].handlers.length;
      router.indexRegistryAssociations(cfg);
      router.indexRegistryAssociations(cfg);
      const countAfter3 = router.listHandlers('win.noteapp')[0].handlers.length;
      assert.equal(countAfter1, 2);
      assert.equal(countAfter3, countAfter1);

      // B6: Compositor.createWindow() leaks ZERO pcb.windowIds slots on hostile opts.title
      const p = pm.spawn({
        name: 'quota-1-app',
        appId: 'universal.q1',
        platform: 'universal',
        quotas: { maxWindows: 1 },
        executionContext: makeWorkExecContext(),
      });

      assert.throws(
        () => comp.createWindow(p.pid, { title: Symbol('bad') }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.equal(p.windowIds.size, 0);

      assert.throws(
        () =>
          comp.createWindow(p.pid, {
            title: {
              toString() {
                throw new Error('hostile toString');
              },
            },
          }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.equal(p.windowIds.size, 0);

      // Subsequent legitimate window succeeds within maxWindows: 1
      const okWin = comp.createWindow(p.pid, { title: 'Legitimate Window' });
      assert.equal(okWin.title, 'Legitimate Window');
      assert.equal(p.windowIds.size, 1);
    } finally {
      cfg.close();
    }
  });
});

// ============================================================================
// SUITE 15: Iteration 3 Adversarial Hardening Regressions (C1–C6 & D1–D4 + Polish)
// ============================================================================

describe('Suite 15: Iteration 3 Adversarial Hardening Regressions (C1–C6 & D1–D4 + Polish)', () => {
  function makeHostileError(tag = 'iter3') {
    const err = {};
    Object.defineProperty(err, 'name', {
      enumerable: true,
      get() {
        throw new Error(`${tag} name getter boom`);
      },
    });
    Object.defineProperty(err, 'message', {
      enumerable: true,
      get() {
        throw new Error(`${tag} message getter boom`);
      },
    });
    Object.defineProperty(err, 'code', {
      enumerable: true,
      get() {
        throw new Error(`${tag} code getter boom`);
      },
    });
    return err;
  }

  function makeHostileProtoProxy(tag = 'proto') {
    return new Proxy(
      {},
      {
        getPrototypeOf() {
          throw new Error(`${tag} trap-getPrototypeOf`);
        },
      }
    );
  }

  function makeRevokedProxy() {
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    return proxy;
  }

  function wireIter3Stack(dbPath) {
    const kernel = new OmniKernel({ dbPath });
    const users = new UserManager({ kernel });
    const permissions = new PermissionBroker({ kernel, userManager: users });
    const vfs = new VFS({ kernel, userManager: users });
    const configStore = new UnifiedConfigStore({ kernel });
    const ipc = new IPCManager({ eventBus: kernel.eventBus, processManager: kernel.processManager });
    const intentRouter = new IntentRouter({
      eventBus: kernel.eventBus,
      processManager: kernel.processManager,
      configStore,
    });
    const clipboard = new SharedClipboard({ eventBus: kernel.eventBus });
    const notifications = new NotificationCenter({
      eventBus: kernel.eventBus,
      configStore,
      processManager: kernel.processManager,
    });
    const compositor = new Compositor({ kernel, configStore });
    const pkgManager = new PackageManager({
      kernel,
      vfs,
      configStore,
      ipc,
      intentRouter,
      clipboard,
      notifications,
      users,
      permissions,
      compositor,
    });
    intentRouter.setLauncher((appId, { intent }) => pkgManager.launch(appId, { intent }));
    registerSecurityService(kernel.serviceManager, { userManager: users, permissionBroker: permissions, kernel, deps: [] });
    registerVfsService(kernel.serviceManager, vfs, { kernel, deps: ['securityd'] });
    registerConfigService(kernel.serviceManager, configStore, { kernel, deps: [] });
    registerIpcBrokerService(kernel.serviceManager, { ipc, router: intentRouter, clipboard, notifications, deps: ['configd'] });
    registerCompositorService(kernel.serviceManager, compositor, { deps: ['configd'] });
    registerPackageService(kernel.serviceManager, pkgManager, { deps: ['securityd', 'vfsd', 'ipc-brokerd', 'compositord'] });
    return { kernel, users, permissions, vfs, configStore, ipc, intentRouter, clipboard, notifications, compositor, pkgManager };
  }

  it('C1: VFS canonicalizes platform-native "/" sandboxRoot across Android/macOS/iOS/Windows, enforces symlinks & rejects ".." in sandboxRoot', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'omnios-m2-c1-'));
    const dbPath = path.join(dir, 'c1.sqlite');
    let storage = null;
    try {
      storage = new SqliteStorage(dbPath);
      const um = new UserManager({ storage });
      const vfs = new VFS({ storage, userManager: um });

      // Seed shared file, outside secret, and writable app containers
      vfs.writeFile('/home/user/Documents/shared.txt', 'hello-c1-shared', { uid: 1000, gid: 1000 });
      vfs.writeFile('/etc/c1-secret.txt', 'root-only-secret', { mode: 0o644, uid: 0, gid: 0 });
      vfs.mkdir('/var/appdata/android/com.a', { recursive: true, mode: 0o755, uid: 0, gid: 0 });
      vfs.chown('/var/appdata/android/com.a', 1000, 1000, { uid: 0, gid: 0 });
      vfs.mkdir('/var/appdata/ios/u1', { recursive: true, mode: 0o755, uid: 0, gid: 0 });
      vfs.chown('/var/appdata/ios/u1', 1000, 1000, { uid: 0, gid: 0 });

      // Android: /sdcard and /data/data/com.a
      assert.equal(
        vfs.readFile('/sdcard/Documents/shared.txt', {
          platform: PLATFORMS.ANDROID,
          sandboxRoot: '/sdcard',
          encoding: 'utf8',
          uid: 1000,
          gid: 1000,
        }),
        'hello-c1-shared'
      );
      vfs.mkdir('/data/data/com.a/sub/deep', {
        recursive: true,
        platform: PLATFORMS.ANDROID,
        sandboxRoot: '/data/data/com.a',
        uid: 1000,
        gid: 1000,
      });
      vfs.writeFile('/data/data/com.a/sub/deep/ok.txt', 'android-nested', {
        platform: PLATFORMS.ANDROID,
        sandboxRoot: '/data/data/com.a',
        uid: 1000,
        gid: 1000,
      });
      assert.equal(
        vfs.readFile('/var/appdata/android/com.a/sub/deep/ok.txt', { encoding: 'utf8', uid: 1000, gid: 1000 }),
        'android-nested'
      );

      // macOS: /Users/user incl. valid internal symlink + escaping symlink EACCES
      assert.equal(
        vfs.readFile('/Users/user/Documents/shared.txt', {
          platform: PLATFORMS.MACOS,
          sandboxRoot: '/Users/user',
          encoding: 'utf8',
          uid: 1000,
          gid: 1000,
        }),
        'hello-c1-shared'
      );
      vfs.symlink('/home/user/Documents/shared.txt', '/home/user/good_link', { uid: 1000, gid: 1000 });
      vfs.symlink('/etc/c1-secret.txt', '/home/user/escape_link', { uid: 1000, gid: 1000 });
      assert.equal(
        vfs.readFile('/Users/user/good_link', {
          platform: PLATFORMS.MACOS,
          sandboxRoot: '/Users/user',
          encoding: 'utf8',
          uid: 1000,
          gid: 1000,
        }),
        'hello-c1-shared'
      );
      assert.throws(
        () =>
          vfs.readFile('/Users/user/escape_link', {
            platform: PLATFORMS.MACOS,
            sandboxRoot: '/Users/user',
            encoding: 'utf8',
            uid: 1000,
            gid: 1000,
          }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EACCES
      );

      // iOS: /var/mobile/Documents and /var/mobile/Containers/Data/Application/u1
      assert.equal(
        vfs.readFile('/var/mobile/Documents/shared.txt', {
          platform: PLATFORMS.IOS,
          sandboxRoot: '/var/mobile/Documents',
          encoding: 'utf8',
          uid: 1000,
          gid: 1000,
        }),
        'hello-c1-shared'
      );
      vfs.mkdir('/var/mobile/Containers/Data/Application/u1/Library/Caches', {
        recursive: true,
        platform: PLATFORMS.IOS,
        sandboxRoot: '/var/mobile/Containers/Data/Application/u1',
        uid: 1000,
        gid: 1000,
      });
      vfs.writeFile('/var/mobile/Containers/Data/Application/u1/Library/Caches/k.txt', 'ios-ok', {
        platform: PLATFORMS.IOS,
        sandboxRoot: '/var/mobile/Containers/Data/Application/u1',
        uid: 1000,
        gid: 1000,
      });
      assert.equal(
        vfs.readFile('/var/appdata/ios/u1/Library/Caches/k.txt', { encoding: 'utf8', uid: 1000, gid: 1000 }),
        'ios-ok'
      );

      // Windows extended-length leading-slash sandboxRoot: //?/C:/Users/user
      const winStat = vfs.stat('//?/C:/Users/user/Documents/shared.txt', {
        platform: PLATFORMS.WINDOWS,
        sandboxRoot: '//?/C:/Users/user',
        uid: 1000,
        gid: 1000,
      });
      assert.equal(winStat.type, 'file');
      assert.equal(
        vfs.readFile('//?/C:/Users/user/Documents/shared.txt', {
          platform: PLATFORMS.WINDOWS,
          sandboxRoot: '//?/C:/Users/user',
          encoding: 'utf8',
          uid: 1000,
          gid: 1000,
        }),
        'hello-c1-shared'
      );
      assert.throws(
        () =>
          vfs.stat('//?/C:/Windows/System32', {
            platform: PLATFORMS.WINDOWS,
            sandboxRoot: '//?/C:/Users/user',
            uid: 1000,
            gid: 1000,
          }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EACCES
      );

      // '..' inside sandboxRoot MUST be rejected across platforms
      const badSandboxRoots = [
        { path: '/sdcard/Documents/shared.txt', platform: PLATFORMS.ANDROID, sandboxRoot: '/sdcard/../etc' },
        { path: '/Users/user/Documents/shared.txt', platform: PLATFORMS.MACOS, sandboxRoot: '/Users/user/../root' },
        { path: '/var/mobile/Documents/shared.txt', platform: PLATFORMS.IOS, sandboxRoot: '/var/mobile/Documents/../../etc' },
        { path: '//?/C:/Users/user/Documents/shared.txt', platform: PLATFORMS.WINDOWS, sandboxRoot: '//?/C:/Users/user/../..' },
        { path: '/home/user/Documents/shared.txt', platform: PLATFORMS.POSIX, sandboxRoot: '/home/user/../etc' },
      ];
      for (const tc of badSandboxRoots) {
        assert.throws(
          () => vfs.stat(tc.path, { platform: tc.platform, sandboxRoot: tc.sandboxRoot, uid: 1000, gid: 1000 }),
          (err) => err instanceof VfsError && err.code === ERROR_CODES.EACCES,
          `Expected EACCES for '..' in sandboxRoot: ${tc.sandboxRoot}`
        );
      }

      // A1 non-widening still holds when strictSandbox app passes platform-native '/sdcard'
      const strictApp = um.allocateAppUid('com.c1.strict', {
        platform: PLATFORMS.IOS,
        sandboxRoot: '/var/appdata/ios/u1',
        strictSandbox: true,
      });
      assert.throws(
        () =>
          vfs.readFile('/sdcard/Documents/shared.txt', {
            platform: PLATFORMS.ANDROID,
            sandboxRoot: '/sdcard',
            uid: strictApp.uid,
            gid: strictApp.gid,
          }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EACCES
      );
    } finally {
      if (storage?.isOpen) storage.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('C2: UnifiedConfigStore Registry VirtualStore domain-separates appId, pid & uid scopes across WAL SQLite reopen', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'omnios-m2-c2-'));
    const dbPath = path.join(dir, 'c2.sqlite');
    let s1 = null;
    let s2 = null;
    try {
      s1 = new SqliteStorage(dbPath);
      const cfg1 = new UnifiedConfigStore({ storage: s1 });

      // Victim 1 writes virtualized HKLM via uid-only context
      cfg1.registry.setValue('HKLM', 'Software\\Bank', 'Token', REGISTRY_TYPES.REG_SZ, 'real-uid-token', {
        uid: 10000,
      });
      // Victim 2 writes virtualized HKLM via pid-only context
      cfg1.registry.setValue('HKLM', 'Software\\Bank', 'PidToken', REGISTRY_TYPES.REG_SZ, 'real-pid-token', {
        pid: 77,
      });

      // Attackers forging appId = 'uid-10000' or 'uid_3130303030' CANNOT read, overwrite, or delete { uid: 10000 }
      for (const attacker of [
        { uid: 10001, appId: 'uid-10000' },
        { uid: 10001, appId: 'uid_3130303030' },
      ]) {
        assert.equal(cfg1.registry.getValue('HKLM', 'Software\\Bank', 'Token', attacker), null);
        cfg1.registry.setValue('HKLM', 'Software\\Bank', 'Token', REGISTRY_TYPES.REG_SZ, 'poisoned', attacker);
        assert.equal(cfg1.registry.getValue('HKLM', 'Software\\Bank', 'Token', attacker)?.data, 'poisoned');
        assert.equal(
          cfg1.registry.getValue('HKLM', 'Software\\Bank', 'Token', { uid: 10000 })?.data,
          'real-uid-token'
        );
        assert.equal(cfg1.registry.deleteValue('HKLM', 'Software\\Bank', 'Token', attacker), true);
        assert.equal(
          cfg1.registry.getValue('HKLM', 'Software\\Bank', 'Token', { uid: 10000 })?.data,
          'real-uid-token'
        );
      }

      // Attackers forging appId = 'pid-77' or { uid: 77 } CANNOT read, overwrite, or delete { pid: 77 }
      for (const attacker of [{ uid: 10001, appId: 'pid-77' }, { uid: 77 }]) {
        assert.equal(cfg1.registry.getValue('HKLM', 'Software\\Bank', 'PidToken', attacker), null);
        cfg1.registry.setValue('HKLM', 'Software\\Bank', 'PidToken', REGISTRY_TYPES.REG_SZ, 'hijacked', attacker);
        assert.equal(
          cfg1.registry.getValue('HKLM', 'Software\\Bank', 'PidToken', { pid: 77 })?.data,
          'real-pid-token'
        );
        assert.equal(cfg1.registry.deleteValue('HKLM', 'Software\\Bank', 'PidToken', attacker), true);
        assert.equal(
          cfg1.registry.getValue('HKLM', 'Software\\Bank', 'PidToken', { pid: 77 })?.data,
          'real-pid-token'
        );
      }

      // Hostile non-string appId rejected with SecurityError
      assert.throws(
        () =>
          cfg1.registry.setValue('HKLM', 'Software\\Bank', 'Bad', REGISTRY_TYPES.REG_SZ, 'x', {
            uid: 10001,
            appId: Symbol('bad-app'),
          }),
        (err) => err instanceof SecurityError
      );

      s1.close();
      s1 = null;

      // Reopen WAL SQLite DB and verify domain separation persists cleanly
      s2 = new SqliteStorage(dbPath);
      const cfg2 = new UnifiedConfigStore({ storage: s2 });
      assert.equal(
        cfg2.registry.getValue('HKLM', 'Software\\Bank', 'Token', { uid: 10000 })?.data,
        'real-uid-token'
      );
      assert.equal(
        cfg2.registry.getValue('HKLM', 'Software\\Bank', 'Token', { uid: 10001, appId: 'uid-10000' }),
        null
      );
      assert.equal(
        cfg2.registry.getValue('HKLM', 'Software\\Bank', 'Token', { uid: 10001, appId: 'uid_3130303030' }),
        null
      );
      assert.equal(
        cfg2.registry.getValue('HKLM', 'Software\\Bank', 'PidToken', { pid: 77 })?.data,
        'real-pid-token'
      );
      assert.equal(
        cfg2.registry.getValue('HKLM', 'Software\\Bank', 'PidToken', { uid: 10001, appId: 'pid-77' }),
        null
      );
    } finally {
      if (s1?.isOpen) s1.close();
      if (s2?.isOpen) s2.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('C3: PathTranslator enforces relative cwd jail on Android & iOS while allowing valid relative paths', () => {
    const pt = new PathTranslator();

    // Blocked Android & iOS relative cwd escapes (MUST throw EACCES / E_PATH_TRAVERSAL)
    const blockedCases = [
      ['../../etc/passwd', { platform: PLATFORMS.ANDROID, appId: 'com.a', cwd: '/sdcard' }],
      ['../../../etc/passwd', { platform: PLATFORMS.ANDROID, appId: 'com.a', cwd: '/sdcard/Documents' }],
      ['../../etc/passwd', { platform: PLATFORMS.ANDROID, appId: 'com.a', cwd: '/storage/emulated/0' }],
      ['../etc', { platform: PLATFORMS.ANDROID, cwd: '/data/data' }],
      ['../1/com.b', { platform: PLATFORMS.ANDROID, cwd: '/data/user/0' }],
      ['../com.b/secret.db', { platform: PLATFORMS.ANDROID, appId: 'com.a', cwd: '/data/data/com.a' }],
      ['0/../..', { platform: PLATFORMS.ANDROID, appId: 'com.a', cwd: '/storage/emulated' }],
      ['../Other', { platform: PLATFORMS.IOS, cwd: '/var/mobile/Containers/Data/Application' }],
      ['../x', { platform: PLATFORMS.IOS, cwd: '/var/containers/Bundle/Application' }],
      ['../u2/secret', { platform: PLATFORMS.IOS, containerUuid: 'u1', cwd: '/var/mobile/Containers/Data/Application/u1' }],
      ['Application/..', { platform: PLATFORMS.IOS, cwd: '/var/mobile/Containers/Data' }],
    ];
    for (const [relPath, opts] of blockedCases) {
      assert.throws(
        () => pt.toCanonical(relPath, opts),
        (err) =>
          err instanceof VfsError &&
          err.code === ERROR_CODES.EACCES &&
          err.details?.violation === ERROR_CODES.E_PATH_TRAVERSAL,
        `Expected traversal jail EACCES for relPath="${relPath}" cwd="${opts.cwd}" (${opts.platform})`
      );
    }

    // Valid relative paths inside Android & iOS roots MUST succeed
    assert.equal(
      pt.toCanonical('Documents/notes.txt', { platform: PLATFORMS.ANDROID, appId: 'com.a', cwd: '/sdcard' })
        .canonicalPath,
      '/home/user/Documents/notes.txt'
    );
    assert.equal(
      pt.toCanonical('../Downloads/pic.png', {
        platform: PLATFORMS.ANDROID,
        appId: 'com.a',
        cwd: '/sdcard/Documents',
      }).canonicalPath,
      '/home/user/Downloads/pic.png'
    );
    assert.equal(
      pt.toCanonical('Pictures/a.jpg', {
        platform: PLATFORMS.ANDROID,
        appId: 'com.a',
        cwd: '/storage/emulated/0',
      }).canonicalPath,
      '/home/user/Pictures/a.jpg'
    );
    assert.equal(
      pt.toCanonical('cache/../files/db.sqlite', {
        platform: PLATFORMS.ANDROID,
        appId: 'com.a',
        cwd: '/data/data/com.a',
      }).canonicalPath,
      '/var/appdata/android/com.a/files/db.sqlite'
    );
    assert.equal(
      pt.toCanonical('shared_prefs/app.xml', {
        platform: PLATFORMS.ANDROID,
        appId: 'com.a',
        cwd: '/data/user/0/com.a',
      }).canonicalPath,
      '/var/appdata/android/com.a/shared_prefs/app.xml'
    );
    assert.equal(
      pt.toCanonical('Documents/../Library/prefs.plist', {
        platform: PLATFORMS.IOS,
        containerUuid: 'u1',
        cwd: '/var/mobile/Containers/Data/Application/u1',
      }).canonicalPath,
      '/var/appdata/ios/u1/Library/prefs.plist'
    );
    assert.equal(
      pt.toCanonical('report.pdf', {
        platform: PLATFORMS.IOS,
        cwd: '/var/mobile/Documents',
      }).canonicalPath,
      '/home/user/Documents/report.pdf'
    );
  });

  it('C4: formatPlistUtcDate atomically clamps out-of-range leap-year dates verified directly by host Python 3 plistlib.loads()', () => {
    const cfg = new UnifiedConfigStore();
    try {
      cfg.defaults.set('com.omnios.leapclamp', 'y0', new Date('0000-02-29T12:00:00Z'));
      cfg.defaults.set('com.omnios.leapclamp', 'yNeg4', new Date('-000004-02-29T12:00:00Z'));
      cfg.defaults.set('com.omnios.leapclamp', 'y10000', new Date('+010000-02-29T12:00:00Z'));
      cfg.defaults.set('com.omnios.leapclamp', 'y0004', new Date('0004-02-29T00:00:00Z'));
      cfg.defaults.set('com.omnios.leapclamp', 'y2024', new Date('2024-02-29T23:59:59Z'));
      cfg.defaults.set('com.omnios.leapclamp', 'y9996', new Date('9996-02-29T12:34:56Z'));

      const xml = cfg.defaults.exportPlistXml('com.omnios.leapclamp');
      assert.equal(xml.includes('0001-02-29'), false, 'Must never emit invalid non-leap 0001-02-29');
      assert.equal(xml.includes('9999-02-29'), false, 'Must never emit invalid non-leap 9999-02-29');

      const pyOut = runPython(
        [
          'import sys, json, plistlib',
          'data = plistlib.loads(sys.stdin.buffer.read())',
          'out = {k: f"{v.year:04d}-{v.month:02d}-{v.day:02d}T{v.hour:02d}:{v.minute:02d}:{v.second:02d}Z" for k, v in data.items()}',
          'print(json.dumps(out, sort_keys=True))',
        ].join('\n'),
        xml
      );
      const parsed = JSON.parse(pyOut.trim());
      assert.deepEqual(parsed, {
        y0: '0001-01-01T00:00:00Z',
        y0004: '0004-02-29T00:00:00Z',
        y10000: '9999-12-31T23:59:59Z',
        y2024: '2024-02-29T23:59:59Z',
        y9996: '9996-02-29T12:34:56Z',
        yNeg4: '0001-01-01T00:00:00Z',
      });
    } finally {
      cfg.close();
    }
  });

  it('C5: VFS.symlink() & VFS.setXattr() enforce length caps & /tmp + SQLite quotas with exact byte reclamation', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'omnios-m2-c5-'));
    const dbPath = path.join(dir, 'c5.sqlite');
    let storage = null;
    try {
      storage = new SqliteStorage(dbPath);
      const um = new UserManager({ storage });
      const vfs = new VFS({ storage, userManager: um, maxStorageBytes: 128, maxTmpBytes: 128 });

      const baseStats = vfs.getStorageStats();
      const baseSqliteUsed = baseStats.usedBytes;
      const baseTmpUsed = baseStats.tmpUsedBytes;

      // 1. VFS.symlink() enforces MAX_PATH_LENGTH (4096) with EINVAL
      const tooLongTarget = 'a'.repeat(MAX_PATH_LENGTH + 1);
      assert.throws(
        () => vfs.symlink(tooLongTarget, '/tmp/long_sym'),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => vfs.symlink(tooLongTarget, '/home/user/long_sym'),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => vfs.symlink('b'.repeat(50000), '/home/user/huge_sym'),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
      );

      // 2. VFS.symlink() enforces /tmp and SQLite storage quotas with ENOSPC
      const overQuotaTarget = 'c'.repeat(200);
      assert.throws(
        () => vfs.symlink(overQuotaTarget, '/tmp/quota_sym'),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.ENOSPC
      );
      assert.throws(
        () => vfs.symlink(overQuotaTarget, '/home/user/quota_sym'),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.ENOSPC
      );

      // Valid symlinks account bytes accurately and unlink reclaims 100%
      const okTarget = 't'.repeat(40);
      vfs.symlink(okTarget, '/tmp/ok_sym');
      assert.equal(vfs.getStorageStats().tmpUsedBytes, baseTmpUsed + 40);
      vfs.unlink('/tmp/ok_sym');
      assert.equal(vfs.getStorageStats().tmpUsedBytes, baseTmpUsed);

      vfs.symlink(okTarget, '/home/user/ok_sym');
      assert.equal(vfs.getStorageStats().usedBytes, baseSqliteUsed + 40);
      vfs.unlink('/home/user/ok_sym');
      assert.equal(vfs.getStorageStats().usedBytes, baseSqliteUsed);

      // 3. VFS.setXattr() enforces MAX_XATTR_NAME_BYTES (255) & storage quotas (/tmp + SQLite)
      vfs.writeFile('/tmp/x.txt', 'a'); // 1 byte
      vfs.writeFile('/home/user/s.txt', 'a'); // 1 byte
      assert.equal(vfs.getStorageStats().tmpUsedBytes, baseTmpUsed + 1);
      assert.equal(vfs.getStorageStats().usedBytes, baseSqliteUsed + 1);

      const longXattrName = `user.${'n'.repeat(251)}`; // 256 bytes > 255
      assert.equal(Buffer.byteLength(longXattrName, 'utf8'), 256);
      assert.throws(
        () => vfs.setXattr('/tmp/x.txt', longXattrName, new Uint8Array(4)),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => vfs.setXattr('/home/user/s.txt', longXattrName, new Uint8Array(4)),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
      );

      // Quota enforcement on /tmp & SQLite xattrs
      assert.throws(
        () => vfs.setXattr('/tmp/x.txt', 'user.bomb', new Uint8Array(200)),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.ENOSPC
      );
      assert.throws(
        () => vfs.setXattr('/home/user/s.txt', 'user.bomb', new Uint8Array(200)),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.ENOSPC
      );

      // Accurate accounting on set, shrink overwrite, removeXattr, and file unlink
      const attrName = 'user.k'; // 6 bytes
      vfs.setXattr('/tmp/x.txt', attrName, new Uint8Array(32));
      assert.equal(vfs.getStorageStats().tmpUsedBytes, baseTmpUsed + 1 + 6 + 32);
      vfs.setXattr('/tmp/x.txt', attrName, new Uint8Array(8));
      assert.equal(vfs.getStorageStats().tmpUsedBytes, baseTmpUsed + 1 + 6 + 8);
      assert.equal(vfs.removeXattr('/tmp/x.txt', attrName), true);
      assert.equal(vfs.getStorageStats().tmpUsedBytes, baseTmpUsed + 1);

      vfs.setXattr('/home/user/s.txt', attrName, new Uint8Array(32));
      assert.equal(vfs.getStorageStats().usedBytes, baseSqliteUsed + 1 + 6 + 32);
      vfs.setXattr('/home/user/s.txt', attrName, new Uint8Array(8));
      assert.equal(vfs.getStorageStats().usedBytes, baseSqliteUsed + 1 + 6 + 8);
      assert.equal(vfs.removeXattr('/home/user/s.txt', attrName), true);
      assert.equal(vfs.getStorageStats().usedBytes, baseSqliteUsed + 1);

      // Unlinking files with active xattrs reclaims both file & xattr bytes
      vfs.setXattr('/tmp/x.txt', attrName, new Uint8Array(20));
      vfs.unlink('/tmp/x.txt');
      assert.equal(vfs.getStorageStats().tmpUsedBytes, baseTmpUsed);

      vfs.setXattr('/home/user/s.txt', attrName, new Uint8Array(20));
      vfs.unlink('/home/user/s.txt');
      assert.equal(vfs.getStorageStats().usedBytes, baseSqliteUsed);
    } finally {
      if (storage?.isOpen) storage.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('C6: PermissionBroker fails closed cleanly on hostile toString/toPrimitive, null-proto, revoked Proxy & Symbol', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'omnios-m2-c6-'));
    const dbPath = path.join(dir, 'c6.sqlite');
    let storage = null;
    try {
      storage = new SqliteStorage(dbPath);
      const um = new UserManager({ storage });
      const pb = new PermissionBroker({ storage, userManager: um });
      pb.setGrant('com.c6.hostile', CAPABILITIES.CAMERA_DEVICE, PERMISSION_STATES.ALLOW);

      const hostileValues = [
        {
          toString() {
            throw new Error('hostile toString boom');
          },
        },
        {
          [Symbol.toPrimitive]() {
            throw new Error('hostile toPrimitive boom');
          },
        },
        Object.create(null),
        makeRevokedProxy(),
        Symbol('evil-permission'),
      ];

      for (const val of hostileValues) {
        // mapNativePermission returns null safely
        assert.equal(mapNativePermission(val, 'android'), null);
        assert.equal(pb.mapNativePermission(val, 'ios'), null);

        // mapNativePermissions places hostile element safely in unmapped without throwing
        const mapped = mapNativePermissions([val, 'android.permission.CAMERA'], 'android');
        assert.deepEqual(mapped.capabilities, [CAPABILITIES.CAMERA_DEVICE]);
        assert.equal(mapped.unmapped.length, 1);
        assert.equal(typeof mapped.unmapped[0], 'string');

        const pbMapped = pb.mapNativePermissions([val], 'windows');
        assert.deepEqual(pbMapped.capabilities, []);
        assert.equal(pbMapped.unmapped.length, 1);

        // checkPermission fails closed on hostile capability or nativePermission
        const resCap = await pb.checkPermission({ appId: 'com.c6.hostile', capability: val });
        assert.equal(resCap.granted, false);
        assert.equal(resCap.policy, PERMISSION_STATES.DENY);
        assert.equal(resCap.reason, 'unknown_capability');

        const resNative = await pb.checkPermission({
          appId: 'com.c6.hostile',
          nativePermission: val,
          platform: 'android',
        });
        assert.equal(resNative.granted, false);
        assert.equal(resNative.policy, PERMISSION_STATES.DENY);
        assert.equal(resNative.reason, 'unmapped_native_permission');

        // Hostile nativePermission alongside valid capability never crashes SQLite audit binding
        const resMixed = await pb.checkPermission({
          appId: 'com.c6.hostile',
          capability: CAPABILITIES.CAMERA_DEVICE,
          nativePermission: val,
          platform: 'android',
        });
        assert.equal(resMixed.granted, true);

        // assertPermission throws typed SecurityError (never raw Error/TypeError)
        await assert.rejects(
          () => pb.assertPermission({ appId: 'com.c6.hostile', capability: val }),
          (err) => err instanceof SecurityError
        );
      }

      const auditRows = pb.getAuditLog({ appId: 'com.c6.hostile', limit: 50 });
      assert.ok(auditRows.length >= hostileValues.length * 2);
    } finally {
      if (storage?.isOpen) storage.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('D1 (+ Obs #2, #3): PackageManager preserves untouched v1 installDir on rename EIO, rejects Symbol expectedSha256 & cleans obsolete cross-platform installDir post-commit', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'omnios-m2-d1-'));
    const dbPath = path.join(dir, 'd1.sqlite');
    let stack = null;
    try {
      stack = wireIter3Stack(dbPath);
      let failWinInstallHook = false;

      stack.pkgManager.registerRuntime('universal', {
        platform: 'universal',
        inspectPackage(_bytes, _hint, detection) {
          return {
            format: detection.format,
            platform: 'universal',
            arch: 'wasm',
            appId: 'com.d1.atomic',
            name: 'D1 Universal',
            version: '1.0.0',
            permissions: [],
            intents: [],
          };
        },
        createExecutionContext() {
          return makeWorkExecContext();
        },
      });

      stack.pkgManager.registerRuntime('windows', {
        platform: 'windows',
        inspectPackage(_bytes, _hint, detection) {
          return {
            format: detection.format,
            platform: 'windows',
            arch: 'x86_64',
            appId: 'com.d1.atomic',
            name: 'D1 Windows',
            version: '2.0.0',
            permissions: [],
            intents: [],
          };
        },
        installPackage() {
          if (failWinInstallHook) {
            throw new OmniOSError('Simulated cross-platform install failure', { code: ERROR_CODES.EINVAL });
          }
          return null;
        },
        createExecutionContext() {
          return makeWorkExecContext();
        },
      });

      await stack.kernel.boot();

      const makeUniPkg = (fileName, body) =>
        createZip([
          { name: 'omnios.manifest.json', data: JSON.stringify({ appId: 'com.d1.atomic', version: '1.0.0' }) },
          { name: 'main.wasm', data: buildWasmFixture() },
          { name: fileName, data: body, method: ZIP_METHODS.STORE },
        ]);

      // Install v1 universal package
      const v1Rec = await stack.pkgManager.install(makeUniPkg('v1.txt', 'live-v1-data'));
      assert.equal(v1Rec.installDir, '/apps/universal/com.d1.atomic');
      assert.equal(stack.vfs.readFile('/apps/universal/com.d1.atomic/v1.txt', { encoding: 'utf8' }), 'live-v1-data');

      // D1: Overwrite install when vfs.rename() throws EIO MUST preserve untouched live v1 installDir
      const origRename = stack.vfs.rename.bind(stack.vfs);
      stack.vfs.rename = () => {
        throw new OmniOSError('Simulated rename EIO', { code: ERROR_CODES.EIO });
      };
      try {
        await assert.rejects(
          () => stack.pkgManager.install(makeUniPkg('v2.txt', 'v2-data'), { overwrite: true }),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EIO
        );
      } finally {
        stack.vfs.rename = origRename;
      }
      assert.equal(stack.pkgManager.get('com.d1.atomic')?.version, '1.0.0');
      assert.equal(
        stack.vfs.readFile('/apps/universal/com.d1.atomic/v1.txt', { encoding: 'utf8' }),
        'live-v1-data',
        'Live untouched v1 installDir must survive failed vfs.rename()'
      );

      // Obs #2: Reject expectedSha256: Symbol() / throwing toString / blank string with OmniOSError(EINVAL)
      for (const badSha of [
        Symbol('bad-sha'),
        {
          toString() {
            throw new Error('sha-toString-boom');
          },
        },
        '   ',
        makeRevokedProxy(),
      ]) {
        await assert.rejects(
          () => stack.pkgManager.install(makeUniPkg('v2.txt', 'x'), { overwrite: true, expectedSha256: badSha }),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
        );
      }
      await assert.rejects(
        () =>
          stack.pkgManager.install(makeUniPkg('v2.txt', 'x'), {
            overwrite: true,
            expectedSha256: '0'.repeat(64),
          }),
        (err) => err instanceof SecurityError && err.code === 'E_HASH_MISMATCH'
      );

      // Obs #3: Cross-platform same-appId overwrite (universal -> windows) cleans obsolete installDir strictly AFTER commit
      const winPkg = buildPeFixture({ pe32Plus: true });

      // Failed cross-platform overwrite must keep old /apps/universal/com.d1.atomic completely intact
      failWinInstallHook = true;
      await assert.rejects(
        () => stack.pkgManager.install(winPkg, { overwrite: true, filenameHint: 'd1.exe' }),
        /Simulated cross-platform install failure/
      );
      failWinInstallHook = false;
      assert.equal(stack.pkgManager.get('com.d1.atomic')?.platform, 'universal');
      assert.equal(stack.vfs.readFile('/apps/universal/com.d1.atomic/v1.txt', { encoding: 'utf8' }), 'live-v1-data');

      // Committed cross-platform overwrite moves to /apps/windows/com.d1.atomic and removes obsolete /apps/universal/com.d1.atomic
      const v2Rec = await stack.pkgManager.install(winPkg, { overwrite: true, filenameHint: 'd1.exe' });
      assert.equal(v2Rec.platform, 'windows');
      assert.equal(v2Rec.installDir, '/apps/windows/com.d1.atomic');
      assert.equal(stack.vfs.stat('/apps/windows/com.d1.atomic').type, 'dir');
      assert.throws(
        () => stack.vfs.stat('/apps/universal/com.d1.atomic'),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.ENOENT
      );
    } finally {
      if (stack) await stack.kernel.shutdown();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('D2: NotificationCenter.post() leaves 0 orphan LiveActivity & 0 premature eviction; updateLiveActivity() stays atomic & synced on NaN progress', () => {
    const nc = new NotificationCenter({ maxNotifications: 2 });
    const n1 = nc.post({ appId: 'app.a', title: 'Notif 1', body: 'one' });
    const n2 = nc.post({ appId: 'app.b', title: 'Notif 2', body: 'two' });

    // Throwing body.toString() must throw OmniOSError(EINVAL), insert 0 orphan LiveActivity, and evict 0 healthy notifications
    assert.throws(
      () =>
        nc.post({
          appId: 'ios.weather',
          title: 'Storm',
          body: {
            toString() {
              throw new Error('body-toString-boom');
            },
          },
          liveActivity: { id: 'la-no-orphan', title: 'Live Storm' },
        }),
      (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
    );
    assert.equal(nc.getLiveActivities().length, 0);
    assert.deepEqual(
      nc
        .list()
        .map((n) => n.id)
        .sort(),
      [n1.id, n2.id].sort()
    );

    // Invalid liveActivity.progress: NaN must also fail atomically with 0 orphan LiveActivity and 0 eviction
    assert.throws(
      () =>
        nc.post({
          appId: 'ios.weather',
          title: 'BadProg',
          liveActivity: { id: 'la-bad-prog', title: 'Bad', progress: Number.NaN },
        }),
      (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
    );
    assert.equal(nc.getLiveActivities().length, 0);
    assert.equal(nc.list().length, 2);

    // updateLiveActivity() with NaN progress leaves BOTH la and linkedNotif.liveActivity untouched and synchronized
    const nc2 = new NotificationCenter();
    const posted = nc2.post({
      appId: 'ios.weather',
      title: 'Forecast',
      liveActivity: { id: 'la-sync', title: 'Sunny', subtitle: '72F', progress: 0.25 },
    });
    assert.throws(
      () =>
        nc2.updateLiveActivity('la-sync', {
          title: 'CORRUPTED_STORM',
          subtitle: '99F',
          progress: Number.NaN,
        }),
      (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
    );

    const laAfterFail = nc2.getLiveActivities().find((item) => item.id === 'la-sync');
    const linkedAfterFail = nc2.get(posted.id)?.liveActivity;
    assert.equal(laAfterFail.title, 'Sunny');
    assert.equal(laAfterFail.subtitle, '72F');
    assert.equal(laAfterFail.progress, 0.25);
    assert.deepEqual(linkedAfterFail, laAfterFail);

    // Subsequent valid update succeeds and keeps la + linkedNotif.liveActivity in sync
    const updated = nc2.updateLiveActivity('la-sync', { title: 'Cloudy', subtitle: '68F', progress: 0.75 });
    assert.equal(updated.title, 'Cloudy');
    assert.equal(updated.progress, 0.75);
    assert.deepEqual(nc2.get(posted.id)?.liveActivity, updated);
  });

  it('D3 (+ Obs #1, #4, #5): Throwing-getPrototypeOf & revoked Proxy inputs never crash uncaught across all M2B subsystems', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'omnios-m2-d3-'));
    const dbPath = path.join(dir, 'd3.sqlite');
    const hostileProto = makeHostileProtoProxy('d3');
    const revoked = makeRevokedProxy();

    const bus = new KernelEventBus();
    const pm = new ProcessManager({ eventBus: bus });
    const ipc = new IPCManager({ eventBus: bus, processManager: pm, defaultRpcTimeoutMs: 2000 });
    const router = new IntentRouter({ eventBus: bus, processManager: pm });
    const clip = new SharedClipboard({ eventBus: bus });
    const nc = new NotificationCenter({ eventBus: bus, processManager: pm });
    const comp = new Compositor({ processManager: pm, eventBus: bus });
    const detector = new FormatDetector();
    let storage = null;

    try {
      // 1. FormatDetector.detect(): returns unknown cleanly (never throws uncaught)
      const detProto = detector.detect(hostileProto);
      assert.equal(detProto.format, PACKAGE_FORMATS.UNKNOWN);
      const detRev = detector.detect(revoked);
      assert.equal(detRev.format, PACKAGE_FORMATS.UNKNOWN);

      // 2. SharedClipboard.set(): throws structured OmniOSError(EINVAL) incl. top-level throwing getter on input
      const topGetterInput = {};
      Object.defineProperty(topGetterInput, 'text', {
        enumerable: true,
        get() {
          throw new Error('top-level input getter boom');
        },
      });
      for (const badInput of [
        { json: revoked },
        { imagePng: hostileProto },
        { formats: revoked },
        revoked,
        topGetterInput,
      ]) {
        assert.throws(
          () => clip.set(badInput),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
        );
      }

      // 3. IPCManager.send() & callRpc() (+ Obs #1 Proxy-wrapped OmniOSError safely re-wrapped)
      ipc.createChannel('ch.d3', 0);
      for (const badPayload of [{ bad: hostileProto }, revoked]) {
        assert.throws(
          () => ipc.send('ch.d3', 0, badPayload),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
        );
      }
      ipc.registerRpc('rpc.d3', async () => ({ ok: true }));
      for (const badPayload of [{ bad: hostileProto }, revoked]) {
        await assert.rejects(
          () => ipc.callRpc('rpc.d3', badPayload),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
        );
      }

      // Obs #1: Hostile Proxy wrapping OmniOSError is re-wrapped into a clean non-Proxy OmniOSError
      ipc.registerRpc('rpc.proxyerr', async () => {
        throw new Proxy(new OmniOSError('inner-secret', { code: ERROR_CODES.EACCES }), {
          get() {
            throw new Error('proxy-wrapped-omni-err-getter-boom');
          },
        });
      });
      let caughtRpcErr = null;
      try {
        await ipc.callRpc('rpc.proxyerr', {});
      } catch (err) {
        caughtRpcErr = err;
      }
      assert.ok(caughtRpcErr instanceof OmniOSError);
      assert.equal(utilTypes.isProxy(caughtRpcErr), false, 'Proxy-wrapped OmniOSError must be re-wrapped cleanly');
      assert.equal(typeof caughtRpcErr.message, 'string');
      assert.equal(typeof caughtRpcErr.code, 'string');
      assert.equal(typeof caughtRpcErr.name, 'string');

      // 4. IntentRouter.dispatch() (+ Obs #4 BigInt label in dedup)
      pm.spawn({ name: 'd3-router-app', appId: 'app.d3.router', executionContext: makeWorkExecContext() });
      router.registerHandlers('app.d3.router', [{ schemes: ['d3test'] }]);
      const dispatchRes = await router.dispatch({
        action: 'view',
        uri: 'd3test://go',
        extras: { badProto: hostileProto, badRev: revoked },
      });
      assert.equal(dispatchRes.status, 'DELIVERED');

      // Obs #4: BigInt label in registerHandlers / _dedupeDescriptors never throws raw TypeError
      router.registerHandlers('app.d3.bigint', [
        { schemes: ['biglab'], label: 42n },
        { schemes: ['biglab'], label: 42n },
      ]);
      assert.equal(router.listHandlers('app.d3.bigint')[0].handlers.length, 1);

      // 5. NotificationCenter.post(): sanitizes nested hostile/revoked Proxies & rejects revoked options
      const safeNotif = nc.post({
        appId: 'app.d3.notif',
        title: 'Safe',
        data: { p: hostileProto, r: revoked },
      });
      assert.equal(safeNotif.data.p, '[Unreadable]');
      assert.equal(safeNotif.data.r, '[Unreadable]');
      assert.throws(
        () => nc.post(revoked),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );

      // 6. Compositor.createWindow() / updateSurface() / setShellMode() (+ Obs #5 Symbol templates)
      const p = pm.spawn({
        name: 'd3-comp-app',
        appId: 'app.d3.comp',
        platform: 'universal',
        quotas: { maxWindows: 2 },
        executionContext: makeWorkExecContext(),
      });

      // Nested hostile/revoked uiTree/icon sanitized cleanly
      const w1 = comp.createWindow(p.pid, { title: 'Sanitized', uiTree: hostileProto, icon: revoked });
      assert.equal(w1.surface.uiTree, '[Unreadable]');
      assert.equal(w1.icon, '[Unreadable]');
      assert.equal(p.windowIds.size, 1);

      // Revoked drawOps array rejected with OmniOSError(EINVAL) & 0 quota leak
      assert.throws(
        () => comp.createWindow(p.pid, { title: 'RevOps', drawOps: revoked }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.equal(p.windowIds.size, 1);

      // updateSurface sanitizes nested proxies and rejects revoked drawOps atomically
      const revBefore = w1.surfaceRevision;
      const w1Upd = comp.updateSurface(w1.windowId, {
        uiTree: { nested: hostileProto },
        drawOps: [{ op: 'rect', bad: revoked }],
      });
      assert.equal(w1Upd.surfaceRevision, revBefore + 1);
      const w1Snap = comp.getWindow(w1.windowId);
      assert.equal(w1Snap.surface.uiTree.nested, '[Unreadable]');
      assert.equal(w1Snap.surface.drawOps[0].bad, '[Unreadable]');

      const revAfter = w1Upd.surfaceRevision;
      assert.throws(
        () => comp.updateSurface(w1.windowId, { drawOps: revoked }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.equal(comp.getWindow(w1.windowId).surfaceRevision, revAfter);

      // Obs #5: Symbol() in setShellMode & createWindow({ state }) throws OmniOSError(EINVAL), not raw TypeError
      assert.throws(
        () => comp.setShellMode(Symbol('bad-mode')),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => comp.createWindow(p.pid, { title: 'BadState', state: Symbol('bad-state') }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.equal(p.windowIds.size, 1);

      // 7. PackageManager: inspect() & registerCatalogEntry() never crash uncaught on hostile/revoked Proxies
      storage = new SqliteStorage(dbPath);
      const pkgMgr = new PackageManager({ storage });
      for (const badBuf of [hostileProto, revoked]) {
        await assert.rejects(
          () => pkgMgr.inspect(badBuf),
          (err) => err instanceof FormatError && err.code === ERROR_CODES.EINVAL
        );
      }
      assert.throws(
        () => pkgMgr.registerCatalogEntry(revoked),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      const catRec = pkgMgr.registerCatalogEntry({
        appId: 'com.d3.cat',
        name: 'D3 Cat',
        platform: 'universal',
        metadata: { badProto: hostileProto, badRev: revoked },
      });
      assert.equal(catRec.metadata.badProto, '[Unreadable]');
      assert.equal(catRec.metadata.badRev, '[Unreadable]');
    } finally {
      ipc.stop();
      if (storage?.isOpen) storage.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('D4: Compositor with throwing log() dispatching input to async-rejecting deliverEvent produces 0 unhandledRejections', async () => {
    const beforeUnhandled = unhandledRejections.length;
    const bus = new KernelEventBus();
    const pm = new ProcessManager({ eventBus: bus });
    const comp = new Compositor({
      processManager: pm,
      eventBus: bus,
      log: () => {
        throw new Error('log-fail');
      },
    });

    const pAsync = pm.spawn({
      name: 'd4-async-reject',
      appId: 'app.d4.async',
      platform: 'universal',
      executionContext: makeWorkExecContext({
        async onEvent() {
          throw new Error('async-deliver-err');
        },
      }),
    });
    const pAsyncHostile = pm.spawn({
      name: 'd4-async-hostile',
      appId: 'app.d4.async.hostile',
      platform: 'universal',
      executionContext: makeWorkExecContext({
        async onEvent() {
          throw makeHostileError('d4-async-hostile');
        },
      }),
    });
    const pSync = pm.spawn({
      name: 'd4-sync-throw',
      appId: 'app.d4.sync',
      platform: 'universal',
      executionContext: makeWorkExecContext({
        onEvent() {
          throw new Error('sync-deliver-err');
        },
      }),
    });

    const wAsync = comp.createWindow(pAsync.pid, { title: 'AsyncReject' });
    const wAsyncHostile = comp.createWindow(pAsyncHostile.pid, { title: 'AsyncHostile' });
    const wSync = comp.createWindow(pSync.pid, { title: 'SyncThrow' });

    assert.doesNotThrow(() => comp.dispatchInput(wAsync.windowId, { type: 'click', x: 12, y: 24 }));
    assert.doesNotThrow(() => comp.dispatchInput(wAsyncHostile.windowId, { type: 'click', x: 15, y: 30 }));
    assert.doesNotThrow(() => comp.dispatchInput(wSync.windowId, { type: 'keydown', key: 'Enter' }));

    await new Promise((r) => setTimeout(r, 40));
    assert.equal(unhandledRejections.length, beforeUnhandled);
  });
});

// ============================================================================
// SUITE 16: Iteration 4 Security, Proxy/RangeError & Cross-Platform Sandbox
//           Regressions (E1–E3, F1–F3, Obs #1–#4)
// ============================================================================

describe('Suite 16: Iteration 4 Security, Proxy/RangeError & Cross-Platform Sandbox Regressions (E1–E3, F1–F3, Obs #1–#4)', () => {
  function makeRevokedObjProxy() {
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    return proxy;
  }

  function makeRevokedArrProxy() {
    const { proxy, revoke } = Proxy.revocable([], {});
    revoke();
    return proxy;
  }

  function makeThrowingProtoObj(tag = 'obj-proto') {
    return new Proxy(
      {},
      {
        getPrototypeOf() {
          throw new Error(`${tag}-boom`);
        },
      }
    );
  }

  function makeThrowingProtoArr(items, tag = 'arr-proto') {
    return new Proxy(items, {
      getPrototypeOf() {
        throw new Error(`${tag}-boom`);
      },
    });
  }

  function makeInvalidLengthArrProxy(badLength) {
    return new Proxy([], {
      get(target, key, receiver) {
        if (key === 'length') return badLength;
        return Reflect.get(target, key, receiver);
      },
    });
  }

  function wireIter4Stack(dbPath, { withPermissions = true } = {}) {
    const kernel = new OmniKernel({ dbPath });
    const users = new UserManager({ kernel });
    const permissions = withPermissions ? new PermissionBroker({ kernel, userManager: users }) : null;
    const vfs = new VFS({ kernel, userManager: users });
    const configStore = new UnifiedConfigStore({ kernel });
    const ipc = new IPCManager({ eventBus: kernel.eventBus, processManager: kernel.processManager });
    const intentRouter = new IntentRouter({
      eventBus: kernel.eventBus,
      processManager: kernel.processManager,
      configStore,
    });
    const clipboard = new SharedClipboard({ eventBus: kernel.eventBus });
    const notifications = new NotificationCenter({
      eventBus: kernel.eventBus,
      configStore,
      processManager: kernel.processManager,
    });
    const compositor = new Compositor({ kernel, configStore });
    const pkgManager = new PackageManager({
      kernel,
      vfs,
      configStore,
      ipc,
      intentRouter,
      clipboard,
      notifications,
      users,
      permissions,
      compositor,
    });
    intentRouter.setLauncher((appId, { intent }) => pkgManager.launch(appId, { intent }));
    registerSecurityService(kernel.serviceManager, {
      userManager: users,
      permissionBroker: permissions ?? new PermissionBroker({ kernel, userManager: users }),
      kernel,
      deps: [],
    });
    registerVfsService(kernel.serviceManager, vfs, { kernel, deps: ['securityd'] });
    registerConfigService(kernel.serviceManager, configStore, { kernel, deps: [] });
    registerIpcBrokerService(kernel.serviceManager, {
      ipc,
      router: intentRouter,
      clipboard,
      notifications,
      deps: ['configd'],
    });
    registerCompositorService(kernel.serviceManager, compositor, { deps: ['configd'] });
    registerPackageService(kernel.serviceManager, pkgManager, {
      deps: ['securityd', 'vfsd', 'ipc-brokerd', 'compositord'],
    });
    return {
      kernel,
      users,
      permissions,
      vfs,
      configStore,
      ipc,
      intentRouter,
      clipboard,
      notifications,
      compositor,
      pkgManager,
    };
  }

  it('16.1 (E1): UnifiedConfigStore.resolveRegContext fails closed on non-number UIDs, preserves pcb.uid on uid:null, isolates non-elevated root & rejects revoked Proxy ctx', () => {
    const cfg = new UnifiedConfigStore();
    try {
      // Seed global HKLM and HKCR as privileged root
      cfg.registry.setValue('HKLM', 'Software\\Sys', 'Secret', REGISTRY_TYPES.REG_SZ, 'orig', { uid: 0 });
      cfg.registry.setValue('HKCR', '.exe\\shell\\open\\command', '', REGISTRY_TYPES.REG_SZ, 'safe.exe', { uid: 0 });

      const invalidContexts = [
        { uid: '10000' },
        { uid: 'bad' },
        { uid: '0' },
        { uid: 10000n },
        { uid: {} },
        { uid: Symbol('u') },
        { pcb: { uid: '10000' } },
        { uid: null, pcb: { uid: '10000' } },
        makeRevokedObjProxy(),
      ];

      for (const badCtx of invalidContexts) {
        assert.throws(
          () => cfg.registry.setValue('HKLM', 'Software\\Sys', 'Secret', REGISTRY_TYPES.REG_SZ, 'pwned', badCtx),
          (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
        );
        assert.throws(
          () => cfg.registry.setValue('HKCR', '.exe\\shell\\open\\command', '', REGISTRY_TYPES.REG_SZ, 'evil.exe', badCtx),
          (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
        );
        assert.throws(
          () => cfg.registry.deleteKey('HKLM', 'Software\\Sys', badCtx),
          (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
        );
        assert.throws(
          () => cfg.registry.deleteKey('HKCR', '.exe\\shell\\open\\command', badCtx),
          (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
        );
      }

      // Global HKLM and HKCR MUST remain completely untouched
      assert.equal(cfg.registry.getValue('HKLM', 'Software\\Sys', 'Secret', { uid: 0 })?.data, 'orig');
      assert.equal(cfg.registry.getValue('HKCR', '.exe\\shell\\open\\command', '', { uid: 0 })?.data, 'safe.exe');

      // { uid: null, pcb: { uid: 10000 } } MUST virtualize under uid 10000 and leave global HKLM unchanged
      const virtRes = cfg.registry.setValue(
        'HKLM',
        'Software\\Sys',
        'Secret',
        REGISTRY_TYPES.REG_SZ,
        'virt-10000',
        { uid: null, pcb: { uid: 10000 } }
      );
      assert.equal(virtRes.virtualized, true);
      assert.equal(cfg.registry.getValue('HKLM', 'Software\\Sys', 'Secret', { uid: 0 })?.data, 'orig');
      assert.equal(cfg.registry.getValue('HKLM', 'Software\\Sys', 'Secret', { uid: 10000 })?.data, 'virt-10000');
      assert.equal(
        cfg.registry.getValue('HKLM', 'Software\\Sys', 'Secret', { uid: null, pcb: { uid: 10000 } })?.data,
        'virt-10000'
      );

      // { uid: 0, elevated: false } stays isolated from global HKLM and from uid 10000
      const nonElevRoot = cfg.registry.setValue(
        'HKLM',
        'Software\\Sys',
        'Secret',
        REGISTRY_TYPES.REG_SZ,
        'non-elev-root',
        { uid: 0, elevated: false }
      );
      assert.equal(nonElevRoot.virtualized, true);
      assert.equal(cfg.registry.getValue('HKLM', 'Software\\Sys', 'Secret', { uid: 0 })?.data, 'orig');
      assert.equal(cfg.registry.getValue('HKLM', 'Software\\Sys', 'Secret', { uid: 10000 })?.data, 'virt-10000');
      assert.equal(
        cfg.registry.getValue('HKLM', 'Software\\Sys', 'Secret', { uid: 0, elevated: false })?.data,
        'non-elev-root'
      );

      // Explicit Reviewer 1 (G1a) assertions: { uid: null }, { pcb: { uid: null } }, and
      // { uid: null, pcb: { uid: null } } MUST fail closed (never escalate to ROOT):
      // HKLM writes virtualize, HKCR writes target HKCU (not global HKLM), global HKLM deleteKey
      // throws SecurityError(EACCES), '..' traversal is rejected, and global HKLM/HKCR stay untouched.
      cfg.registry.setValue('HKLM', 'Software\\SysProtected', 'Locked', REGISTRY_TYPES.REG_SZ, 'immutable', { uid: 0 });
      const nullUidContexts = [
        { uid: null },
        { pcb: { uid: null } },
        { uid: null, pcb: { uid: null } },
      ];
      for (let i = 0; i < nullUidContexts.length; i += 1) {
        const nullCtx = nullUidContexts[i];

        // Global HKLM deleteKey denied with SecurityError(EACCES)
        assert.throws(
          () => cfg.registry.deleteKey('HKLM', 'Software\\SysProtected', nullCtx),
          (err) => err instanceof SecurityError && err.code === ERROR_CODES.EACCES
        );

        // '..' traversal rejected on both writes and reads for unprivileged null-UID contexts
        assert.throws(
          () => cfg.registry.setValue('HKLM', 'Software\\..\\Sys', 'Secret', REGISTRY_TYPES.REG_SZ, 'trav', nullCtx),
          (err) => err instanceof SecurityError && err.code === ERROR_CODES.E_PATH_TRAVERSAL
        );
        assert.throws(
          () => cfg.registry.getValue('HKLM', 'Software\\..\\Sys', 'Secret', nullCtx),
          (err) => err instanceof SecurityError && err.code === ERROR_CODES.E_PATH_TRAVERSAL
        );

        // HKLM write virtualizes into __VIRTUALSTORE__ (never global HKLM)
        const hklmRes = cfg.registry.setValue(
          'HKLM',
          'Software\\Sys',
          'Secret',
          REGISTRY_TYPES.REG_SZ,
          `null-virt-${i}`,
          nullCtx
        );
        assert.equal(hklmRes.virtualized, true);
        assert.notEqual(hklmRes.actualHive, REGISTRY_HIVES.HKLM);

        // HKCR write targets HKCU\Software\Classes (never global HKLM\Software\Classes)
        const hkcrRes = cfg.registry.setValue(
          'HKCR',
          '.exe\\shell\\open\\command',
          '',
          REGISTRY_TYPES.REG_SZ,
          `user-null-${i}.exe`,
          nullCtx
        );
        assert.equal(hkcrRes.actualHive, REGISTRY_HIVES.HKCU);
        assert.notEqual(hkcrRes.actualHive, REGISTRY_HIVES.HKLM);

        // Global HKLM and HKLM\Software\Classes remain completely untouched
        assert.equal(cfg.registry.getValue('HKLM', 'Software\\Sys', 'Secret', { uid: 0 })?.data, 'orig');
        assert.equal(cfg.registry.getValue('HKLM', 'Software\\SysProtected', 'Locked', { uid: 0 })?.data, 'immutable');
        assert.equal(
          cfg.registry.getValue('HKLM', 'Software\\Classes\\.exe\\shell\\open\\command', '', { uid: 0 })?.data,
          'safe.exe'
        );
      }

      // Clean up per-user HKCU override and confirm global HKCR still resolves to untouched global value
      cfg.registry.deleteKey('HKCU', 'Software\\Classes\\.exe', { uid: 0 });
      assert.equal(cfg.registry.getValue('HKCR', '.exe\\shell\\open\\command', '', { uid: 0 })?.data, 'safe.exe');
    } finally {
      cfg.close();
    }
  });

  it('16.2 (E2): PermissionBroker isolates revoked/invalid-length Array Proxies in mapNativePermissions & hostile reasons in cancelAllPendingPrompts', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'omnios-m2-e2-'));
    const dbPath = path.join(dir, 'e2.sqlite');
    let storage = null;
    try {
      storage = new SqliteStorage(dbPath);
      const pb = new PermissionBroker({ storage, promptTimeoutMs: 5000 });

      const revokedArr = makeRevokedArrProxy();
      const negLenArr = makeInvalidLengthArrProxy(-1);
      const overflowLenArr = makeInvalidLengthArrProxy(0x100000000);

      for (const badList of [revokedArr, negLenArr, overflowLenArr]) {
        assert.throws(
          () => mapNativePermissions(badList, 'android'),
          (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
        );
        assert.throws(
          () => pb.mapNativePermissions(badList, 'android'),
          (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
        );
      }

      // Throwing element trap on Array Proxy is safely handled without crashing
      const throwingElemArr = new Proxy(['android.permission.CAMERA', 'placeholder'], {
        get(target, key, receiver) {
          if (key === '1') throw new Error('element-trap-boom');
          return Reflect.get(target, key, receiver);
        },
      });
      const mapped = mapNativePermissions(throwingElemArr, 'android');
      assert.deepEqual(mapped.capabilities, [CAPABILITIES.CAMERA_DEVICE]);
      assert.deepEqual(mapped.unmapped, ['[Unreadable]']);

      // cancelAllPendingPrompts(hostileReason) settles pending checkPermission fail-closed & records clean audit rows
      const hostileReasons = [
        {
          toString() {
            throw new Error('boom');
          },
        },
        Symbol('r'),
        makeRevokedObjProxy(),
        9007199254740993n,
      ];

      for (let i = 0; i < hostileReasons.length; i += 1) {
        const appId = `com.e2.cancel.${i}`;
        const pending = pb.checkPermission({ appId, capability: CAPABILITIES.CAMERA_DEVICE });
        // Yield a macrotask so prompt is registered as pending
        await new Promise((r) => setTimeout(r, 5));
        const cancelled = pb.cancelAllPendingPrompts(hostileReasons[i]);
        assert.equal(cancelled, 1);

        const res = await pending;
        assert.equal(res.granted, false);
        assert.equal(typeof res.reason, 'string');
        assert.ok(res.reason.length > 0);

        const auditRows = pb.getAuditLog({ appId, limit: 10 });
        assert.ok(auditRows.length >= 1, `Expected security_audit row for ${appId}`);
        assert.equal(auditRows[0].granted, false);
        assert.equal(typeof auditRows[0].reason, 'string');
        assert.ok(auditRows[0].reason.length > 0);
      }
    } finally {
      if (storage?.isOpen) storage.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('16.3 (E3): UnifiedConfigStore guards revoked, throwing-getPrototypeOf & invalid-length Proxies while preserving E_CYCLIC_PLIST & valid Array Proxy cloning', () => {
    const cfg = new UnifiedConfigStore();
    try {
      const revObj = makeRevokedObjProxy();
      const revArr = makeRevokedArrProxy();
      const throwingProto = makeThrowingProtoObj('e3');
      const negLenArr = makeInvalidLengthArrProxy(-1);
      const overflowLenArr = makeInvalidLengthArrProxy(0x100000000);

      // defaults.set() rejects all hostile proxies with OmniOSError(EINVAL)
      for (const bad of [revObj, revArr, throwingProto, negLenArr, overflowLenArr]) {
        assert.throws(
          () => cfg.defaults.set('com.e3.test', 'k', bad),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
        );
      }

      // sharedPrefs.edit() rejects hostile ops arrays & hostile operation values with OmniOSError(EINVAL)
      for (const badOps of [revObj, revArr, throwingProto, negLenArr, overflowLenArr]) {
        assert.throws(
          () => cfg.sharedPrefs.edit('com.e3.test', 'prefs', badOps),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
        );
      }
      for (const badVal of [revObj, revArr, throwingProto, negLenArr, overflowLenArr]) {
        assert.throws(
          () => cfg.sharedPrefs.edit('com.e3.test', 'prefs', [{ op: 'put', key: 'k', value: badVal }]),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
        );
      }

      // registry.setValue() REG_BINARY & REG_MULTI_SZ reject hostile proxies with OmniOSError(EINVAL)
      for (const badBin of [revObj, revArr, throwingProto, negLenArr, overflowLenArr]) {
        assert.throws(
          () => cfg.registry.setValue('HKCU', 'Software\\E3', 'Bin', REGISTRY_TYPES.REG_BINARY, badBin),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
        );
      }
      for (const badMulti of [revObj, revArr, throwingProto, negLenArr, overflowLenArr]) {
        assert.throws(
          () => cfg.registry.setValue('HKCU', 'Software\\E3', 'Multi', REGISTRY_TYPES.REG_MULTI_SZ, badMulti),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
        );
      }

      // Cyclic graph MUST still throw FormatError(E_CYCLIC_PLIST)
      const cyclic = { name: 'loop' };
      cyclic.self = cyclic;
      assert.throws(
        () => cfg.defaults.set('com.e3.test', 'cyc', cyclic),
        (err) => err instanceof FormatError && err.code === ERROR_CODES.E_CYCLIC_PLIST
      );

      // Valid Proxy-wrapped Arrays (both normal Proxy and throwing-getPrototypeOf Array Proxy) clone cleanly
      const plainArrProxy = new Proxy(['alpha', 'beta'], {});
      const protoArrProxy = makeThrowingProtoArr(['gamma', 'delta'], 'e3-arr');

      cfg.defaults.set('com.e3.test', 'arrPlain', plainArrProxy);
      cfg.defaults.set('com.e3.test', 'arrProto', protoArrProxy);
      assert.deepEqual(cfg.defaults.get('com.e3.test', 'arrPlain'), ['alpha', 'beta']);
      assert.deepEqual(cfg.defaults.get('com.e3.test', 'arrProto'), ['gamma', 'delta']);

      cfg.sharedPrefs.edit('com.e3.test', 'prefs', [
        { op: 'put', key: 'tags', value: new Proxy(['one', 'two'], {}) },
      ]);
      assert.deepEqual(cfg.sharedPrefs.get('com.e3.test', 'prefs', 'tags'), ['one', 'two']);

      cfg.registry.setValue('HKCU', 'Software\\E3', 'MultiOk', REGISTRY_TYPES.REG_MULTI_SZ, protoArrProxy);
      assert.deepEqual(cfg.registry.getValue('HKCU', 'Software\\E3', 'MultiOk')?.data, ['gamma', 'delta']);
    } finally {
      cfg.close();
    }
  });

  it('16.4 (F1 & Obs #2): Compositor preserves Proxy-wrapped Arrays under maxDrawOps, keeps updateSurface atomic, prevents TOCTOU .length crash & guards viewport/opts', async () => {
    const kernel = new OmniKernel({ storage: new SqliteStorage(':memory:') });
    await kernel.boot();
    try {
      const hostileProtoArr = makeThrowingProtoArr([{ op: 'rect', x: 1 }], 'f1-ops');
      const hostileMenuArr = makeThrowingProtoArr([{ id: 'file', label: 'File', items: [] }], 'f1-menu');
      const negLenArr = makeInvalidLengthArrProxy(-1);
      const overflowLenArr = makeInvalidLengthArrProxy(0x100000000);
      const revoked = makeRevokedObjProxy();

      // constructor defaultMenuBar keeps genuine Array when given Proxy-wrapped Array with throwing getPrototypeOf
      const comp = new Compositor({ kernel, maxDrawOps: 5, defaultMenuBar: hostileMenuArr });
      assert.equal(Array.isArray(comp.getActiveMenuBar()), true);
      assert.equal(comp.getActiveMenuBar()[0].label, 'File');

      const pcb = kernel.processManager.spawn({
        name: 'f1-app',
        appId: 'com.f1.app',
        platform: 'universal',
        quotas: { maxWindows: 4 },
        executionContext: makeWorkExecContext(),
      });

      // createWindow keeps genuine Arrays for drawOps and menuBar
      const w0 = comp.createWindow(pcb.pid, {
        title: 'ProxyArraysWin',
        drawOps: hostileProtoArr,
        menuBar: hostileMenuArr,
      });
      assert.equal(Array.isArray(w0.surface.drawOps), true);
      assert.equal(w0.surface.drawOps.length, 1);
      assert.equal(w0.surface.drawOps[0].op, 'rect');
      assert.equal(Array.isArray(w0.menuBar), true);
      assert.equal(w0.menuBar[0].id, 'file');

      // maxDrawOps=5 quota enforced on Proxy-wrapped Array (never bypassed or char-spread as '[Unreadable]')
      const w1 = comp.createWindow(pcb.pid, {
        title: 'QuotaWin',
        drawOps: [{ op: 'a' }, { op: 'b' }, { op: 'c' }, { op: 'd' }],
      });
      comp.updateSurface(w1.windowId, { appendDrawOps: hostileProtoArr });
      const w1Snap = comp.getWindow(w1.windowId);
      assert.equal(Array.isArray(w1Snap.surface.drawOps), true);
      assert.equal(w1Snap.surface.drawOps.length, 5);
      assert.deepEqual(w1Snap.surface.drawOps[4], { op: 'rect', x: 1 });

      // Exceeding maxDrawOps=5 with hostileProtoArr throws QuotaExceededError cleanly
      assert.throws(
        () => comp.updateSurface(w1.windowId, { appendDrawOps: hostileProtoArr }),
        (err) => err instanceof QuotaExceededError && err.code === ERROR_CODES.EQUOTA
      );
      assert.equal(comp.getWindow(w1.windowId).surface.drawOps.length, 5);

      // updateSurface() remains 100% atomic on unreadable drawOps/appendDrawOps (-1 and 0x100000000)
      const w2 = comp.createWindow(pcb.pid, {
        title: 'AtomicTitle',
        drawOps: [{ op: 'orig' }],
      });
      const beforeRev = w2.surfaceRevision;
      for (const badPatch of [
        { title: 'MUTATED_1', drawOps: negLenArr, appendDrawOps: [{ op: 'x' }] },
        { title: 'MUTATED_2', drawOps: overflowLenArr },
        { title: 'MUTATED_3', appendDrawOps: negLenArr },
        { title: 'MUTATED_4', appendDrawOps: overflowLenArr },
      ]) {
        assert.throws(
          () => comp.updateSurface(w2.windowId, badPatch),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
        );
        const snap = comp.getWindow(w2.windowId);
        assert.equal(snap.title, 'AtomicTitle');
        assert.deepEqual(snap.surface.drawOps, [{ op: 'orig' }]);
        assert.equal(snap.surfaceRevision, beforeRev);
      }

      // TOCTOU .length Proxy throwing on 2nd .length read:
      // Case A: returns 0 on 1st read -> succeeds cleanly because appendLen === 0 is reused without re-reading .length
      let toctouReads0 = 0;
      const toctouEmptyProxy = new Proxy([], {
        get(target, key, receiver) {
          if (key === 'length') {
            toctouReads0 += 1;
            if (toctouReads0 >= 2) throw new Error('toctou-second-length-boom');
            return 0;
          }
          return Reflect.get(target, key, receiver);
        },
      });
      const toctouRes = comp.updateSurface(w2.windowId, { title: 'AfterToctou', appendDrawOps: toctouEmptyProxy });
      assert.equal(toctouReads0, 1);
      assert.equal(toctouRes.surfaceRevision, beforeRev + 1);
      assert.equal(comp.getWindow(w2.windowId).title, 'AfterToctou');

      // Case B: returns 1 on 1st read and throws on 2nd read -> caught cleanly & throws OmniOSError(EINVAL) atomically
      let toctouReads1 = 0;
      const toctouNonEmptyProxy = new Proxy([{ op: 'x' }], {
        get(target, key, receiver) {
          if (key === 'length') {
            toctouReads1 += 1;
            if (toctouReads1 >= 2) throw new Error('toctou-second-length-boom');
            return 1;
          }
          return Reflect.get(target, key, receiver);
        },
      });
      const revBeforeB = comp.getWindow(w2.windowId).surfaceRevision;
      assert.throws(
        () => comp.updateSurface(w2.windowId, { title: 'ShouldNotCommit', appendDrawOps: toctouNonEmptyProxy }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.equal(comp.getWindow(w2.windowId).title, 'AfterToctou');
      assert.equal(comp.getWindow(w2.windowId).surfaceRevision, revBeforeB);

      // Obs #2: revoked viewport/insets Proxy & throwing opts.width getter -> OmniOSError(EINVAL), 0 leaked quota slots
      assert.throws(
        () => new Compositor({ kernel, viewport: revoked }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => comp.setViewport(800, 600, revoked),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      const slotsBefore = pcb.windowIds.size;
      assert.throws(
        () =>
          comp.createWindow(pcb.pid, {
            title: 'BadWidth',
            get width() {
              throw new Error('w');
            },
          }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.equal(pcb.windowIds.size, slotsBefore);
    } finally {
      await kernel.shutdown();
    }
  });

  it('16.5 (F2): All 6 M2B cloners isolate invalid Array Proxy lengths (-1 & 0x100000000) & PackageManager rejects hostile permissions/intents with clean rollback', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'omnios-m2-f2-'));
    const negLenArr = makeInvalidLengthArrProxy(-1);
    const overflowLenArr = makeInvalidLengthArrProxy(0x100000000);
    const invalidArrs = [negLenArr, overflowLenArr];

    const bus = new KernelEventBus();
    const pm = new ProcessManager({ eventBus: bus });
    const nc = new NotificationCenter({ eventBus: bus, processManager: pm });
    const router = new IntentRouter({ eventBus: bus, processManager: pm });
    const comp = new Compositor({ eventBus: bus, processManager: pm });
    const clip = new SharedClipboard({ eventBus: bus });
    const ipc = new IPCManager({ eventBus: bus, processManager: pm, defaultRpcTimeoutMs: 2000 });

    let storageCat = null;
    let stackWithBroker = null;
    let stackNoBroker = null;

    try {
      const p = pm.spawn({
        name: 'f2-app',
        appId: 'app.f2.target',
        platform: 'universal',
        executionContext: makeWorkExecContext(),
      });
      const win = comp.createWindow(p.pid, { title: 'F2Win' });
      router.registerHandlers('app.f2.target', [{ schemes: ['f2scheme'] }]);
      ipc.createChannel('ch.f2', 0);
      ipc.registerRpc('rpc.f2.echo', async (payload) => payload);
      ipc.registerRpc('rpc.f2.returnBadNeg', async () => negLenArr);
      ipc.registerRpc('rpc.f2.returnBadOver', async () => overflowLenArr);

      storageCat = new SqliteStorage(path.join(dir, 'cat.sqlite'));
      const pkgCat = new PackageManager({ storage: storageCat });

      const baseNotif = nc.post({
        appId: 'app.f2.target',
        title: 'BaseLA',
        liveActivity: { id: 'la-f2', title: 'Track' },
      });
      assert.ok(baseNotif.liveActivity);

      for (let idx = 0; idx < invalidArrs.length; idx += 1) {
        const badArr = invalidArrs[idx];

        // 1. NotificationCenter.post & updateLiveActivity (never RangeError)
        const n = nc.post({ appId: 'app.f2.target', title: `N${idx}`, data: badArr });
        assert.equal(n.data, '[Unreadable]');
        const la = nc.updateLiveActivity('la-f2', { payload: badArr });
        assert.equal(la.payload, '[Unreadable]');

        // 2. IntentRouter.dispatch (never RangeError)
        const dRes = router.dispatch({ action: 'view', uri: 'f2scheme://open', extras: badArr });
        assert.equal(dRes.status, 'DELIVERED');

        // 3. Compositor.dispatchInput (never RangeError)
        assert.doesNotThrow(() => comp.dispatchInput(win.windowId, { type: 'click', detail: badArr }));

        // 4. PackageManager.registerCatalogEntry (never RangeError)
        const cRec = pkgCat.registerCatalogEntry({
          appId: `com.f2.cat.${idx}`,
          name: `F2 Cat ${idx}`,
          platform: 'universal',
          metadata: badArr,
        });
        assert.equal(cRec.metadata, '[Unreadable]');

        // 5. SharedClipboard.set -> OmniOSError(EINVAL), never RangeError
        assert.throws(
          () => clip.set({ json: badArr }),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
        );

        // 6. IPCManager.send & callRpc -> OmniOSError(EINVAL), never RangeError
        assert.throws(
          () => ipc.send('ch.f2', 0, badArr),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
        );
        await assert.rejects(
          () => ipc.callRpc('rpc.f2.echo', badArr),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
        );
      }

      // RPC returning invalid-length Array Proxy -> rejects with OmniOSError(EINVAL)
      await assert.rejects(
        () => ipc.callRpc('rpc.f2.returnBadNeg', {}),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      await assert.rejects(
        () => ipc.callRpc('rpc.f2.returnBadOver', {}),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );

      // PackageManager.install() when runtime returns hostile/unreadable permissions or intents (BOTH with and without PermissionBroker)
      const hostileRuntimeVariants = [
        { label: 'negLenPerms', perms: negLenArr, intents: [] },
        { label: 'overflowIntents', perms: [], intents: overflowLenArr },
        { label: 'revokedPerms', perms: makeRevokedArrProxy(), intents: [] },
        { label: 'stringPerms', perms: 'android.permission.CAMERA', intents: [] },
        { label: 'nonArrIntents', perms: [], intents: { schemes: ['x'] } },
      ];

      for (const withPermissions of [true, false]) {
        const dbFile = path.join(dir, withPermissions ? 'pkg-with-pb.sqlite' : 'pkg-no-pb.sqlite');
        const stack = wireIter4Stack(dbFile, { withPermissions });
        if (withPermissions) stackWithBroker = stack;
        else stackNoBroker = stack;

        let activeVariant = hostileRuntimeVariants[0];
        let failInInspect = false;

        stack.pkgManager.registerRuntime('universal', {
          platform: 'universal',
          inspectPackage(_bytes, _hint, detection) {
            return {
              format: detection.format,
              platform: 'universal',
              arch: 'wasm',
              appId: `com.f2.bad.${activeVariant.label}`,
              name: 'Hostile Runtime App',
              version: '1.0.0',
              permissions: failInInspect ? activeVariant.perms : [],
              intents: failInInspect ? activeVariant.intents : [],
            };
          },
          installPackage() {
            if (failInInspect) return null;
            return {
              permissions: activeVariant.perms,
              intents: activeVariant.intents,
            };
          },
          createExecutionContext() {
            return makeWorkExecContext();
          },
        });

        await stack.kernel.boot();

        const uapp = buildUappFixture();
        for (const variant of hostileRuntimeVariants) {
          activeVariant = variant;

          // Case 1: hostile returned from installPackage() (after VFS extraction -> verifies clean rollback!)
          failInInspect = false;
          await assert.rejects(
            () => stack.pkgManager.install(uapp),
            (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL,
            `Expected OmniOSError(EINVAL) for installPackage ${variant.label} (withPermissions=${withPermissions})`
          );

          // Verify zero persisted records, zero "[Unreadable]" rows, and rolled-back VFS installDir
          const appId = `com.f2.bad.${variant.label}`;
          assert.equal(stack.pkgManager.get(appId), null);
          assert.equal(
            stack.kernel.storage.get('SELECT app_id FROM installed_packages WHERE app_id = ?', appId),
            null
          );
          assert.throws(
            () => stack.vfs.stat(`/apps/universal/${appId}`),
            (e) => e instanceof VfsError && e.code === ERROR_CODES.ENOENT
          );

          // Case 2: hostile Array Proxies returned from inspectPackage() reject with OmniOSError(EINVAL),
          // while non-Array primitives/objects normalize safely to [] (never crashing or persisting "[Unreadable]")
          failInInspect = true;
          if (variant.label === 'negLenPerms' || variant.label === 'overflowIntents' || variant.label === 'revokedPerms') {
            await assert.rejects(
              () => stack.pkgManager.install(uapp),
              (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
            );
            assert.equal(stack.pkgManager.get(appId), null);
          } else {
            const inspected = await stack.pkgManager.inspect(uapp);
            assert.equal(Array.isArray(inspected.permissions), true);
            assert.equal(Array.isArray(inspected.intents), true);
            assert.deepEqual(inspected.permissions, []);
            assert.deepEqual(inspected.intents, []);
          }
        }

        // Verify valid Proxy-wrapped Array with throwing getPrototypeOf still installs cleanly as genuine JSON Arrays!
        failInInspect = false;
        activeVariant = {
          label: 'validprotoarr',
          perms: makeThrowingProtoArr(['android.permission.CAMERA'], 'f2-rt-perm'),
          intents: makeThrowingProtoArr([{ schemes: ['f2valid'] }], 'f2-rt-intent'),
        };
        const installedOk = await stack.pkgManager.install(uapp);
        assert.equal(Array.isArray(installedOk.permissions), true);
        assert.deepEqual(installedOk.permissions, ['android.permission.CAMERA']);
        assert.equal(Array.isArray(installedOk.intents), true);
        assert.equal(installedOk.intents.length, 1);
        const row = stack.kernel.storage.get(
          'SELECT permissions_json, intents_json FROM installed_packages WHERE app_id = ?',
          'com.f2.bad.validprotoarr'
        );
        assert.deepEqual(JSON.parse(row.permissions_json), ['android.permission.CAMERA']);
        assert.equal(Array.isArray(JSON.parse(row.intents_json)), true);
      }
    } finally {
      ipc.stop();
      if (storageCat?.isOpen) storageCat.close();
      if (stackWithBroker) await stackWithBroker.kernel.shutdown();
      if (stackNoBroker) await stackNoBroker.kernel.shutdown();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('16.6 (F3): IntentRouter & zip.mjs isolate Symbol() and revoked Proxy inputs into typed OmniOSError / FormatError', () => {
    const router = new IntentRouter();
    router.registerHandlers('app.a', [{ schemes: ['myapp'] }]);
    const revoked = makeRevokedObjProxy();

    // IntentRouter F3 vectors
    assert.throws(
      () => router.dispatch({ action: 'view', uri: 'myapp://x', preferredAppId: Symbol('bad') }),
      (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
    );
    assert.throws(
      () => router.resolveChooser(Symbol('req'), 'app.a'),
      (err) => err instanceof OmniOSError && err.code === ERROR_CODES.ENOENT
    );
    assert.throws(
      () => router.registerHandlers('app.c', [revoked]),
      (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
    );
    assert.throws(
      () => router.setDefaultHandler(revoked, 'app.a'),
      (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
    );

    // zip.mjs F3 vectors
    const validZip = createZip([{ name: 'a.txt', data: 'hi' }]);

    assert.throws(
      () => createZip([{ name: 'a.txt', data: 'hi', method: Symbol('m') }]),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.EINVAL
    );
    assert.throws(
      () => listZipEntries(validZip, revoked),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.EINVAL
    );
    assert.throws(
      () => readZip(validZip, revoked),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.EINVAL
    );
    assert.throws(
      () => extractZipEntry(validZip, revoked),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.EINVAL
    );
    assert.throws(
      () => createZip([revoked]),
      (err) => err instanceof FormatError && err.code === ERROR_CODES.EINVAL
    );
  });

  it('16.7 (Obs #1): UserManager.updateAppSandbox persists across WAL reopen & PackageManager cross-platform overwrite updates and rolls back sandbox atomically', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'omnios-m2-obs1-'));
    const umDbPath = path.join(dir, 'um-obs1.sqlite');
    const osDbPath = path.join(dir, 'os-obs1.sqlite');
    let s1 = null;
    let s2 = null;
    let stack = null;

    try {
      // Part A: UserManager.updateAppSandbox standalone + WAL SQLite reopen + validation
      s1 = new SqliteStorage(umDbPath);
      const um1 = new UserManager({ storage: s1 });

      const app1 = um1.allocateAppUid('com.obs1.solo', {
        platform: 'universal',
        sandboxRoot: '/var/appdata/universal/com.obs1.solo',
        strictSandbox: false,
      });
      assert.equal(app1.uid, SANDBOX_UID_BASE);
      assert.equal(app1.strictSandbox, false);

      // allocateAppUid remains 100% idempotent
      const app1Again = um1.allocateAppUid('com.obs1.solo', {
        platform: 'android',
        sandboxRoot: '/var/appdata/android/com.obs1.solo',
        strictSandbox: true,
      });
      assert.equal(app1Again.uid, app1.uid);
      assert.equal(app1Again.sandboxRoot, '/var/appdata/universal/com.obs1.solo');
      assert.equal(app1Again.strictSandbox, false);

      // updateAppSandbox updates platform, sandboxRoot, home & strictSandbox atomically
      const updated = um1.updateAppSandbox('com.obs1.solo', {
        platform: 'android',
        sandboxRoot: '/var/appdata/android/com.obs1.solo',
        strictSandbox: true,
      });
      assert.equal(updated.uid, app1.uid);
      assert.equal(updated.platform, 'android');
      assert.equal(updated.sandboxRoot, '/var/appdata/android/com.obs1.solo');
      assert.equal(updated.home, '/var/appdata/android/com.obs1.solo');
      assert.equal(updated.strictSandbox, true);
      assert.equal(um1.getAppUser('com.obs1.solo')?.sandboxRoot, '/var/appdata/android/com.obs1.solo');
      assert.equal(um1.checkSandboxAccess(app1.uid, '/var/appdata/android/com.obs1.solo/a.txt').allowed, true);
      assert.equal(um1.checkSandboxAccess(app1.uid, '/var/appdata/universal/com.obs1.solo/a.txt').allowed, false);

      // Reject missing/invalid inputs cleanly
      assert.throws(
        () => um1.updateAppSandbox('com.obs1.missing', { platform: 'android' }),
        (err) => err instanceof SecurityError && err.code === ERROR_CODES.ENOENT
      );
      for (const badOpts of [
        { sandboxRoot: '/var/appdata/../etc' },
        { sandboxRoot: '' },
        { sandboxRoot: Symbol('r') },
        { platform: 123 },
        { platform: '..' },
        { strictSandbox: 'yes' },
        makeRevokedObjProxy(),
      ]) {
        assert.throws(
          () => um1.updateAppSandbox('com.obs1.solo', badOpts),
          (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
        );
      }

      // Close & reopen WAL SQLite to confirm persistence and allocateAppUid idempotency
      s1.close();
      s1 = null;

      s2 = new SqliteStorage(umDbPath);
      const um2 = new UserManager({ storage: s2 });
      const persisted = um2.getUserByAppId('com.obs1.solo');
      assert.equal(persisted.uid, app1.uid);
      assert.equal(persisted.platform, 'android');
      assert.equal(persisted.sandboxRoot, '/var/appdata/android/com.obs1.solo');
      assert.equal(persisted.strictSandbox, true);
      assert.equal(um2.allocateAppUid('com.obs1.solo').uid, app1.uid);
      s2.close();
      s2 = null;

      // Part B: End-to-end PackageManager cross-platform overwrite (universal -> android same appId) & post-update rollback
      stack = wireIter4Stack(osDbPath);

      stack.pkgManager.registerRuntime('universal', {
        platform: 'universal',
        inspectPackage(_bytes, _hint, detection) {
          return {
            format: detection.format,
            platform: 'universal',
            arch: 'wasm',
            appId: 'com.obs1.cross',
            name: 'CrossApp Universal',
            version: '1.0.0',
            permissions: [],
            intents: [],
          };
        },
        createExecutionContext() {
          return makeWorkExecContext();
        },
      });

      stack.pkgManager.registerRuntime('android', {
        platform: 'android',
        inspectPackage(_bytes, _hint, detection) {
          return {
            format: detection.format,
            platform: 'android',
            arch: 'dalvik',
            appId: 'com.obs1.cross',
            name: 'CrossApp Android',
            version: '2.0.0',
            permissions: ['android.permission.CAMERA'],
            intents: [],
          };
        },
        createExecutionContext() {
          return makeWorkExecContext();
        },
      });

      await stack.kernel.boot();

      const uniPkg = createZip([
        { name: 'omnios.manifest.json', data: JSON.stringify({ appId: 'com.obs1.cross', version: '1.0.0' }) },
        { name: 'main.wasm', data: buildWasmFixture() },
        { name: 'v1.txt', data: 'universal-v1-live', method: ZIP_METHODS.STORE },
      ]);
      const apkPkg = buildApkFixture([
        { name: 'assets/v2.txt', data: 'android-v2-live', method: ZIP_METHODS.STORE },
      ]);

      // Install v1 (universal) -> uid 10000, strictSandbox: false
      const v1 = await stack.pkgManager.install(uniPkg);
      assert.equal(v1.uid, SANDBOX_UID_BASE);
      assert.equal(v1.platform, 'universal');
      assert.equal(v1.dataDir, '/var/appdata/universal/com.obs1.cross');
      assert.equal(stack.users.getUserByAppId('com.obs1.cross')?.strictSandbox, false);

      // Write app state into v1 universal dataDir as app UID 10000
      stack.vfs.writeFile(`${v1.dataDir}/v1-state.txt`, 'v1-secret', { uid: v1.uid, gid: v1.gid });

      // Forced post-update rollback: fail permissions.setGrant AFTER UserManager.updateAppSandbox has executed!
      const origSetGrant = stack.permissions.setGrant.bind(stack.permissions);
      stack.permissions.setGrant = () => {
        throw new OmniOSError('Simulated post-sandbox-update grant failure', { code: ERROR_CODES.EIO });
      };
      try {
        await assert.rejects(
          () => stack.pkgManager.install(apkPkg, { overwrite: true, grantAll: true }),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EIO
        );
      } finally {
        stack.permissions.setGrant = origSetGrant;
      }

      // Verify rollback restored UserManager sandbox, v1 files, and package record cleanly!
      const userAfterRollback = stack.users.getUserByAppId('com.obs1.cross');
      assert.equal(userAfterRollback.platform, 'universal');
      assert.equal(userAfterRollback.sandboxRoot, '/var/appdata/universal/com.obs1.cross');
      assert.equal(userAfterRollback.strictSandbox, false);
      assert.equal(stack.pkgManager.get('com.obs1.cross')?.platform, 'universal');
      assert.equal(
        stack.vfs.readFile('/apps/universal/com.obs1.cross/v1.txt', { encoding: 'utf8' }),
        'universal-v1-live'
      );
      assert.equal(
        stack.vfs.readFile(`${v1.dataDir}/v1-state.txt`, { encoding: 'utf8', uid: v1.uid, gid: v1.gid }),
        'v1-secret'
      );

      // Now commit cross-platform overwrite (universal -> android)
      const v2 = await stack.pkgManager.install(apkPkg, { overwrite: true, grantAll: true });
      assert.equal(v2.uid, v1.uid);
      assert.equal(v2.platform, 'android');
      assert.equal(v2.dataDir, '/var/appdata/android/com.obs1.cross');

      const userV2 = stack.users.getUserByAppId('com.obs1.cross');
      assert.equal(userV2.platform, 'android');
      assert.equal(userV2.sandboxRoot, '/var/appdata/android/com.obs1.cross');
      assert.equal(userV2.strictSandbox, true);

      // App UID 10000 CAN write & read inside new record.dataDir (/var/appdata/android/com.obs1.cross)
      stack.vfs.writeFile(`${v2.dataDir}/android-state.json`, '{"ok":true}', { uid: v2.uid, gid: v2.gid });
      assert.equal(
        stack.vfs.readFile(`${v2.dataDir}/android-state.json`, { encoding: 'utf8', uid: v2.uid, gid: v2.gid }),
        '{"ok":true}'
      );

      // Escape back to old universal sandbox or shared /home/user fails with VfsError(EACCES)
      assert.throws(
        () => stack.vfs.readFile(`${v1.dataDir}/v1-state.txt`, { uid: v2.uid, gid: v2.gid }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EACCES
      );
      assert.throws(
        () => stack.vfs.writeFile('/home/user/escape.txt', 'nope', { uid: v2.uid, gid: v2.gid }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EACCES
      );
    } finally {
      if (s1?.isOpen) s1.close();
      if (s2?.isOpen) s2.close();
      if (stack) await stack.kernel.shutdown();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('16.8 (Obs #3 & Obs #4): PackageManager guards catalog icon & launch Symbol args (0 orphan PCBs) & IPCManager re-wraps one-shot accessor OmniOSErrors', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'omnios-m2-obs34-'));
    const dbPath = path.join(dir, 'obs34.sqlite');
    let stack = null;

    try {
      stack = wireIter4Stack(dbPath);
      stack.pkgManager.registerRuntime('universal', {
        platform: 'universal',
        inspectPackage(_bytes, _hint, detection) {
          return {
            format: detection.format,
            platform: 'universal',
            arch: 'wasm',
            appId: 'com.obs3.launch',
            name: 'Obs3 Launch App',
            version: '1.0.0',
            permissions: [],
            intents: [],
          };
        },
        createExecutionContext() {
          return makeWorkExecContext();
        },
      });

      await stack.kernel.boot();

      // Obs #3a: registerCatalogEntry with throwing icon.toString() or Symbol icon -> OmniOSError(EINVAL)
      assert.throws(
        () =>
          stack.pkgManager.registerCatalogEntry({
            appId: 'com.obs3.cat1',
            name: 'Cat1',
            platform: 'universal',
            icon: {
              toString() {
                throw new Error('icon-toString-boom');
              },
            },
          }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () =>
          stack.pkgManager.registerCatalogEntry({
            appId: 'com.obs3.cat2',
            name: 'Cat2',
            platform: 'universal',
            icon: Symbol('ico'),
          }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );

      // Obs #3b: launch(appId, { args: [Symbol('a')] }) -> OmniOSError(EINVAL) with ZERO orphan PCBs leaked
      await stack.pkgManager.install(buildUappFixture());
      const pcbsBefore = stack.kernel.processManager.getAll().length;

      await assert.rejects(
        () => stack.pkgManager.launch('com.obs3.launch', { args: [Symbol('a')] }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.equal(stack.kernel.processManager.getAll().length, pcbsBefore, 'Must leak 0 orphan PCBs on invalid launch args');

      // Obs #4: IPCManager.callRpc throwing a non-Proxy OmniOSError with a one-shot stateful message getter
      function makeOneShotOmniError(tag) {
        const err = new OmniOSError('initial', { code: ERROR_CODES.EACCES });
        let reads = 0;
        Object.defineProperty(err, 'message', {
          configurable: true,
          enumerable: false,
          get() {
            reads += 1;
            if (reads > 1) {
              throw new Error(`${tag}-one-shot-message-boom`);
            }
            return `${tag}-first-read-message`;
          },
        });
        return err;
      }

      stack.ipc.registerRpc('rpc.obs4.async', async () => {
        throw makeOneShotOmniError('async');
      });
      stack.ipc.registerRpc('rpc.obs4.sync', () => {
        throw makeOneShotOmniError('sync');
      });
      stack.ipc.registerRpc('rpc.obs4.reject', () => Promise.reject(makeOneShotOmniError('reject')));

      for (const method of ['rpc.obs4.async', 'rpc.obs4.sync', 'rpc.obs4.reject']) {
        let caught = null;
        try {
          await stack.ipc.callRpc(method, {});
        } catch (err) {
          caught = err;
        }
        assert.ok(caught instanceof OmniOSError, `Expected OmniOSError from ${method}`);
        assert.equal(utilTypes.isProxy(caught), false);
        assert.equal(Object.getOwnPropertyDescriptor(caught, 'message')?.get, undefined);
        // Must be readable repeatedly without throwing!
        const firstMsg = caught.message;
        assert.equal(typeof firstMsg, 'string');
        assert.ok(firstMsg.length > 0);
        for (let r = 0; r < 5; r += 1) {
          assert.equal(caught.message, firstMsg);
        }
      }

      // Also verify channel request/reply with one-shot accessor OmniOSError
      stack.ipc.createChannel('ch.obs4', 0);
      stack.ipc.subscribe('ch.obs4', (env) => {
        if (env.correlationId) {
          stack.ipc.reply(env.correlationId, null, { error: makeOneShotOmniError('reply') });
        }
      });
      let replyErr = null;
      try {
        await stack.ipc.request('ch.obs4', 0, { ping: 1 });
      } catch (err) {
        replyErr = err;
      }
      assert.ok(replyErr instanceof OmniOSError);
      assert.equal(utilTypes.isProxy(replyErr), false);
      assert.equal(Object.getOwnPropertyDescriptor(replyErr, 'message')?.get, undefined);
      const firstReplyMsg = replyErr.message;
      assert.equal(typeof firstReplyMsg, 'string');
      for (let r = 0; r < 5; r += 1) {
        assert.equal(replyErr.message, firstReplyMsg);
      }
    } finally {
      if (stack) await stack.kernel.shutdown();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ============================================================================
// SUITE 17: Iteration 5 Security, OOM/Proxy, Lifecycle & Cross-Module Parity Regressions
// ============================================================================

describe('Suite 17: Iteration 5 Security, OOM/Proxy, Lifecycle & Cross-Module Parity Regressions (G1–G5, H1–H4, Obs-R1/R2/A/B1/B2)', () => {
  function makeRevokedObjProxy() {
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    return proxy;
  }

  function wireIter5Stack(dbPath, { withPermissions = true } = {}) {
    const kernel = new OmniKernel({ dbPath });
    const users = new UserManager({ kernel });
    const permissions = withPermissions ? new PermissionBroker({ kernel, userManager: users }) : null;
    const vfs = new VFS({ kernel, userManager: users });
    const configStore = new UnifiedConfigStore({ kernel });
    const ipc = new IPCManager({ eventBus: kernel.eventBus, processManager: kernel.processManager });
    const intentRouter = new IntentRouter({
      eventBus: kernel.eventBus,
      processManager: kernel.processManager,
      configStore,
    });
    const clipboard = new SharedClipboard({ eventBus: kernel.eventBus });
    const notifications = new NotificationCenter({
      eventBus: kernel.eventBus,
      configStore,
      processManager: kernel.processManager,
    });
    const compositor = new Compositor({ kernel, configStore });
    const pkgManager = new PackageManager({
      kernel,
      vfs,
      configStore,
      ipc,
      intentRouter,
      clipboard,
      notifications,
      users,
      permissions,
      compositor,
    });
    intentRouter.setLauncher((appId, { intent }) => pkgManager.launch(appId, { intent }));
    registerSecurityService(kernel.serviceManager, {
      userManager: users,
      permissionBroker: permissions ?? new PermissionBroker({ kernel, userManager: users }),
      kernel,
      deps: [],
    });
    registerVfsService(kernel.serviceManager, vfs, { kernel, deps: ['securityd'] });
    registerConfigService(kernel.serviceManager, configStore, { kernel, deps: [] });
    registerIpcBrokerService(kernel.serviceManager, {
      ipc,
      router: intentRouter,
      clipboard,
      notifications,
      deps: ['configd'],
    });
    registerCompositorService(kernel.serviceManager, compositor, { deps: ['configd'] });
    registerPackageService(kernel.serviceManager, pkgManager, {
      deps: ['securityd', 'vfsd', 'ipc-brokerd', 'compositord'],
    });
    return {
      kernel,
      users,
      permissions,
      vfs,
      configStore,
      ipc,
      intentRouter,
      clipboard,
      notifications,
      compositor,
      pkgManager,
    };
  }

  it('17.1 (G1b): Anonymous unprivileged VirtualStore contexts stay strictly isolated from uid: 10000', () => {
    const cfg = new UnifiedConfigStore();
    try {
      // Seed uid: 10000 (SANDBOX_UID_BASE) private VirtualStore entry
      const seed = cfg.registry.setValue(
        'HKLM',
        'Software\\App10000',
        'ApiKey',
        REGISTRY_TYPES.REG_SZ,
        'secret-10000',
        { uid: SANDBOX_UID_BASE }
      );
      assert.equal(seed.virtualized, true);
      assert.equal(
        cfg.registry.getValue('HKLM', 'Software\\App10000', 'ApiKey', { uid: SANDBOX_UID_BASE })?.data,
        'secret-10000'
      );

      const anonContexts = [
        { uid: null },
        { pcb: { uid: null } },
        { uid: null, pcb: { uid: null } },
        { elevated: false },
      ];

      for (let i = 0; i < anonContexts.length; i += 1) {
        const anonCtx = anonContexts[i];

        // Anonymous callers MUST NOT read uid: 10000's private VirtualStore entry
        assert.equal(
          cfg.registry.getValue('HKLM', 'Software\\App10000', 'ApiKey', anonCtx),
          null
        );

        // Anonymous write virtualizes into its own isolated bucket and NEVER overwrites uid: 10000
        const wRes = cfg.registry.setValue(
          'HKLM',
          'Software\\App10000',
          'ApiKey',
          REGISTRY_TYPES.REG_SZ,
          `tampered-${i}`,
          anonCtx
        );
        assert.equal(wRes.virtualized, true);
        assert.equal(
          cfg.registry.getValue('HKLM', 'Software\\App10000', 'ApiKey', { uid: SANDBOX_UID_BASE })?.data,
          'secret-10000'
        );

        // Anonymous deleteValue / deleteKey only touch anonymous scope and NEVER delete uid: 10000's entry
        cfg.registry.deleteValue('HKLM', 'Software\\App10000', 'ApiKey', anonCtx);
        cfg.registry.deleteKey('HKLM', 'Software\\App10000', anonCtx);
        assert.equal(
          cfg.registry.getValue('HKLM', 'Software\\App10000', 'ApiKey', { uid: SANDBOX_UID_BASE })?.data,
          'secret-10000'
        );
      }

      // Bidirectional check: uid: 10000 cannot see anonymous-only VirtualStore entries either
      cfg.registry.setValue('HKLM', 'Software\\AnonOnly', 'Marker', REGISTRY_TYPES.REG_SZ, 'anon-val', { uid: null });
      assert.equal(cfg.registry.getValue('HKLM', 'Software\\AnonOnly', 'Marker', { uid: SANDBOX_UID_BASE }), null);
      assert.equal(cfg.registry.getValue('HKLM', 'Software\\AnonOnly', 'Marker', { uid: 0 }), null);
    } finally {
      cfg.close();
    }
  });

  it('17.2 (G2, Obs-R1 & Cross-Module Parity): Fake/Proxy 4 GiB ArrayBuffer DoS bomb & spoofed Date/Set reject instantaneously across all M2A & M2B modules', async () => {
    const fakeAb = Object.assign(Object.create(ArrayBuffer.prototype), { length: 0x100000000, 0: 0x41 });
    const proxyAb = new Proxy(new ArrayBuffer(4), {
      get(t, k) {
        return k === 'length' ? 0x100000000 : t[k];
      },
    });
    const spoofDate = Object.assign(Object.create(Date.prototype), {
      getTime: () => 1000,
      toISOString: () => 123n,
    });
    const proxyDate = new Proxy(new Date(1000), {});
    const spoofSet = Object.defineProperties(Object.create(Set.prototype), {
      size: { value: 1, enumerable: true, configurable: true },
      [Symbol.iterator]: {
        value: function* () {
          yield 'spoof-item';
        },
        enumerable: true,
        configurable: true,
      },
    });
    const proxySet = new Proxy(new Set(['proxied-item']), {});

    const t0 = performance.now();

    const cfg = new UnifiedConfigStore();
    const vfs = new VFS();
    const pb = new PermissionBroker();
    const bus = new KernelEventBus();
    const pm = new ProcessManager({ eventBus: bus });
    const ipc = new IPCManager({ eventBus: bus, processManager: pm });
    const clip = new SharedClipboard({ eventBus: bus });
    const nc = new NotificationCenter({ eventBus: bus, processManager: pm });
    const router = new IntentRouter({ eventBus: bus, processManager: pm });
    const comp = new Compositor({ eventBus: bus, processManager: pm });
    const pkg = new PackageManager();
    const detector = new FormatDetector();

    try {
      const proc = pm.spawn({
        name: 'g2-proc',
        appId: 'com.g2.app',
        platform: 'universal',
        executionContext: makeWorkExecContext(),
      });
      const win = comp.createWindow(proc.pid, { title: 'G2Win' });
      ipc.createChannel('ch.g2', 0);

      const deliveredIntents = [];
      router.registerHandlers('com.g2.app', [{ schemes: ['g2scheme'] }]);
      bus.on('intent:delivered', (evt) => deliveredIntents.push(evt));

      // 1. UnifiedConfigStore: defaults.set, registry.REG_BINARY, system.set, sharedPrefs.edit (Set)
      for (const bad of [fakeAb, proxyAb, spoofDate, proxyDate]) {
        assert.throws(
          () => cfg.defaults.set('com.g2', 'k', bad),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
        );
        assert.throws(
          () => cfg.system.set('custom.g2.key', bad),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
        );
      }
      for (const badBin of [fakeAb, proxyAb, spoofDate]) {
        assert.throws(
          () => cfg.registry.setValue('HKCU', 'Software\\G2', 'Bin', REGISTRY_TYPES.REG_BINARY, badBin),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
        );
      }
      for (const badSet of [spoofSet, proxySet]) {
        assert.throws(
          () => cfg.sharedPrefs.edit('com.g2', 'prefs', [{ op: 'put', key: 'tags', value: badSet }]),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
        );
      }

      // 2. VFS.writeFile
      for (const bad of [fakeAb, proxyAb, spoofDate]) {
        assert.throws(
          () => vfs.writeFile('/home/user/g2-bomb.bin', bad, { uid: DEFAULT_USER_UID }),
          (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
        );
      }

      // 3. PermissionBroker.checkPermission (instant fail-closed + sanitized audit context, zero OOM/BigInt crash)
      const pbSpoofedBinOrDate = [fakeAb, proxyAb, spoofDate, proxyDate];
      for (let i = 0; i < pbSpoofedBinOrDate.length; i += 1) {
        const appId = `com.g2.pb.${i}`;
        const res = await pb.checkPermission({
          appId,
          capability: CAPABILITIES.FS_WRITE_SYSTEM,
          context: pbSpoofedBinOrDate[i],
        });
        assert.equal(res.granted, false);
        const rows = pb.getAuditLog({ appId, limit: 5 });
        assert.ok(rows.length >= 1);
        assert.equal(rows[0].context, '[UnreadableObject]');
      }
      for (let i = 0; i < 2; i += 1) {
        const appId = `com.g2.pb.set.${i}`;
        const res = await pb.checkPermission({
          appId,
          capability: CAPABILITIES.FS_WRITE_SYSTEM,
          context: [spoofSet, proxySet][i],
        });
        assert.equal(res.granted, false);
        const rows = pb.getAuditLog({ appId, limit: 5 });
        assert.ok(rows.length >= 1);
      }

      // 4. IPCManager.send (instant OmniOSError(EINVAL), queue stays empty)
      for (const bad of [fakeAb, proxyAb, spoofDate, proxyDate]) {
        assert.throws(
          () => ipc.send('ch.g2', 0, bad),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
        );
      }
      assert.equal(ipc.listChannels().find((c) => c.name === 'ch.g2')?.queueSize, 0);

      // 5. SharedClipboard.set (both json and imagePng paths)
      for (const bad of [fakeAb, proxyAb, spoofDate, proxyDate]) {
        assert.throws(
          () => clip.set({ json: bad }),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
        );
      }
      for (const badBin of [fakeAb, proxyAb]) {
        assert.throws(
          () => clip.set({ imagePng: badBin }),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
        );
      }

      // 6. NotificationCenter.post (instant sanitization to '[Unreadable]')
      for (let i = 0; i < 4; i += 1) {
        const bad = [fakeAb, proxyAb, spoofDate, proxyDate][i];
        const posted = nc.post({ appId: 'com.g2.app', title: `G2-${i}`, data: bad });
        assert.equal(posted.data, '[Unreadable]');
      }

      // 7. IntentRouter.dispatch (instant sanitization of extras to '[Unreadable]')
      for (const bad of [fakeAb, proxyAb, spoofDate, proxyDate]) {
        const res = router.dispatch({ action: 'view', uri: 'g2scheme://open', extras: bad });
        assert.equal(res.status, 'DELIVERED');
      }
      assert.equal(deliveredIntents.length, 4);
      for (const evt of deliveredIntents) {
        assert.equal(evt.intent.extras, '[Unreadable]');
      }

      // 8. Compositor.dispatchInput (instant sanitization, zero hang/OOM)
      for (const bad of [fakeAb, proxyAb, spoofDate, proxyDate]) {
        assert.doesNotThrow(() => comp.dispatchInput(win.windowId, { type: 'click', detail: bad }));
      }
      const receivedEvents = proc.executionContext.receivedEvents.filter((e) => e.type === 'click');
      assert.equal(receivedEvents.length, 4);
      for (const evt of receivedEvents) {
        assert.equal(evt.detail, '[Unreadable]');
      }

      // 9. zip.mjs (createZip & readZip)
      for (const bad of [fakeAb, proxyAb, spoofDate]) {
        assert.throws(
          () => createZip([{ name: 'bomb.bin', data: bad }]),
          (err) => err instanceof FormatError && err.code === ERROR_CODES.EINVAL
        );
        assert.throws(
          () => readZip(bad),
          (err) => err instanceof FormatError && err.code === ZIP_ERROR_CODES.E_MALFORMED_ZIP
        );
      }
      // Spoofed/Proxy Date mtime safely falls back to deterministic default without throwing BigInt/TypeError
      const safeZipFromSpoofMtime = createZip([{ name: 'ok.txt', data: 'ok', mtime: spoofDate }]);
      const safeZip = readZip(safeZipFromSpoofMtime);
      assert.equal(safeZip.entries.size, 1);
      assert.equal(safeZip.readText('ok.txt'), 'ok');

      // 10. FormatDetector.detect (instant PACKAGE_FORMATS.UNKNOWN, zero throw/hang)
      for (const bad of [fakeAb, proxyAb, spoofDate]) {
        const det = detector.detect(bad);
        assert.equal(det.format, PACKAGE_FORMATS.UNKNOWN);
      }

      // 11. PackageManager.registerCatalogEntry (instant sanitization of metadata to '[Unreadable]')
      const pkgBads = [fakeAb, proxyAb, spoofDate, proxyDate];
      for (let i = 0; i < pkgBads.length; i += 1) {
        const entry = pkg.registerCatalogEntry({
          appId: `com.g2.cat.${i}`,
          name: `G2 Cat ${i}`,
          platform: 'universal',
          metadata: pkgBads[i],
        });
        assert.equal(entry.metadata, '[Unreadable]');
      }

      // Entire 11-subsystem sweep MUST complete near-instantaneously (zero 4 GiB allocation hang)
      const elapsedMs = performance.now() - t0;
      assert.ok(elapsedMs < 5000, `Expected instant rejection across all modules, took ${elapsedMs.toFixed(1)}ms`);
    } finally {
      ipc.stop();
      cfg.close();
      vfs.close();
      pb.close();
      pkg.close();
    }
  });

  it('17.3 (G3 & Obs-R2): VFS._resolveHandleArg rejects hostile opts.pid & forged handles with VfsError and VFS.symlink uses string-safe VfsError.path', () => {
    const vfs = new VFS();
    try {
      vfs.writeFile('/home/user/g3-handle.txt', 'hello-g3', { uid: DEFAULT_USER_UID });
      const h = vfs.open('/home/user/g3-handle.txt', 'r+', { uid: DEFAULT_USER_UID });

      const hostilePidOpts = [
        { pid: Symbol('p') },
        { pid: makeRevokedObjProxy() },
        {
          pid: {
            toString() {
              throw new Error('boom');
            },
          },
        },
        { pid: -1 },
        { pid: '0' },
      ];

      for (const badOpts of hostilePidOpts) {
        assert.throws(
          () => vfs.read(h.fd, 5, badOpts),
          (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
        );
        assert.throws(
          () => vfs.write(h.fd, 'x', badOpts),
          (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
        );
        assert.throws(
          () => vfs.seek(h.fd, 0, SEEK_WHENCE.SEEK_SET, badOpts),
          (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
        );
        assert.throws(
          () => vfs.closeHandle(h.fd, badOpts),
          (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
        );
        assert.throws(
          () => vfs.close(h.fd, badOpts),
          (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
        );
      }

      // Forged handle objects & revoked/proxied handles MUST throw typed VfsError (never raw TypeError/Error)
      const forgedWithThrowingGetters = Object.create(Object.getPrototypeOf(h));
      Object.defineProperty(forgedWithThrowingGetters, 'fd', {
        get() {
          throw new Error('forged-fd-boom');
        },
      });
      Object.defineProperty(forgedWithThrowingGetters, 'pid', {
        get() {
          throw new Error('forged-pid-boom');
        },
      });
      const forgedPlain = { fd: h.fd, pid: h.pid };
      const proxiedRealHandle = new Proxy(h, {});
      const revokedHandle = makeRevokedObjProxy();

      for (const badHandle of [forgedWithThrowingGetters, forgedPlain, proxiedRealHandle, revokedHandle]) {
        assert.throws(
          () => vfs.read(badHandle, 5),
          (err) => err instanceof VfsError && (err.code === ERROR_CODES.EBADF || err.code === ERROR_CODES.EINVAL)
        );
        assert.throws(
          () => vfs.write(badHandle, 'x'),
          (err) => err instanceof VfsError && (err.code === ERROR_CODES.EBADF || err.code === ERROR_CODES.EINVAL)
        );
        assert.throws(
          () => vfs.seek(badHandle, 0, SEEK_WHENCE.SEEK_SET),
          (err) => err instanceof VfsError && (err.code === ERROR_CODES.EBADF || err.code === ERROR_CODES.EINVAL)
        );
        assert.throws(
          () => vfs.closeHandle(badHandle),
          (err) => err instanceof VfsError && (err.code === ERROR_CODES.EBADF || err.code === ERROR_CODES.EINVAL)
        );
        assert.throws(
          () => vfs.close(badHandle),
          (err) => err instanceof VfsError && (err.code === ERROR_CODES.EBADF || err.code === ERROR_CODES.EINVAL)
        );
      }

      // Real handle remains healthy and usable
      const bytes = vfs.read(h, 8);
      assert.equal(new TextDecoder().decode(bytes), 'hello-g3');
      vfs.close(h);

      // Obs-R2: VFS.symlink produces string-safe VfsError.path even when target or linkPath is Symbol / revoked Proxy
      for (const [target, linkPath] of [
        [Symbol('link'), ''],
        ['', Symbol('link')],
        ['', makeRevokedObjProxy()],
      ]) {
        let caught = null;
        try {
          vfs.symlink(target, linkPath);
        } catch (err) {
          caught = err;
        }
        assert.ok(caught instanceof VfsError, 'Expected VfsError from VFS.symlink');
        assert.equal(caught.code, ERROR_CODES.EINVAL);
        assert.equal(typeof caught.path, 'string');
      }
    } finally {
      vfs.close();
    }
  });

  it('17.4 (G4): UserManager.allocateAppUid & createUser reject traversal platform/username values with zero SQLite rows persisted', () => {
    const storage = new SqliteStorage(':memory:');
    const um = new UserManager({ storage });
    try {
      const initialRowCount = Number(storage.get('SELECT COUNT(*) AS cnt FROM security_users').cnt);

      for (const badPlatform of ['..', '.', 'a..b', 'ios/../etc']) {
        assert.throws(
          () => um.allocateAppUid('com.evil', { platform: badPlatform }),
          (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
        );
      }

      for (const badUserOpts of [
        { username: '..', platform: '..' },
        { username: '.', platform: 'android' },
        { username: 'safeuser1', platform: '..' },
        { username: 'safeuser2', platform: '.' },
        { username: 'safeuser3', platform: 'a..b' },
      ]) {
        assert.throws(
          () => um.createUser(badUserOpts),
          (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
        );
      }

      assert.equal(um.getUserByAppId('com.evil'), null);
      const finalRowCount = Number(storage.get('SELECT COUNT(*) AS cnt FROM security_users').cnt);
      assert.equal(finalRowCount, initialRowCount, 'ZERO rows may be persisted into security_users on rejected inputs');
    } finally {
      um.close();
      storage.close();
    }
  });

  it('17.5 (G5 & PackageManager._ownsStorage Parity): Standalone .close() closes private DBs, shared storage is preserved & PermissionBroker.close() settles pending prompts fail-closed', async () => {
    // Part A: Standalone instances own & close their private :memory: SqliteStorage
    const standaloneInstances = [
      new UserManager(),
      new PermissionBroker(),
      new VFS(),
      new UnifiedConfigStore(),
      new PackageManager(),
    ];
    for (const inst of standaloneInstances) {
      assert.equal(inst._ownsStorage, true, `${inst.constructor.name} standalone must have _ownsStorage === true`);
      assert.equal(inst._storage.isOpen, true, `${inst.constructor.name} standalone storage should start open`);
      inst.close();
      assert.equal(inst._storage.isOpen, false, `${inst.constructor.name}.close() must close private storage`);
    }

    // Part B: Shared storage instances NEVER close shared storage on .close()
    const shared = new SqliteStorage(':memory:');
    try {
      const sharedInstances = [
        new UserManager({ storage: shared }),
        new PermissionBroker({ storage: shared }),
        new VFS({ storage: shared }),
        new UnifiedConfigStore({ storage: shared }),
        new PackageManager({ storage: shared }),
      ];
      for (const inst of sharedInstances) {
        assert.equal(inst._ownsStorage, false, `${inst.constructor.name} with shared storage must have _ownsStorage === false`);
        inst.close();
        assert.equal(shared.isOpen, true, `${inst.constructor.name}.close() must NEVER close shared storage`);
      }

      // Part C: PermissionBroker.close() while checkPermission() prompt is pending (BOTH standalone & shared storage)
      const pbStandalone = new PermissionBroker({ promptTimeoutMs: 5000 });
      const pendingSolo = pbStandalone.checkPermission({
        appId: 'com.g5.pending.solo',
        capability: CAPABILITIES.CAMERA_DEVICE,
      });
      await new Promise((r) => setTimeout(r, 5));
      pbStandalone.close();
      const soloRes = await pendingSolo;
      assert.equal(soloRes.granted, false);
      assert.equal(soloRes.reason, 'broker_closed');
      assert.equal(soloRes.auditId, null);
      assert.equal(pbStandalone._storage.isOpen, false);

      const pbShared = new PermissionBroker({ storage: shared, promptTimeoutMs: 5000 });
      const pendingShared = pbShared.checkPermission({
        appId: 'com.g5.pending.shared',
        capability: CAPABILITIES.CAMERA_DEVICE,
      });
      await new Promise((r) => setTimeout(r, 5));
      pbShared.close();
      const sharedRes = await pendingShared;
      assert.equal(sharedRes.granted, false);
      assert.equal(sharedRes.reason, 'broker_closed');
      assert.equal(sharedRes.auditId, null);
      assert.equal(shared.isOpen, true);
    } finally {
      if (shared.isOpen) shared.close();
    }
  });

  it('17.6 (H1): PackageManager.install() syncs fresh iOS UUID custom dataDir, updates sandbox on reinstall after uninstall({ purgeData: false }) & preserves UID + prevUserSandbox on failed rollback', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'omnios-m2-h1-'));
    let stackA = null;
    let stackB = null;
    let stackC = null;

    try {
      // 17.6a: Fresh iOS install returning custom UUID dataDir updates UserManager.sandboxRoot & cleans unused empty defaultDataDir
      stackA = wireIter5Stack(path.join(dir, 'h1a.sqlite'));
      const uuidDataDir = '/var/appdata/ios/550e8400-e29b-41d4-a716-446655440000';
      stackA.pkgManager.registerRuntime('ios', {
        platform: 'ios',
        inspectPackage(_bytes, _hint, detection) {
          return {
            format: detection.format,
            platform: 'ios',
            arch: 'arm64',
            appId: 'com.apple.weather',
            name: 'Weather',
            version: '1.0.0',
            permissions: [],
            intents: [],
          };
        },
        installPackage() {
          return { dataDir: uuidDataDir };
        },
        createExecutionContext() {
          return makeWorkExecContext();
        },
      });
      await stackA.kernel.boot();

      const iosRec = await stackA.pkgManager.install(buildIpaFixture());
      assert.equal(iosRec.uid, SANDBOX_UID_BASE);
      assert.equal(iosRec.dataDir, uuidDataDir);

      const iosUser = stackA.users.getUserByAppId('com.apple.weather');
      assert.equal(iosUser.uid, SANDBOX_UID_BASE);
      assert.equal(iosUser.sandboxRoot, uuidDataDir);
      assert.equal(iosUser.strictSandbox, true);

      // App UID 10000 immediately writes inside its UUID dataDir
      stackA.vfs.writeFile(`${uuidDataDir}/prefs.plist`, '<plist/>', { uid: iosRec.uid, gid: iosRec.gid });
      assert.equal(
        stackA.vfs.readFile(`${uuidDataDir}/prefs.plist`, { encoding: 'utf8', uid: iosRec.uid, gid: iosRec.gid }),
        '<plist/>'
      );

      // Escape outside UUID dataDir is blocked with VfsError(EACCES)
      stackA.vfs.writeFile('/tmp/outside_ios.txt', 'nope', { uid: 0, gid: 0, mode: 0o644 });
      assert.throws(
        () => stackA.vfs.readFile('/tmp/outside_ios.txt', { uid: iosRec.uid, gid: iosRec.gid }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EACCES
      );

      // Unused empty default dataDir (/var/appdata/ios/com.apple.weather) is removed
      assert.throws(
        () => stackA.vfs.stat('/var/appdata/ios/com.apple.weather'),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.ENOENT
      );

      // 17.6b: universal -> uninstall({ purgeData: false }) -> android tightens strictSandbox=true & updates sandboxRoot;
      //        android -> uninstall({ purgeData: false }) -> ios updates sandboxRoot to /var/appdata/ios/<appId>
      stackB = wireIter5Stack(path.join(dir, 'h1b.sqlite'));
      stackB.pkgManager.registerRuntime('universal', {
        platform: 'universal',
        inspectPackage(_bytes, _hint, detection) {
          return {
            format: detection.format,
            platform: 'universal',
            arch: 'wasm',
            appId: 'com.h1.reinstall',
            name: 'Reinstall Universal',
            version: '1.0.0',
            permissions: [],
            intents: [],
          };
        },
        createExecutionContext() {
          return makeWorkExecContext();
        },
      });
      stackB.pkgManager.registerRuntime('android', {
        platform: 'android',
        inspectPackage(_bytes, _hint, detection) {
          return {
            format: detection.format,
            platform: 'android',
            arch: 'dalvik',
            appId: 'com.h1.reinstall',
            name: 'Reinstall Android',
            version: '2.0.0',
            permissions: [],
            intents: [],
          };
        },
        createExecutionContext() {
          return makeWorkExecContext();
        },
      });
      stackB.pkgManager.registerRuntime('ios', {
        platform: 'ios',
        inspectPackage(_bytes, _hint, detection) {
          return {
            format: detection.format,
            platform: 'ios',
            arch: 'arm64',
            appId: 'com.h1.reinstall',
            name: 'Reinstall iOS',
            version: '3.0.0',
            permissions: [],
            intents: [],
          };
        },
        createExecutionContext() {
          return makeWorkExecContext();
        },
      });
      await stackB.kernel.boot();
      stackB.vfs.writeFile('/tmp/outside_secret.txt', 'secret-data', { uid: 0, gid: 0, mode: 0o644 });

      const rUni = await stackB.pkgManager.install(buildUappFixture());
      assert.equal(rUni.uid, SANDBOX_UID_BASE);
      assert.equal(stackB.users.getUserByAppId('com.h1.reinstall')?.strictSandbox, false);

      await stackB.pkgManager.uninstall('com.h1.reinstall', { purgeData: false });
      assert.equal(stackB.pkgManager.get('com.h1.reinstall'), null);
      assert.equal(stackB.users.getUserByAppId('com.h1.reinstall')?.uid, SANDBOX_UID_BASE);

      const rAnd = await stackB.pkgManager.install(buildApkFixture());
      assert.equal(rAnd.uid, SANDBOX_UID_BASE);
      const userAnd = stackB.users.getUserByAppId('com.h1.reinstall');
      assert.equal(userAnd.platform, 'android');
      assert.equal(userAnd.sandboxRoot, '/var/appdata/android/com.h1.reinstall');
      assert.equal(userAnd.strictSandbox, true);

      // Android app writes inside /var/appdata/android/com.h1.reinstall & is blocked from /tmp/outside_secret.txt!
      stackB.vfs.writeFile('/var/appdata/android/com.h1.reinstall/state.json', '{"a":1}', {
        uid: rAnd.uid,
        gid: rAnd.gid,
      });
      assert.throws(
        () => stackB.vfs.readFile('/tmp/outside_secret.txt', { uid: rAnd.uid, gid: rAnd.gid, encoding: 'utf8' }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EACCES
      );

      // android -> uninstall({ purgeData: false }) -> ios updates sandboxRoot to /var/appdata/ios/<appId>
      await stackB.pkgManager.uninstall('com.h1.reinstall', { purgeData: false });
      const rIos = await stackB.pkgManager.install(buildIpaFixture());
      assert.equal(rIos.uid, SANDBOX_UID_BASE);
      const userIos = stackB.users.getUserByAppId('com.h1.reinstall');
      assert.equal(userIos.platform, 'ios');
      assert.equal(userIos.sandboxRoot, '/var/appdata/ios/com.h1.reinstall');
      assert.equal(userIos.strictSandbox, true);

      stackB.vfs.writeFile('/var/appdata/ios/com.h1.reinstall/ios.plist', '<plist/>', {
        uid: rIos.uid,
        gid: rIos.gid,
      });
      assert.equal(
        stackB.vfs.readFile('/var/appdata/ios/com.h1.reinstall/ios.plist', {
          encoding: 'utf8',
          uid: rIos.uid,
          gid: rIos.gid,
        }),
        '<plist/>'
      );
      assert.throws(
        () =>
          stackB.vfs.readFile('/var/appdata/android/com.h1.reinstall/state.json', {
            uid: rIos.uid,
            gid: rIos.gid,
          }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EACCES
      );

      // 17.6c: Forced failure during reinstall after uninstall({ purgeData: false }) preserves pre-existing UID 10000 & restores prevUserSandbox
      stackC = wireIter5Stack(path.join(dir, 'h1c.sqlite'));
      stackC.pkgManager.registerRuntime('universal', {
        platform: 'universal',
        inspectPackage(_bytes, _hint, detection) {
          return {
            format: detection.format,
            platform: 'universal',
            arch: 'wasm',
            appId: 'com.h1.rollback',
            name: 'Rollback Universal',
            version: '1.0.0',
            permissions: [],
            intents: [],
          };
        },
        createExecutionContext() {
          return makeWorkExecContext();
        },
      });
      stackC.pkgManager.registerRuntime('android', {
        platform: 'android',
        inspectPackage(_bytes, _hint, detection) {
          return {
            format: detection.format,
            platform: 'android',
            arch: 'dalvik',
            appId: 'com.h1.rollback',
            name: 'Rollback Android',
            version: '2.0.0',
            permissions: ['android.permission.CAMERA'],
            intents: [],
          };
        },
        createExecutionContext() {
          return makeWorkExecContext();
        },
      });
      await stackC.kernel.boot();

      const origUni = await stackC.pkgManager.install(buildUappFixture());
      assert.equal(origUni.uid, SANDBOX_UID_BASE);
      await stackC.pkgManager.uninstall('com.h1.rollback', { purgeData: false });

      const origSetGrant = stackC.permissions.setGrant.bind(stackC.permissions);
      stackC.permissions.setGrant = () => {
        throw new OmniOSError('Simulated post-sandbox-update reinstall failure', { code: ERROR_CODES.EIO });
      };
      try {
        await assert.rejects(
          () => stackC.pkgManager.install(buildApkFixture(), { grantAll: true }),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EIO
        );
      } finally {
        stackC.permissions.setGrant = origSetGrant;
      }

      // Pre-existing UserManager UID 10000 MUST survive AND prevUserSandbox MUST be restored!
      const preservedUser = stackC.users.getUserByAppId('com.h1.rollback');
      assert.ok(preservedUser, 'Pre-existing UserManager user must NOT be deleted on failed reinstall rollback');
      assert.equal(preservedUser.uid, SANDBOX_UID_BASE);
      assert.equal(preservedUser.platform, 'universal');
      assert.equal(preservedUser.sandboxRoot, '/var/appdata/universal/com.h1.rollback');
      assert.equal(preservedUser.strictSandbox, false);
      assert.equal(stackC.pkgManager.get('com.h1.rollback'), null);
    } finally {
      if (stackA) await stackA.kernel.shutdown();
      if (stackB) await stackB.kernel.shutdown();
      if (stackC) await stackC.kernel.shutdown();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('17.7 (H2 & H4): IPCManager.send() is pre-queue atomic on correlationId/replyTo & re-wraps prototype-chain Proxy OmniOSErrors', async () => {
    const ipc = new IPCManager({ defaultRpcTimeoutMs: 2000 });
    try {
      ipc.createChannel('ch.h2', 0);

      // H2a: Poisoned correlationId / replyTo MUST fail BEFORE enqueueing (queueSize === 0, recv peek === null)
      assert.throws(
        () => ipc.send('ch.h2', 0, 'hello', { correlationId: Symbol('poison') }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => ipc.send('ch.h2', 0, 'hello', { replyTo: Symbol('poison') }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.equal(ipc.listChannels().find((c) => c.name === 'ch.h2')?.queueSize, 0);
      assert.equal(ipc.recv('ch.h2', 0, { peek: true }), null);

      // H2b: Plain object correlationId & replyTo are deep-cloned so post-send caller mutation does not leak into ch.queue
      const cidObj = { tag: 'v1' };
      const replyToObj = { ch: 'resp-v1' };
      ipc.send('ch.h2', 0, 'hello', { correlationId: cidObj, replyTo: replyToObj });
      cidObj.tag = 'MUTATED_AFTER_SEND';
      replyToObj.ch = 'MUTATED_AFTER_SEND';
      const queued = ipc.recv('ch.h2', 0);
      assert.deepEqual(queued.correlationId, { tag: 'v1' });
      assert.deepEqual(queued.replyTo, { ch: 'resp-v1' });

      // H4: Non-Proxy OmniOSError with deleted .message and prototype-chain Proxy throwing on 2nd .message read
      function makeProtoProxyOmniError(tag) {
        let reads = 0;
        const evilProto = new Proxy(Object.create(OmniOSError.prototype), {
          get(target, key, receiver) {
            if (key === 'message') {
              reads += 1;
              if (reads === 1) return `${tag}-first-read-ok`;
              throw new Error(`${tag}-BOOM-ON-2ND-READ`);
            }
            return Reflect.get(target, key, receiver);
          },
          getOwnPropertyDescriptor(target, key) {
            if (key === 'message') {
              return { value: 'fake-data-desc', writable: true, enumerable: true, configurable: true };
            }
            return Reflect.getOwnPropertyDescriptor(target, key);
          },
        });
        const err = new OmniOSError('tmp', { code: ERROR_CODES.EIO });
        delete err.message;
        Object.setPrototypeOf(err, evilProto);
        return err;
      }

      const syncOriginal = makeProtoProxyOmniError('rpc-sync');
      const asyncOriginal = makeProtoProxyOmniError('rpc-async');
      ipc.registerRpc('rpc.h4.sync', () => {
        throw syncOriginal;
      });
      ipc.registerRpc('rpc.h4.async', async () => {
        throw asyncOriginal;
      });

      for (const [method, origErr] of [
        ['rpc.h4.sync', syncOriginal],
        ['rpc.h4.async', asyncOriginal],
      ]) {
        let caught = null;
        try {
          await ipc.callRpc(method, null);
        } catch (err) {
          caught = err;
        }
        assert.ok(caught instanceof OmniOSError, `Expected OmniOSError from ${method}`);
        assert.notEqual(caught, origErr, `Prototype-chain Proxy OmniOSError must be re-wrapped in ${method}`);
        assert.equal(utilTypes.isProxy(caught), false);
        assert.equal(utilTypes.isProxy(Object.getPrototypeOf(caught)), false);
        const msg = caught.message;
        assert.equal(typeof msg, 'string');
        assert.ok(msg.length > 0);
        for (let r = 0; r < 5; r += 1) {
          assert.equal(caught.message, msg);
        }
      }

      // Also verify request() / reply() re-wraps prototype-chain Proxy OmniOSError
      const replyOriginal = makeProtoProxyOmniError('reply');
      ipc.createChannel('ch.h4', 0);
      ipc.subscribe('ch.h4', (env) => {
        if (env.correlationId) {
          ipc.reply(env.correlationId, null, { error: replyOriginal });
        }
      });
      let caughtReply = null;
      try {
        await ipc.request('ch.h4', 0, { ping: 1 });
      } catch (err) {
        caughtReply = err;
      }
      assert.ok(caughtReply instanceof OmniOSError);
      assert.notEqual(caughtReply, replyOriginal);
      assert.equal(utilTypes.isProxy(caughtReply), false);
      assert.equal(utilTypes.isProxy(Object.getPrototypeOf(caughtReply)), false);
      const replyMsg = caughtReply.message;
      assert.equal(typeof replyMsg, 'string');
      assert.ok(replyMsg.length > 0);
      for (let r = 0; r < 5; r += 1) {
        assert.equal(caughtReply.message, replyMsg);
      }
    } finally {
      ipc.stop();
    }
  });

  it('17.8 (H3): Compositor enforces cumulative appendDrawOps node budget atomically & preserves Array surface.drawOps everywhere', async () => {
    const kernel = new OmniKernel({ storage: new SqliteStorage(':memory:') });
    await kernel.boot();
    try {
      const comp = new Compositor({ kernel, maxDrawOps: 1000 });
      const pcb = kernel.processManager.spawn({
        name: 'h3-app',
        appId: 'com.h3.app',
        platform: 'universal',
        executionContext: makeWorkExecContext(),
      });

      const makeOp = () => {
        const o = {};
        for (let i = 0; i < 500; i += 1) o[`k${i}`] = i;
        return o;
      };

      const surfacePatches = [];
      kernel.eventBus.on('compositor:surface_patch', (evt) => surfacePatches.push(evt));

      const w = comp.createWindow(pcb.pid, {
        title: 'BigWindow',
        drawOps: Array.from({ length: 300 }, makeOp),
      });
      const beforeRev = w.surfaceRevision;

      // Appending another 300 ops x 500 keys exceeds MAX_SURFACE_DRAW_OPS_NODES -> atomic QuotaExceededError(EQUOTA)
      assert.throws(
        () =>
          comp.updateSurface(w.windowId, {
            title: 'ShouldNotMutate',
            appendDrawOps: Array.from({ length: 300 }, makeOp),
          }),
        (err) => err instanceof QuotaExceededError && err.code === ERROR_CODES.EQUOTA
      );

      // Atomicity: original title, drawOps, surfaceRevision remain untouched and zero failed patch emitted
      assert.equal(surfacePatches.length, 0);

      const fetched = comp.getWindow(w.windowId);
      assert.equal(fetched.title, 'BigWindow');
      assert.equal(fetched.surfaceRevision, beforeRev);
      assert.equal(Array.isArray(fetched.surface.drawOps), true);
      assert.equal(fetched.surface.drawOps.length, 300);

      const listed = comp.listWindows().find((item) => item.windowId === w.windowId);
      assert.equal(Array.isArray(listed.surface.drawOps), true);
      assert.equal(listed.surface.drawOps.length, 300);

      const snapshotWin = comp.getSnapshot().windows.find((item) => item.windowId === w.windowId);
      assert.equal(Array.isArray(snapshotWin.surface.drawOps), true);
      assert.equal(snapshotWin.surface.drawOps.length, 300);

      // A valid smaller append succeeds and emits compositor:surface_patch with Array surface.drawOps (never '[Unreadable]')
      comp.updateSurface(w.windowId, { appendDrawOps: [{ op: 'rect', x: 1, y: 2 }] });
      assert.equal(surfacePatches.length, 1);
      assert.equal(Array.isArray(surfacePatches[0].surface.drawOps), true);
      assert.equal(surfacePatches[0].surface.drawOps.length, 301);
      assert.equal(Array.isArray(comp.getWindow(w.windowId).surface.drawOps), true);
      assert.equal(comp.getWindow(w.windowId).surface.drawOps.length, 301);
    } finally {
      await kernel.shutdown();
    }
  });

  it('17.9 (Obs A, Obs B1, Obs B2): Null/revoked opts, PackageManager.stop Symbol signal & revoked kernel constructors throw typed errors (never raw TypeError)', async () => {
    const revoked = makeRevokedObjProxy();
    const um = new UserManager();
    const pbNull = new PermissionBroker(null);
    const kernel = new OmniKernel({ storage: new SqliteStorage(':memory:') });

    try {
      // Obs A: null options succeed cleanly without TypeError; revoked Proxy options throw typed SecurityError / VfsError(EINVAL)
      assert.equal(isWithinRoot('/a', '/', null), true);
      assert.throws(
        () => isWithinRoot('/a', '/', revoked),
        (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
      );

      assert.equal(Array.isArray(um.listUsers(null)), true);
      assert.throws(
        () => um.listUsers(revoked),
        (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
      );

      assert.equal(isPathWithinRoot('/a', '/', null), true);
      assert.throws(
        () => isPathWithinRoot('/a', '/', revoked),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
      );

      assert.equal(pbNull._ownsStorage, true);
      assert.throws(
        () => new PermissionBroker(revoked),
        (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
      );

      // Obs B1: PackageManager.stop(pid, { signal: Symbol('bad') }) throws OmniOSError(EINVAL) (never raw TypeError)
      await kernel.boot();
      const vfs = new VFS({ kernel });
      const pkg = new PackageManager({ kernel, vfs });
      pkg.registerRuntime('universal', {
        platform: 'universal',
        inspectPackage(_bytes, _hint, detection) {
          return {
            format: detection.format,
            platform: 'universal',
            arch: 'wasm',
            appId: 'com.obsb1.stop',
            name: 'StopTest',
            version: '1.0.0',
            permissions: [],
            intents: [],
          };
        },
        createExecutionContext() {
          return makeWorkExecContext({ totalWork: 1000 });
        },
      });
      await pkg.install(buildUappFixture());
      const launched = await pkg.launch('com.obsb1.stop');

      assert.throws(
        () => pkg.stop(launched.pid, { signal: Symbol('bad') }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => pkg.stop(launched.pid, { signal: 1.5 }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      // Clean stop still succeeds
      const stopped = pkg.stop(launched.pid);
      assert.deepEqual(stopped.stoppedPids, [launched.pid]);

      // Obs B2 & Obs A: Revoked kernel option in M2 constructors throws typed OmniOSError / VfsError / SecurityError (EINVAL)
      assert.throws(
        () => new Compositor({ kernel: revoked }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => new PackageManager({ kernel: revoked }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => new VFS({ kernel: revoked }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => new UnifiedConfigStore({ kernel: revoked }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => new UserManager({ kernel: revoked }),
        (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => new PermissionBroker({ kernel: revoked }),
        (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => new IPCManager({ kernel: revoked }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => new IntentRouter({ kernel: revoked }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => new NotificationCenter({ kernel: revoked }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => new SharedClipboard({ kernel: revoked }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
    } finally {
      um.close();
      pbNull.close();
      await kernel.shutdown();
    }
  });
});

// ============================================================================
// SUITE 18: Iteration 6 Final Surgical Defect Regressions (I1–I4, J1–J4)
// ============================================================================

describe('Suite 18: Iteration 6 Final Surgical Defect Regressions (I1–I4, J1–J4)', () => {
  function makeRevokedObjProxy() {
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    return proxy;
  }

  function makeRevokedFnProxy() {
    const { proxy, revoke } = Proxy.revocable(() => null, {});
    revoke();
    return proxy;
  }

  function makeDrain(nodeCount) {
    const out = [];
    let rem = nodeCount;
    while (rem > 0) {
      rem -= 1; // outer array element slot
      if (rem <= 0) {
        out.push(0);
        break;
      }
      const len = Math.min(rem, 50_000);
      out.push(new Array(len).fill(0));
      rem -= len;
    }
    return out;
  }

  function buildNestedObject(depth, leaf = 'leaf') {
    let cur = leaf;
    for (let i = 0; i < depth; i += 1) {
      cur = { n: cur };
    }
    return cur;
  }

  function buildNestedArray(depth, leaf = 'leaf') {
    let cur = leaf;
    for (let i = 0; i < depth; i += 1) {
      cur = [cur];
    }
    return cur;
  }

  it('18.1 (I1): VFS.init(ext2) re-binds owned UserManager cleanly without split-brain or closing ext1', () => {
    const ext1 = new SqliteStorage(':memory:');
    const ext2 = new SqliteStorage(':memory:');
    try {
      const vfs = new VFS({ storage: ext1 });
      assert.equal(vfs._ownsUserManager, true);
      assert.equal(vfs._storage, ext1);
      assert.equal(vfs.userManager._storage, ext1);

      const ext1App = vfs.userManager.allocateAppUid('com.only.ext1', { platform: 'android' });
      assert.ok(ext1App.uid >= SANDBOX_UID_BASE);
      assert.equal(
        vfs.userManager.checkSandboxAccess(ext1App.uid, `${ext1App.sandboxRoot}/prefs.xml`).allowed,
        true
      );

      // Switch VFS onto ext2 while ext1 is still open
      vfs.init(ext2);
      assert.equal(ext1.isOpen, true, 'Switching VFS storage must never close external ext1');
      assert.equal(vfs._storage, ext2);
      assert.equal(vfs.userManager._storage, ext2, 'Owned UserManager must re-bind to ext2');

      // Stale ext1 user & sandbox cache must NOT bleed into ext2
      assert.equal(vfs.userManager.getUserByAppId('com.only.ext1'), null);
      assert.equal(vfs.userManager.getUserByUid(ext1App.uid), null);
      const staleSandboxCheck = vfs.userManager.checkSandboxAccess(
        ext1App.uid,
        `${ext1App.sandboxRoot}/prefs.xml`
      );
      assert.equal(staleSandboxCheck.allowed, false);
      assert.equal(staleSandboxCheck.reason, 'cross_app_sandbox_violation');

      // Closing ext1 must leave VFS and owned UserManager healthy on ext2
      ext1.close();
      assert.equal(ext1.isOpen, false);
      assert.equal(vfs.isReady, true);
      assert.equal(vfs.userManager.isReady, true);

      const ext2App = vfs.userManager.allocateAppUid('com.on.ext2', { platform: 'android' });
      assert.ok(ext2App.uid >= SANDBOX_UID_BASE);
      assert.equal(vfs.userManager.getUserByAppId('com.on.ext2')?.uid, ext2App.uid);
      assert.equal(
        vfs.userManager.checkSandboxAccess(ext2App.uid, `${ext2App.sandboxRoot}/state.db`).allowed,
        true
      );

      vfs.mkdir('/ext2-check', { recursive: true, uid: ROOT_UID, gid: ROOT_GID });
      vfs.writeFile('/ext2-check/hello.txt', 'on-ext2', { uid: ROOT_UID, gid: ROOT_GID });
      assert.equal(vfs.readFile('/ext2-check/hello.txt', { encoding: 'utf8', uid: ROOT_UID, gid: ROOT_GID }), 'on-ext2');
    } finally {
      if (ext1.isOpen) ext1.close();
      if (ext2.isOpen) ext2.close();
    }
  });

  it('18.2 (I2): TmpFsMount blocks detached & [Symbol.species] Uint8Array, enforces quota before allocation, returns defensive xattr copy & ProcFsMount survives revoked kernel', () => {
    const ab = new ArrayBuffer(8);
    const detachedU8 = new Uint8Array(ab);
    ab.transfer();

    const speciesBombU8 = new Uint8Array([10, 20, 30]);
    Object.defineProperty(speciesBombU8, 'constructor', {
      get() {
        throw new Error('SPECIES_BOMB');
      },
    });

    const poisonedCtor = {
      [Symbol.species]() {
        throw new Error('POISONED_SPECIES');
      },
    };
    const poisonedSpeciesU8 = new Uint8Array([4, 5, 6]);
    Object.defineProperty(poisonedSpeciesU8, 'constructor', {
      value: poisonedCtor,
    });

    const backing = new Uint8Array([0, 1, 2, 77, 88, 99, 255]);
    const subU8 = backing.subarray(3, 6);
    assert.equal(subU8.byteOffset, 3);
    assert.equal(subU8.byteLength, 3);

    // 1. Detached Uint8Array throws VfsError(EINVAL) across all 3 write methods (and BEFORE quota on maxBytes: 0)
    const tmpFs = new TmpFsMount({ maxBytes: 1024 });
    const root = tmpFs.getRootNode();
    const baseFile = tmpFs.createFile(root, 'base.bin', new Uint8Array([9]));

    assert.throws(
      () => tmpFs.createFile(root, 'det.bin', detachedU8),
      (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
    );
    assert.throws(
      () => tmpFs.updateFileData(baseFile, detachedU8),
      (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
    );
    assert.throws(
      () => tmpFs.setXattr(baseFile, 'user.det', detachedU8),
      (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
    );

    const zeroMount = new TmpFsMount({ maxBytes: 0 });
    const zeroRoot = zeroMount.getRootNode();
    const zeroEmpty = zeroMount.createFile(zeroRoot, 'empty.bin', new Uint8Array(0));
    assert.throws(
      () => zeroMount.createFile(zeroRoot, 'det0.bin', detachedU8),
      (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
    );
    assert.throws(
      () => zeroMount.updateFileData(zeroEmpty, detachedU8),
      (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
    );
    assert.throws(
      () => zeroMount.setXattr(zeroEmpty, 'user.det0', detachedU8),
      (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
    );

    // 2. Shadowed throwing .constructor (SPECIES_BOMB) & poisoned [Symbol.species] succeed safely
    const fSpecies = tmpFs.createFile(root, 'species.bin', speciesBombU8);
    assert.deepEqual(Array.from(tmpFs.readFileData(fSpecies)), [10, 20, 30]);
    tmpFs.updateFileData(fSpecies, poisonedSpeciesU8);
    assert.deepEqual(Array.from(tmpFs.readFileData(fSpecies)), [4, 5, 6]);
    const xa1 = tmpFs.setXattr(fSpecies, 'user.bomb', speciesBombU8);
    assert.deepEqual(Array.from(xa1), [10, 20, 30]);
    const xa2 = tmpFs.setXattr(fSpecies, 'user.poison', poisonedSpeciesU8);
    assert.deepEqual(Array.from(xa2), [4, 5, 6]);

    // 3. Subarray (byteOffset > 0) copies exact slice and isolates from subsequent backing buffer mutation
    const fSub = tmpFs.createFile(root, 'sub.bin', subU8);
    const xaSub = tmpFs.setXattr(fSub, 'user.sub', subU8);
    backing.fill(0xee);
    assert.deepEqual(Array.from(tmpFs.readFileData(fSub)), [77, 88, 99]);
    assert.deepEqual(Array.from(xaSub), [77, 88, 99]);
    assert.deepEqual(Array.from(fSub.xattrs.get('user.sub')), [77, 88, 99]);
    const sub2 = new Uint8Array([1, 2, 31, 32, 33, 9]).subarray(2, 5);
    tmpFs.updateFileData(fSub, sub2);
    assert.deepEqual(Array.from(tmpFs.readFileData(fSub)), [31, 32, 33]);

    // 4. Defensive copy return from setXattr prevents external mutation of stored xattr
    const retXattr = tmpFs.setXattr(baseFile, 'user.safe', new Uint8Array([1, 2, 3, 4]));
    retXattr[0] = 0xff;
    assert.equal(baseFile.xattrs.get('user.safe')[0], 1);
    assert.notEqual(retXattr, baseFile.xattrs.get('user.safe'));

    // 5. ENOSPC quota rejection before allocation leaves mount state untouched
    const quotaFs = new TmpFsMount({ maxBytes: 16 });
    const qRoot = quotaFs.getRootNode();
    assert.throws(
      () => quotaFs.createFile(qRoot, 'too-big.bin', new Uint8Array(17)),
      (err) => err instanceof VfsError && err.code === ERROR_CODES.ENOSPC
    );
    assert.equal(quotaFs.usedBytes, 0);
    assert.equal(qRoot.children.size, 0);

    const smallFile = quotaFs.createFile(qRoot, 'ok.bin', new Uint8Array([1, 2, 3, 4]));
    assert.equal(quotaFs.usedBytes, 4);
    assert.throws(
      () => quotaFs.updateFileData(smallFile, new Uint8Array(20)),
      (err) => err instanceof VfsError && err.code === ERROR_CODES.ENOSPC
    );
    assert.equal(quotaFs.usedBytes, 4);
    assert.deepEqual(Array.from(quotaFs.readFileData(smallFile)), [1, 2, 3, 4]);
    assert.throws(
      () => quotaFs.setXattr(smallFile, 'user.big', new Uint8Array(16)),
      (err) => err instanceof VfsError && err.code === ERROR_CODES.ENOSPC
    );
    assert.equal(quotaFs.usedBytes, 4);
    assert.equal(smallFile.xattrs.has('user.big'), false);

    // 6. ProcFsMount survives post-construction revoked kernel cleanly
    const { proxy: kProxy, revoke: revokeKernel } = Proxy.revocable(
      { getUptimeMs: () => 12345, processManager: null },
      {}
    );
    const procFs = new ProcFsMount({ kernel: kProxy });
    const procRoot = procFs.getRootNode();
    const uptimeBefore = new TextDecoder().decode(
      procFs.readNode(procFs.lookupChild(procRoot, 'uptime').node)
    );
    assert.match(uptimeBefore, /^12\.345 /);

    revokeKernel();
    assert.equal(procFs.processManager, null);
    const uptimeAfter = new TextDecoder().decode(
      procFs.readNode(procFs.lookupChild(procRoot, 'uptime').node)
    );
    assert.match(uptimeAfter, /^\d+\.\d{3} \d+\.\d{3}\n$/);
  });

  it('18.3 (I3): UnifiedConfigStore enforces MAX_CONFIG_DEPTH = 128 across writes, XML plist export, cycles & tampered SQLite AST JSON', () => {
    const storage = new SqliteStorage(':memory:');
    const cfg = new UnifiedConfigStore({ storage });

    try {
      const deepObj4000 = buildNestedObject(4000, 'too-deep');
      const deepArr4000 = buildNestedArray(4000, 'too-deep');

      const isEinvalNotRangeError = (err) =>
        err instanceof OmniOSError &&
        !(err instanceof RangeError) &&
        err.code === ERROR_CODES.EINVAL;

      // 1. Depth-4000 objects & arrays throw typed OmniOSError(EINVAL) (never raw RangeError)
      assert.throws(() => cfg.defaults.set('com.deep', 'obj', deepObj4000), isEinvalNotRangeError);
      assert.throws(() => cfg.defaults.set('com.deep', 'arr', deepArr4000), isEinvalNotRangeError);
      assert.throws(
        () => cfg.sharedPrefs.edit('com.deep', 'prefs', [{ op: 'put', key: 'obj', value: deepObj4000 }]),
        isEinvalNotRangeError
      );
      assert.throws(
        () => cfg.sharedPrefs.edit('com.deep', 'prefs', [{ op: 'put', key: 'arr', value: deepArr4000 }]),
        isEinvalNotRangeError
      );
      assert.throws(() => cfg.system.set('custom.deepObj', deepObj4000), isEinvalNotRangeError);
      assert.throws(() => cfg.system.set('custom.deepArr', deepArr4000), isEinvalNotRangeError);
      assert.throws(
        () =>
          cfg.registry.setValue(
            REGISTRY_HIVES.HKCU,
            'Software\\DeepTest',
            'vObj',
            REGISTRY_TYPES.REG_SZ,
            deepObj4000
          ),
        isEinvalNotRangeError
      );
      assert.throws(
        () =>
          cfg.registry.setValue(
            REGISTRY_HIVES.HKCU,
            'Software\\DeepTest',
            'vArr',
            REGISTRY_TYPES.REG_MULTI_SZ,
            deepArr4000
          ),
        isEinvalNotRangeError
      );

      // 2. Exact boundary: depth-128 succeeds; depth-129 throws OmniOSError(EINVAL)
      const obj128 = buildNestedObject(128, 'ok128');
      const obj129 = buildNestedObject(129, 'fail129');
      const arr128 = buildNestedArray(128, 'arr128');
      const arr129 = buildNestedArray(129, 'arr129');

      cfg.defaults.set('com.bound', 'd128', obj128);
      const got128 = cfg.defaults.get('com.bound', 'd128');
      let walk = got128;
      for (let i = 0; i < 128; i += 1) walk = walk.n;
      assert.equal(walk, 'ok128');

      const xml128 = cfg.defaults.exportPlistXml('com.bound');
      assert.ok(xml128.includes('<string>ok128</string>'));
      // Verify exact depth-128 XML plist parses cleanly in host Python 3 plistlib.loads()
      const pyDepthCheck = runPython(
        `import sys, plistlib
d = plistlib.loads(sys.stdin.read().encode('utf-8'))
cur = d['d128']
for _ in range(128):
    cur = cur['n']
assert cur == 'ok128', f'unexpected leaf: {cur!r}'
print('PY_PLIST_128_OK')
`,
        xml128
      );
      assert.equal(pyDepthCheck.trim(), 'PY_PLIST_128_OK');

      cfg.defaults.set('com.bound', 'a128', arr128);
      cfg.sharedPrefs.edit('com.bound', 'prefs', [{ op: 'put', key: 'd128', value: obj128 }]);
      const sp128 = cfg.sharedPrefs.getAll('com.bound', 'prefs');
      let spWalk = sp128.d128;
      for (let i = 0; i < 128; i += 1) spWalk = spWalk.n;
      assert.equal(spWalk, 'ok128');

      cfg.system.set('custom.bound128', obj128);
      let sysWalk = cfg.system.get('custom.bound128');
      for (let i = 0; i < 128; i += 1) sysWalk = sysWalk.n;
      assert.equal(sysWalk, 'ok128');

      assert.throws(() => cfg.defaults.set('com.bound', 'd129', obj129), isEinvalNotRangeError);
      assert.throws(() => cfg.defaults.set('com.bound', 'a129', arr129), isEinvalNotRangeError);
      assert.throws(
        () => cfg.sharedPrefs.edit('com.bound', 'prefs', [{ op: 'put', key: 'd129', value: obj129 }]),
        isEinvalNotRangeError
      );
      assert.throws(() => cfg.system.set('custom.bound129', obj129), isEinvalNotRangeError);

      // 3. Cyclic objects still throw FormatError(E_CYCLIC_PLIST)
      const cyclic = { name: 'loop' };
      cyclic.self = cyclic;
      assert.throws(
        () => cfg.defaults.set('com.cyc', 'loop', cyclic),
        (err) => err instanceof FormatError && err.code === ERROR_CODES.E_CYCLIC_PLIST
      );
      assert.throws(
        () => cfg.sharedPrefs.edit('com.cyc', 'p', [{ op: 'put', key: 'loop', value: cyclic }]),
        (err) => err instanceof FormatError && err.code === ERROR_CODES.E_CYCLIC_PLIST
      );

      // 4. Tampered ultra-deep SQLite AST JSON throws typed OmniOSError(EINVAL) on read (never RangeError/SyntaxError)
      let ast200 = '["s","tampered"]';
      for (let i = 0; i < 200; i += 1) {
        ast200 = `["o",[["a",${ast200}]]]`;
      }
      let ast5000 = '["s","tampered-deep"]';
      for (let i = 0; i < 5000; i += 1) {
        ast5000 = `["o",[["a",${ast5000}]]]`;
      }
      const nowIso = new Date().toISOString();
      storage.run(
        'INSERT INTO defaults_entries (domain, key_name, value_ast_json, updated_at) VALUES (?, ?, ?, ?)',
        'com.tamper',
        'd200',
        ast200,
        nowIso
      );
      storage.run(
        'INSERT INTO defaults_entries (domain, key_name, value_ast_json, updated_at) VALUES (?, ?, ?, ?)',
        'com.tamper',
        'd5000',
        ast5000,
        nowIso
      );
      storage.run(
        'INSERT INTO shared_prefs_entries (package_name, pref_name, key_name, value_type, value_ast_json, updated_at) VALUES (?, ?, ?, ?, ?, ?)',
        'com.tamper',
        'prefs',
        'd200',
        'json',
        ast200,
        nowIso
      );

      assert.throws(() => cfg.defaults.get('com.tamper', 'd200'), isEinvalNotRangeError);
      assert.throws(() => cfg.defaults.get('com.tamper', 'd5000'), isEinvalNotRangeError);
      assert.throws(() => cfg.sharedPrefs.getAll('com.tamper', 'prefs'), isEinvalNotRangeError);
    } finally {
      cfg.close();
      storage.close();
    }
  });

  it('18.4 (I4): M2A daemon helpers & all 4 _requireStorage() methods guard revoked kernel / throwing getStorage() and safe healthCheck/isReady', async () => {
    const revObj = makeRevokedObjProxy();
    const revFn = makeRevokedFnProxy();
    const umBase = new UserManager();
    const pbBase = new PermissionBroker();
    const vfsBase = new VFS();
    const cfgBase = new UnifiedConfigStore();

    try {
      // 1. Registration-time rejection of already-revoked kernel & getStorage
      const smReg = new ServiceManager();
      assert.throws(
        () => registerSecurityService(smReg, { userManager: umBase, permissionBroker: pbBase, kernel: revObj }),
        (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => registerSecurityService(smReg, { userManager: umBase, permissionBroker: pbBase, getStorage: revFn }),
        (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => registerVfsService(smReg, vfsBase, { kernel: revObj }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => registerVfsService(smReg, vfsBase, { getStorage: revFn }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => createConfigService(cfgBase, { kernel: revObj }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => createConfigService(cfgBase, { getStorage: revFn }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => registerConfigService(smReg, cfgBase, { kernel: revObj }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => registerConfigService(smReg, cfgBase, { getStorage: revFn }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );

      // 2. Post-registration revoked kernel & throwing getStorage() caught inside start() with typed EINVAL
      const smPostRev = new ServiceManager();
      const kRevPair = Proxy.revocable({ storage: null }, {});
      registerSecurityService(smPostRev, {
        userManager: umBase,
        permissionBroker: pbBase,
        kernel: kRevPair.proxy,
      });
      registerVfsService(smPostRev, vfsBase, { kernel: kRevPair.proxy });
      registerConfigService(smPostRev, cfgBase, { kernel: kRevPair.proxy });
      const cfgSvcPostRev = createConfigService(cfgBase, { kernel: kRevPair.proxy });
      kRevPair.revoke();

      await assert.rejects(
        () => smPostRev.start('securityd'),
        (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
      );
      await assert.rejects(
        () => smPostRev.start('vfsd'),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
      );
      await assert.rejects(
        () => smPostRev.start('configd'),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => cfgSvcPostRev.start(),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );

      const smThrow = new ServiceManager();
      const throwingGetStorage = () => {
        throw new Error('GET_STORAGE_BOOM');
      };
      registerSecurityService(smThrow, {
        userManager: umBase,
        permissionBroker: pbBase,
        getStorage: throwingGetStorage,
      });
      registerVfsService(smThrow, vfsBase, { getStorage: throwingGetStorage });
      registerConfigService(smThrow, cfgBase, { getStorage: throwingGetStorage });

      await assert.rejects(
        () => smThrow.start('securityd'),
        (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
      );
      await assert.rejects(
        () => smThrow.start('vfsd'),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
      );
      await assert.rejects(
        () => smThrow.start('configd'),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );

      // 3. Safe healthCheck() on post-start dependency revocation
      const hcStorage = new SqliteStorage(':memory:');
      try {
        const umHc = Proxy.revocable(new UserManager({ storage: hcStorage }), {});
        const pbHc = Proxy.revocable(new PermissionBroker({ storage: hcStorage }), {});
        const vfsHc = Proxy.revocable(new VFS({ storage: hcStorage }), {});
        const cfgHc = Proxy.revocable(new UnifiedConfigStore({ storage: hcStorage }), {});

        const smHc = new ServiceManager();
        registerSecurityService(smHc, {
          userManager: umHc.proxy,
          permissionBroker: pbHc.proxy,
          getStorage: () => hcStorage,
        });
        registerVfsService(smHc, vfsHc.proxy, { getStorage: () => hcStorage });
        registerConfigService(smHc, cfgHc.proxy, { getStorage: () => hcStorage });

        await smHc.start('securityd');
        await smHc.start('vfsd');
        await smHc.start('configd');
        assert.equal(smHc._services.get('securityd').healthCheck().ok, true);
        assert.equal(smHc._services.get('vfsd').healthCheck().ok, true);
        assert.equal(smHc._services.get('configd').healthCheck().ok, true);

        umHc.revoke();
        pbHc.revoke();
        vfsHc.revoke();
        cfgHc.revoke();

        assert.equal(smHc._services.get('securityd').healthCheck().ok, false);
        assert.equal(smHc._services.get('vfsd').healthCheck().ok, false);
        assert.equal(smHc._services.get('configd').healthCheck().ok, false);
      } finally {
        hcStorage.close();
      }

      // 4. All 4 M2A SQLite classes: _requireStorage() & isReady on post-construction revoked kernel
      const kLate = Proxy.revocable({ storage: null, eventBus: null, processManager: null }, {});
      const umK = new UserManager({ kernel: kLate.proxy });
      const pbK = new PermissionBroker({ kernel: kLate.proxy });
      const vfsK = new VFS({ kernel: kLate.proxy });
      const cfgK = new UnifiedConfigStore({ kernel: kLate.proxy });
      kLate.revoke();

      assert.equal(umK.isReady, false);
      assert.equal(pbK.isReady, false);
      assert.equal(vfsK.isReady, false);
      assert.equal(cfgK.isReady(), false);

      assert.throws(
        () => umK.listUsers(),
        (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => pbK.listGrants(),
        (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => vfsK.stat('/'),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => cfgK.system.get('system.theme'),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );

      // 5. All 4 M2A SQLite classes: _requireStorage() & isReady on post-construction throwing getStorage()
      let shouldBoom = false;
      const flakyStorage = () => {
        if (shouldBoom) throw new Error('LAZY_STORAGE_BOOM');
        return null;
      };
      const umG = new UserManager({ getStorage: flakyStorage });
      const pbG = new PermissionBroker({ getStorage: flakyStorage });
      const vfsG = new VFS({ getStorage: flakyStorage });
      const cfgG = new UnifiedConfigStore({ getStorage: flakyStorage });
      shouldBoom = true;

      assert.equal(umG.isReady, false);
      assert.equal(pbG.isReady, false);
      assert.equal(vfsG.isReady, false);
      assert.equal(cfgG.isReady(), false);

      assert.throws(
        () => umG.listUsers(),
        (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => pbG.listGrants(),
        (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => vfsG.stat('/'),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => cfgG.system.get('system.theme'),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
    } finally {
      umBase.close();
      pbBase.close();
      vfsBase.close();
      cfgBase.close();
    }
  });

  it('18.5 (J1): PackageManager preserves PermissionBroker grants across failed reinstalls after uninstall({ purgeData: false })', async () => {
    const storage = new SqliteStorage(':memory:');
    const users = new UserManager({ storage });
    const perms = new PermissionBroker({ storage, userManager: users });
    const vfs = new VFS({ storage, userManager: users });
    const router = new IntentRouter();
    let failIntentRegistration = false;
    let routerCalled = false;
    const origRegisterHandlers = router.registerHandlers.bind(router);
    router.registerHandlers = (appId, handlers) => {
      routerCalled = true;
      if (failIntentRegistration) {
        throw new OmniOSError('Simulated intentRouter.registerHandlers failure', {
          code: ERROR_CODES.EINVAL,
        });
      }
      return origRegisterHandlers(appId, handlers);
    };

    const pm = new PackageManager({
      storage,
      vfs,
      users,
      permissions: perms,
      intentRouter: router,
    });

    try {
      const uapp = createZip({ 'omnios.manifest.json': '{"appId":"com.keep.perms"}' });
      pm.registerRuntime('universal', {
        platform: 'universal',
        inspectPackage: () => ({
          appId: 'com.keep.perms',
          name: 'KeepPerms',
          platform: 'universal',
          format: 'universal-uapp',
          intents: [{ action: 'view', extension: '.kp' }],
        }),
        installPackage: () => ({}),
        createExecutionContext: () => makeWorkExecContext({ totalWork: 10 }),
      });

      assert.equal(CAPABILITIES.NETWORK_OUTBOUND, 'network.outbound');

      await pm.install(uapp, {
        grants: {
          [CAPABILITIES.CAMERA_DEVICE]: PERMISSION_STATES.ALLOW,
          [CAPABILITIES.LOCATION_DEVICE]: PERMISSION_STATES.DENY,
        },
      });
      // Apply a custom admin source to verify source metadata is preserved across failed reinstall rollbacks
      perms.setGrant('com.keep.perms', CAPABILITIES.LOCATION_DEVICE, PERMISSION_STATES.DENY, {
        source: 'admin',
      });
      await pm.uninstall('com.keep.perms', { purgeData: false });

      assert.equal(pm.get('com.keep.perms'), null);
      const afterUninstall = new Map(perms.listGrants('com.keep.perms').map((g) => [g.capability, g]));
      assert.equal(afterUninstall.size, 2);
      assert.equal(afterUninstall.get(CAPABILITIES.CAMERA_DEVICE)?.state, PERMISSION_STATES.ALLOW);
      assert.equal(afterUninstall.get(CAPABILITIES.LOCATION_DEVICE)?.state, PERMISSION_STATES.DENY);
      assert.equal(afterUninstall.get(CAPABILITIES.LOCATION_DEVICE)?.source, 'admin');

      // Failure path A: mutates camera.device grant first, then fails on invalid grant state
      await assert.rejects(
        () =>
          pm.install(uapp, {
            grants: {
              [CAPABILITIES.CAMERA_DEVICE]: PERMISSION_STATES.PROMPT,
              [CAPABILITIES.NETWORK_OUTBOUND]: 'INVALID_STATE',
            },
          }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );

      assert.equal(pm.get('com.keep.perms'), null);
      const afterFailA = new Map(perms.listGrants('com.keep.perms').map((g) => [g.capability, g]));
      assert.equal(afterFailA.size, 2);
      assert.equal(afterFailA.get(CAPABILITIES.CAMERA_DEVICE)?.state, PERMISSION_STATES.ALLOW);
      assert.equal(afterFailA.get(CAPABILITIES.LOCATION_DEVICE)?.state, PERMISSION_STATES.DENY);
      assert.equal(afterFailA.get(CAPABILITIES.LOCATION_DEVICE)?.source, 'admin');

      // Failure path B: mutates existing grant AND adds a genuine defined capability grant,
      // then fails specifically inside intentRouter.registerHandlers()
      routerCalled = false;
      failIntentRegistration = true;
      await assert.rejects(
        () =>
          pm.install(uapp, {
            grants: {
              [CAPABILITIES.CAMERA_DEVICE]: PERMISSION_STATES.DENY,
              [CAPABILITIES.NETWORK_OUTBOUND]: PERMISSION_STATES.ALLOW,
            },
          }),
        (err) =>
          err instanceof OmniOSError &&
          err.code === ERROR_CODES.EINVAL &&
          err.message.includes('Simulated intentRouter.registerHandlers failure')
      );
      failIntentRegistration = false;
      assert.equal(routerCalled, true, 'Path B must reach intentRouter.registerHandlers() after setGrant succeeds');

      assert.equal(pm.get('com.keep.perms'), null);
      const afterFailB = new Map(perms.listGrants('com.keep.perms').map((g) => [g.capability, g]));
      assert.equal(afterFailB.size, 2);
      assert.equal(afterFailB.get(CAPABILITIES.CAMERA_DEVICE)?.state, PERMISSION_STATES.ALLOW);
      assert.equal(afterFailB.get(CAPABILITIES.LOCATION_DEVICE)?.state, PERMISSION_STATES.DENY);
      assert.equal(afterFailB.get(CAPABILITIES.LOCATION_DEVICE)?.source, 'admin');
      assert.equal(afterFailB.has(CAPABILITIES.NETWORK_OUTBOUND), false);
    } finally {
      pm.close();
      storage.close();
    }
  });

  it('18.6 (J2): Structural record cloners prevent "[Unreadable]" collapse across PackageManager, NotificationCenter & IntentRouter', async () => {
    const drain249995 = makeDrain(249_995);
    const half150k = makeDrain(150_000);
    const half95k = makeDrain(95_000);

    const kernel = new OmniKernel({ storage: new SqliteStorage(':memory:') });
    await kernel.boot();
    const pm = new PackageManager({ kernel });

    try {
      // 1. PackageManager.registerCatalogEntry() & getCatalog() with 249,995-node metadata
      const catRec = pm.registerCatalogEntry({
        appId: 'com.cat.big',
        name: 'BigCatalogApp',
        platform: 'universal',
        metadata: drain249995,
      });
      assert.equal(typeof catRec, 'object');
      assert.notEqual(catRec, null);
      assert.equal(catRec.appId, 'com.cat.big');
      assert.equal(catRec.installed, false);
      assert.equal(catRec['0'], undefined, 'Catalog entry must never spread "[Unreadable]" string');
      assert.equal(Array.isArray(catRec.metadata), true);

      const catList = pm.getCatalog();
      const foundCat = catList.find((c) => c.appId === 'com.cat.big');
      assert.equal(typeof foundCat, 'object');
      assert.equal(foundCat.appId, 'com.cat.big');
      assert.equal(foundCat.installed, false);
      assert.equal(foundCat['0'], undefined);

      // 2. PackageManager.inspect() with 249,995-node rawMetadata
      const uappZip = createZip({ 'omnios.manifest.json': '{"appId":"com.inspect.big"}' });
      let mode = 'inspect249';
      pm.registerRuntime('universal', {
        platform: 'universal',
        inspectPackage() {
          if (mode === 'inspect249') {
            return {
              appId: 'com.inspect.big',
              name: 'InspectBig',
              platform: 'universal',
              format: 'universal-uapp',
              rawMetadata: drain249995,
            };
          }
          if (mode === 'overflow150') {
            return {
              appId: 'com.overflow.big',
              name: 'OverflowBig',
              platform: 'universal',
              format: 'universal-uapp',
              rawMetadata: { a: half150k },
            };
          }
          return {
            appId: 'com.launchable.big',
            name: 'LaunchableBig',
            platform: 'universal',
            format: 'universal-uapp',
            rawMetadata: { a: half95k },
          };
        },
        installPackage() {
          if (mode === 'overflow150') {
            return { metadata: { b: half150k } };
          }
          return { metadata: { b: half95k } };
        },
        createExecutionContext: () => makeWorkExecContext({ totalWork: 10 }),
      });

      const inspected = await pm.inspect(uappZip);
      assert.equal(typeof inspected, 'object');
      assert.equal(inspected.appId, 'com.inspect.big');
      assert.equal(inspected.platform, 'universal');
      assert.equal(Array.isArray(inspected.rawMetadata), true);

      // 3. PackageManager.install() rejects 150k + 150k merged metadata atomically with QuotaExceededError(EQUOTA)
      mode = 'overflow150';
      await assert.rejects(
        () => pm.install(uappZip),
        (err) => err instanceof QuotaExceededError && err.code === ERROR_CODES.EQUOTA
      );
      assert.equal(pm.get('com.overflow.big'), null);
      assert.equal(pm.list().length, 0);

      // 4. 95k + 95k installs cleanly, get()/list() return intact records, and pm.launch() succeeds
      mode = 'ok95';
      const installed = await pm.install(uappZip);
      assert.equal(typeof installed, 'object');
      assert.equal(installed.appId, 'com.launchable.big');
      assert.equal(installed.platform, 'universal');
      assert.equal(Array.isArray(installed.metadata.a), true);
      assert.equal(Array.isArray(installed.metadata.b), true);

      const gotApp = pm.get('com.launchable.big');
      assert.equal(typeof gotApp, 'object');
      assert.equal(gotApp.appId, 'com.launchable.big');
      assert.equal(gotApp.platform, 'universal');

      const listedApps = pm.list();
      assert.equal(listedApps.length, 1);
      assert.equal(typeof listedApps[0], 'object');
      assert.equal(listedApps[0].appId, 'com.launchable.big');

      const launched = await pm.launch('com.launchable.big');
      assert.equal(launched.appId, 'com.launchable.big');
      assert.equal(typeof launched.pid, 'number');
      pm.stop(launched.pid);

      // 5. NotificationCenter.post()/list() & LiveActivity lifecycle with large subfields
      const notif = new NotificationCenter({ eventBus: kernel.eventBus });
      const posted = notif.post({
        appId: 'com.notif.big',
        title: 'BigNotif',
        data: drain249995,
      });
      assert.equal(typeof posted, 'object');
      assert.equal(posted.appId, 'com.notif.big');
      assert.equal(posted.title, 'BigNotif');
      assert.equal(Array.isArray(posted.data), true);

      const listedNotifs = notif.list();
      assert.equal(listedNotifs.length, 1);
      assert.equal(typeof listedNotifs[0], 'object');
      assert.equal(listedNotifs[0].appId, 'com.notif.big');

      const postedLa = notif.post({
        appId: 'com.la.big',
        title: 'LiveAct',
        liveActivity: {
          title: 'Delivery',
          compactLeading: half150k,
          payload: half150k,
        },
      });
      assert.equal(typeof postedLa, 'object');
      assert.equal(typeof postedLa.liveActivity, 'object');
      assert.equal(postedLa.liveActivity.title, 'Delivery');
      assert.equal(Array.isArray(postedLa.liveActivity.compactLeading), true);
      assert.equal(Array.isArray(postedLa.liveActivity.payload), true);

      const laId = postedLa.liveActivity.id;
      const updatedLa = notif.updateLiveActivity(laId, {
        compactTrailing: half95k,
        expandedBody: half95k,
      });
      assert.equal(typeof updatedLa, 'object');
      assert.equal(updatedLa.id, laId);
      assert.equal(Array.isArray(updatedLa.compactTrailing), true);
      assert.equal(Array.isArray(updatedLa.expandedBody), true);

      const activeLas = notif.getLiveActivities();
      assert.equal(activeLas.length, 1);
      assert.equal(typeof activeLas[0], 'object');
      assert.equal(activeLas[0].id, laId);

      const endedLa = notif.endLiveActivity(laId);
      assert.equal(typeof endedLa, 'object');
      assert.equal(endedLa.id, laId);
      assert.equal(endedLa.state, 'ended');

      // 6. IntentRouter.dispatch() single handler & chooser mode with 249,995-node extras
      const router = new IntentRouter({
        eventBus: kernel.eventBus,
        processManager: kernel.processManager,
      });
      const singleExec = makeWorkExecContext({ totalWork: 100 });
      const singlePcb = kernel.processManager.spawn({
        name: 'SingleHandler',
        appId: 'com.router.single',
        platform: 'universal',
        executionContext: singleExec,
      });
      router.registerHandlers('com.router.single', [{ action: 'view', extension: '.one' }]);
      const singleRes = await router.dispatch({
        action: 'view',
        uri: '/doc.one',
        extras: drain249995,
      });
      assert.equal(singleRes.status, 'DELIVERED');
      assert.equal(singleRes.targetAppId, 'com.router.single');
      assert.equal(singleRes.pid, singlePcb.pid);
      assert.equal(singleExec.receivedEvents.length, 1);
      const deliveredIntent = singleExec.receivedEvents[0].intent;
      assert.equal(typeof deliveredIntent, 'object');
      assert.equal(deliveredIntent.action, 'view');
      assert.equal(Array.isArray(deliveredIntent.extras), true);
      kernel.processManager.exit(singlePcb.pid, 0);

      const chooserEvents = [];
      kernel.eventBus.on('intent:chooser', (evt) => chooserEvents.push(evt));
      router.registerHandlers('com.router.a', [{ action: 'view', extension: '.two' }]);
      router.registerHandlers('com.router.b', [{ action: 'view', extension: '.two' }]);
      const chooserRes = await router.dispatch({
        action: 'view',
        uri: '/doc.two',
        extras: drain249995,
      });
      assert.equal(chooserRes.status, 'CHOOSER_REQUIRED');
      assert.equal(typeof chooserRes.requestId, 'string');
      assert.equal(chooserEvents.length, 1);
      assert.equal(typeof chooserEvents[0], 'object');
      assert.equal(chooserEvents[0].requestId, chooserRes.requestId);
      assert.equal(typeof chooserEvents[0].intent, 'object');
      assert.equal(Array.isArray(chooserEvents[0].intent.extras), true);
      assert.equal(chooserEvents[0].candidates.length, 2);

      const pendingChoosers = router.listPendingChoosers();
      assert.equal(pendingChoosers.length, 1);
      assert.equal(typeof pendingChoosers[0], 'object');
      assert.equal(pendingChoosers[0].requestId, chooserRes.requestId);
      assert.equal(typeof pendingChoosers[0].intent, 'object');
      assert.equal(Array.isArray(pendingChoosers[0].intent.extras), true);
      assert.equal(pendingChoosers[0].candidates.length, 2);
    } finally {
      pm.close();
      await kernel.shutdown();
    }
  });

  it('18.7 (J3): PackageManager enforces canonical dataDir/installDir containment, symlink defense & tampered-DB uninstall guard', async () => {
    const storage = new SqliteStorage(':memory:');
    const users = new UserManager({ storage });
    const vfs = new VFS({ storage, userManager: users });
    const pm = new PackageManager({ storage, vfs, users });

    try {
      vfs.mkdir('/etc', { recursive: true, uid: ROOT_UID, gid: ROOT_GID });
      vfs.writeFile('/etc/important.conf', 'keep-me-intact', { uid: ROOT_UID, gid: ROOT_GID });
      assert.equal(vfs.stat('/etc', { uid: ROOT_UID, gid: ROOT_GID }).uid, ROOT_UID);

      const ipa = buildIpaFixture();
      let currentAppId = 'com.evil.trav';
      let currentInstallOpts = {};

      pm.registerRuntime('ios', {
        platform: 'ios',
        inspectPackage: () => ({
          appId: currentAppId,
          name: currentAppId,
          platform: 'ios',
          format: 'ios-ipa',
        }),
        installPackage: () => currentInstallOpts,
        createExecutionContext: () => makeWorkExecContext({ totalWork: 10 }),
      });

      // 1. Traversal dataDir fails strictly BEFORE mkdir/chown(ROOT_VFS_CTX) and rolls back fresh UID
      currentAppId = 'com.evil.trav';
      currentInstallOpts = { dataDir: '/var/appdata/ios/../../../etc' };
      await assert.rejects(
        () => pm.install(ipa),
        (err) => err instanceof SecurityError && err.code === ERROR_CODES.E_PATH_TRAVERSAL
      );
      assert.equal(vfs.stat('/etc', { uid: ROOT_UID, gid: ROOT_GID }).uid, ROOT_UID);
      assert.equal(users.getUserByAppId('com.evil.trav'), null);
      assert.equal(pm.get('com.evil.trav'), null);

      // 2. Direct system paths, prefix-sibling bypasses, cross-platform paths & traversal installDir rejected
      const forbiddenInstallConfigs = [
        ['com.evil.etc', { dataDir: '/etc' }],
        ['com.evil.root', { dataDir: '/' }],
        ['com.evil.platroot', { dataDir: '/var/appdata/ios' }],
        ['com.evil.sibling', { dataDir: '/var/appdata/ios2/x' }],
        ['com.evil.crossplat', { dataDir: '/var/appdata/android/x' }],
        ['com.evil.instetc', { installDir: '/etc' }],
        ['com.evil.insttrav', { installDir: '/apps/ios/../etc' }],
        ['com.evil.instroot', { installDir: '/apps/ios' }],
      ];
      for (const [appId, installCfg] of forbiddenInstallConfigs) {
        currentAppId = appId;
        currentInstallOpts = installCfg;
        await assert.rejects(
          () => pm.install(ipa),
          (err) => err instanceof SecurityError && err.code === ERROR_CODES.E_PATH_TRAVERSAL,
          `Expected E_PATH_TRAVERSAL for ${appId} (${JSON.stringify(installCfg)})`
        );
        assert.equal(users.getUserByAppId(appId), null);
        assert.equal(pm.get(appId), null);
        assert.equal(vfs.stat('/etc', { uid: ROOT_UID, gid: ROOT_GID }).uid, ROOT_UID);
      }

      // 3. Pre-planted symlink under /var/appdata/ios -> /etc rejected cleanly
      vfs.mkdir('/var/appdata/ios', { recursive: true, uid: ROOT_UID, gid: ROOT_GID });
      vfs.symlink('/etc', '/var/appdata/ios/evil-link', { uid: ROOT_UID, gid: ROOT_GID });
      for (const [appId, badDir] of [
        ['com.evil.sym1', '/var/appdata/ios/evil-link'],
        ['com.evil.sym2', '/var/appdata/ios/evil-link/nested'],
      ]) {
        currentAppId = appId;
        currentInstallOpts = { dataDir: badDir };
        await assert.rejects(
          () => pm.install(ipa),
          (err) => err instanceof SecurityError && err.code === ERROR_CODES.E_PATH_TRAVERSAL
        );
        assert.equal(vfs.stat('/etc', { uid: ROOT_UID, gid: ROOT_GID }).uid, ROOT_UID);
        assert.equal(users.getUserByAppId(appId), null);
      }

      // 4. Tampered SQLite data_dir = '/etc' blocked in uninstall({ purgeData: true }) so /etc/important.conf survives
      currentAppId = 'com.tamper.db';
      currentInstallOpts = {};
      await pm.install(ipa);
      storage.run('UPDATE installed_packages SET data_dir = ? WHERE app_id = ?', '/etc', 'com.tamper.db');
      const pmReloaded = new PackageManager({ storage, vfs, users });
      await assert.rejects(
        () => pmReloaded.uninstall('com.tamper.db', { purgeData: true }),
        (err) => err instanceof SecurityError && err.code === ERROR_CODES.E_PATH_TRAVERSAL
      );
      assert.equal(
        vfs.readFile('/etc/important.conf', { encoding: 'utf8', uid: ROOT_UID, gid: ROOT_GID }),
        'keep-me-intact'
      );
      pmReloaded.close();

      // 5. Legitimate custom iOS UUID container installs, writes as app UID, enforces jail & uninstalls cleanly
      const uuidDir = '/var/appdata/ios/containers/550e8400-e29b-41d4-a716-446655440000';
      currentAppId = 'com.ios.uuid';
      currentInstallOpts = { dataDir: uuidDir };
      const uuidRec = await pm.install(ipa);
      assert.equal(uuidRec.dataDir, uuidDir);
      assert.ok(uuidRec.uid >= SANDBOX_UID_BASE);

      const appCtx = { uid: uuidRec.uid, gid: uuidRec.gid };
      vfs.writeFile(`${uuidDir}/state.json`, '{"ok":true}', appCtx);
      assert.equal(vfs.readFile(`${uuidDir}/state.json`, { ...appCtx, encoding: 'utf8' }), '{"ok":true}');
      assert.throws(
        () => vfs.readFile('/etc/important.conf', { ...appCtx, encoding: 'utf8' }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EACCES
      );

      await pm.uninstall('com.ios.uuid', { purgeData: true });
      assert.equal(pm.get('com.ios.uuid'), null);
      assert.throws(
        () => vfs.stat(uuidDir, { uid: ROOT_UID, gid: ROOT_GID }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.ENOENT
      );
      assert.equal(
        vfs.readFile('/etc/important.conf', { encoding: 'utf8', uid: ROOT_UID, gid: ROOT_GID }),
        'keep-me-intact'
      );
    } finally {
      pm.close();
      storage.close();
    }
  });

  it('18.8 (J4): M2B revoked dependencies, PackageManager._ensureReady()/_getExistingAppUser & M2B daemon helpers throw typed EINVAL without leaking state', async () => {
    const revObj = makeRevokedObjProxy();
    const kernel = new OmniKernel({ storage: new SqliteStorage(':memory:') });
    await kernel.boot();
    const storage = new SqliteStorage(':memory:');

    try {
      // 1. IPCManager constructor rejects revoked processManager / eventBus
      assert.throws(
        () => new IPCManager({ processManager: revObj }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => new IPCManager({ eventBus: revObj }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );

      // Post-construction revoked processManager does not crash with raw TypeError or leave partial leaks
      const pmRev = Proxy.revocable(
        {
          has: () => true,
          addCleanupHook: () => () => {},
        },
        {}
      );
      const ipc = new IPCManager({ processManager: pmRev.proxy });
      pmRev.revoke();

      const ch = ipc.createChannel('c1', 10);
      assert.equal(ch.name, 'c1');
      assert.equal(ipc.listChannels().length, 1);

      const shm = ipc.shmCreate('s1', 1024, 10);
      assert.equal(shm.name, 's1');
      assert.equal(ipc.listShm().length, 1);
      assert.equal(ipc._totalShmBytes, 1024);

      ipc.registerRpc('ep1', () => 'rpc-ok', { ownerPid: 10 });
      assert.equal(await ipc.callRpc('ep1', {}), 'rpc-ok');

      // 2. Compositor.start() & setShellMode() succeed cleanly with { configStore: { system: rev } }
      const comp = new Compositor({ kernel, configStore: { system: revObj } });
      comp.start();
      const modeRes = comp.setShellMode('macos');
      assert.equal(modeRes.shellMode, 'macos');
      assert.equal(comp.getSnapshot().shellMode, 'macos');
      comp.stop();

      // 3. PackageManager constructor rejects revoked optional deps
      for (const depKey of ['processManager', 'users', 'vfs', 'permissions', 'intentRouter', 'detector']) {
        assert.throws(
          () => new PackageManager({ [depKey]: revObj }),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL,
          `Expected EINVAL for revoked PackageManager.${depKey}`
        );
      }

      // Post-construction revoked kernel returns isReady() === false and throws OmniOSError(EINVAL)
      const kLate = Proxy.revocable({ storage: null, eventBus: null, processManager: null }, {});
      const pmLate = new PackageManager({ kernel: kLate.proxy });
      kLate.revoke();
      assert.equal(pmLate.isReady(), false);
      assert.throws(
        () => pmLate.list(),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => pmLate.get('com.any'),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );

      // _getExistingAppUser survives post-construction revoked users
      const usersLate = Proxy.revocable(new UserManager({ storage }), {});
      const pmUsersLate = new PackageManager({ storage, users: usersLate.proxy });
      usersLate.revoke();
      assert.equal(pmUsersLate._getExistingAppUser('com.any'), null);
      pmUsersLate.close();

      // 4. M2B daemon helpers reject revoked kernel at registration & on start() with OmniOSError(EINVAL)
      const smReg = new ServiceManager();
      const pkgBase = new PackageManager({ storage });
      const compBase = new Compositor({ kernel });
      const ipcBase = new IPCManager();

      assert.throws(
        () => registerPackageService(smReg, pkgBase, { kernel: revObj }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => registerCompositorService(smReg, compBase, { kernel: revObj }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => createIpcBrokerService({ ipc: ipcBase, kernel: revObj }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => registerIpcBrokerService(smReg, { ipc: ipcBase, kernel: revObj }),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );

      // Post-registration revoked kernel caught inside start() with OmniOSError(EINVAL)
      const smPost = new ServiceManager();
      const kPost = Proxy.revocable({ storage }, {});
      registerPackageService(smPost, pkgBase, { kernel: kPost.proxy });
      registerCompositorService(smPost, compBase, { kernel: kPost.proxy });
      registerIpcBrokerService(smPost, { ipc: ipcBase, kernel: kPost.proxy });
      const brokerSvcPost = createIpcBrokerService({ ipc: ipcBase, kernel: kPost.proxy });
      kPost.revoke();

      await assert.rejects(
        () => smPost.start('pkgd'),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      await assert.rejects(
        () => smPost.start('compositord'),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      await assert.rejects(
        () => smPost.start('ipc-brokerd'),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => brokerSvcPost.start(),
        (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL
      );

      // Safe healthCheck() on post-start M2B dependency revocation
      const hcSm = new ServiceManager();
      const pkgHc = Proxy.revocable(new PackageManager({ storage }), {});
      const compHc = Proxy.revocable(new Compositor({ kernel }), {});
      const ipcHc = Proxy.revocable(new IPCManager(), {});
      registerPackageService(hcSm, pkgHc.proxy, { storage });
      registerCompositorService(hcSm, compHc.proxy, { kernel });
      registerIpcBrokerService(hcSm, { ipc: ipcHc.proxy, kernel });
      await hcSm.start('pkgd');
      await hcSm.start('compositord');
      await hcSm.start('ipc-brokerd');
      assert.equal((await hcSm._services.get('pkgd').healthCheck()).ok, true);
      assert.equal((await hcSm._services.get('compositord').healthCheck()).ok, true);
      assert.equal(hcSm._services.get('ipc-brokerd').healthCheck().ok, true);

      pkgHc.revoke();
      compHc.revoke();
      ipcHc.revoke();
      assert.equal((await hcSm._services.get('pkgd').healthCheck()).ok, false);
      assert.equal((await hcSm._services.get('compositord').healthCheck()).ok, false);
      assert.equal(hcSm._services.get('ipc-brokerd').healthCheck().ok, false);

      pkgBase.close();
    } finally {
      storage.close();
      await kernel.shutdown();
    }
  });
});

// ============================================================================
// SUITE 19: Iteration 7 Final Surgical Defect Regressions (K1–K3, Obs-1/2, L1–L2)
// ============================================================================

describe('Suite 19: Iteration 7 Final Surgical Defect Regressions (K1–K3, Obs-1/2, L1–L2)', () => {
  function makeRevokedObj() {
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    return proxy;
  }

  function isTypedEinval(err) {
    return (
      err instanceof OmniOSError &&
      err.code === ERROR_CODES.EINVAL &&
      !(err instanceof TypeError) &&
      !(err instanceof SyntaxError) &&
      !(err instanceof RangeError)
    );
  }

  it('19.1 (K1): UnifiedConfigStore enforces MAX_CONFIG_NODES = 65536 against DAG OOM DoS & tampered wide ASTs', () => {
    const storage = new SqliteStorage(':memory:');
    const cfg = new UnifiedConfigStore({ storage });

    try {
      // 1. 26-object non-cyclic DAG (depth 25 << 128, 2^25 ~= 33.5M logical nodes)
      let arrDag = { v: 1 };
      for (let i = 0; i < 25; i += 1) {
        arrDag = [arrDag, arrDag];
      }
      let objDag = { v: 1 };
      for (let i = 0; i < 25; i += 1) {
        objDag = { a: objDag, b: objDag };
      }

      const t0 = performance.now();
      assert.throws(() => cfg.defaults.set('com.dag', 'arr', arrDag), isTypedEinval);
      assert.throws(() => cfg.defaults.set('com.dag', 'obj', objDag), isTypedEinval);
      assert.throws(
        () => cfg.sharedPrefs.edit('com.dag', 'prefs', [{ op: 'put', key: 'arr', value: arrDag }]),
        isTypedEinval
      );
      assert.throws(() => cfg.system.set('custom.dag', arrDag), isTypedEinval);
      assert.throws(
        () =>
          cfg.registry.setValue(
            REGISTRY_HIVES.HKCU,
            'Software\\DagGuard',
            'multi',
            REGISTRY_TYPES.REG_MULTI_SZ,
            arrDag
          ),
        isTypedEinval
      );
      const elapsedMs = performance.now() - t0;
      assert.ok(elapsedMs < 1000, `DAG rejections must complete instantaneously (<1000ms), got ${elapsedMs.toFixed(1)}ms`);

      // Verify zero partial persistence on rejected DAG writes
      assert.equal(cfg.defaults.get('com.dag', 'arr'), null);
      assert.equal(cfg.defaults.get('com.dag', 'obj'), null);
      assert.equal(cfg.sharedPrefs.get('com.dag', 'prefs', 'arr', null), null);
      assert.equal(cfg.system.get('custom.dag'), null);
      assert.equal(cfg.registry.getValue(REGISTRY_HIVES.HKCU, 'Software\\DagGuard', 'multi'), null);

      // 2. Legitimate nested config well under 65536 nodes succeeds across defaults, sharedPrefs, system & plist export
      let safeTree = { leaf: 'ok', count: 42 };
      for (let i = 0; i < 10; i += 1) {
        safeTree = { left: safeTree, right: i };
      }
      cfg.defaults.set('com.ok', 'nested', safeTree);
      const gotDef = cfg.defaults.get('com.ok', 'nested');
      assert.equal(gotDef.right, 9);
      let cur = gotDef;
      for (let i = 0; i < 10; i += 1) cur = cur.left;
      assert.deepEqual(cur, { leaf: 'ok', count: 42 });

      const xmlOk = cfg.defaults.exportPlistXml('com.ok');
      assert.ok(xmlOk.includes('<string>ok</string>'));
      assert.ok(xmlOk.includes('<integer>42</integer>'));

      cfg.sharedPrefs.edit('com.ok', 'prefs', [{ op: 'put', key: 'nested', value: safeTree }]);
      assert.equal(cfg.sharedPrefs.get('com.ok', 'prefs', 'nested').right, 9);

      cfg.system.set('custom.okTree', safeTree);
      assert.equal(cfg.system.get('custom.okTree').right, 9);

      // 3. Genuine cyclic objects & arrays STILL throw FormatError(E_CYCLIC_PLIST) (ancestors checked before node budget)
      const cycObj = { tag: 'cycle' };
      cycObj.self = cycObj;
      const cycArr = [];
      cycArr.push(cycArr);
      assert.throws(
        () => cfg.defaults.set('com.cyc', 'o', cycObj),
        (err) => err instanceof FormatError && err.code === ERROR_CODES.E_CYCLIC_PLIST
      );
      assert.throws(
        () => cfg.defaults.set('com.cyc', 'a', cycArr),
        (err) => err instanceof FormatError && err.code === ERROR_CODES.E_CYCLIC_PLIST
      );
      assert.throws(
        () => cfg.sharedPrefs.edit('com.cyc', 'p', [{ op: 'put', key: 'o', value: cycObj }]),
        (err) => err instanceof FormatError && err.code === ERROR_CODES.E_CYCLIC_PLIST
      );

      // 4. Tampered 70,000-node SQLite AST (shallow depth 2 << 128, but > 65536 nodes) throws OmniOSError(EINVAL) on read
      const wideElems = new Array(70_000).fill('["i",1]').join(',');
      const wideAst70k = `["a",[${wideElems}]]`;
      const nowIso = new Date().toISOString();
      storage.run(
        'INSERT INTO defaults_entries (domain, key_name, value_ast_json, updated_at) VALUES (?, ?, ?, ?)',
        'com.wide',
        'big70k',
        wideAst70k,
        nowIso
      );
      storage.run(
        'INSERT INTO shared_prefs_entries (package_name, pref_name, key_name, value_type, value_ast_json, updated_at) VALUES (?, ?, ?, ?, ?, ?)',
        'com.wide',
        'prefs',
        'big70k',
        'json',
        wideAst70k,
        nowIso
      );

      assert.throws(() => cfg.defaults.get('com.wide', 'big70k'), isTypedEinval);
      assert.throws(() => cfg.defaults.readDomain('com.wide'), isTypedEinval);
      assert.throws(() => cfg.defaults.exportPlistXml('com.wide'), isTypedEinval);
      assert.throws(() => cfg.sharedPrefs.get('com.wide', 'prefs', 'big70k'), isTypedEinval);
      assert.throws(() => cfg.sharedPrefs.getAll('com.wide', 'prefs'), isTypedEinval);

      // 5. Combined multi-key domain exceeding MAX_CONFIG_NODES during serializePlistValueXml throws OmniOSError(EINVAL)
      const arr40k = new Array(40_000).fill(1);
      cfg.defaults.set('com.plistcap', 'k1', arr40k);
      cfg.defaults.set('com.plistcap', 'k2', arr40k);
      assert.throws(() => cfg.defaults.exportPlistXml('com.plistcap'), isTypedEinval);
    } finally {
      cfg.close();
      storage.close();
    }
  });

  it('19.2 (K2): UnifiedConfigStore rejects tampered malformed SQLite ASTs, corrupt system_config & corrupt registry rows with typed OmniOSError(EINVAL)', () => {
    const storage = new SqliteStorage(':memory:');
    const cfg = new UnifiedConfigStore({ storage });

    try {
      const nowIso = new Date().toISOString();
      const malformedAstCases = [
        ['o_num', '["o",[123]]'],
        ['o_null', '["o",[null]]'],
        ['o_short_tuple', '["o",[["onlyKey"]]]'],
        ['o_non_str_key', '["o",[[99,["s","v"]]]]'],
        ['i_not_bigint', '["I","not_a_bigint"]'],
        ['i_null', '["I",null]'],
        ['x_num', '["x",12345]'],
        ['x_null', '["x",null]'],
        ['d_bad', '["d","not-a-date"]'],
        ['d_num', '["d",12345]'],
      ];

      // 1. Insert all malformed AST vectors into defaults_entries and shared_prefs_entries
      for (const [key, astJson] of malformedAstCases) {
        storage.run(
          'INSERT INTO defaults_entries (domain, key_name, value_ast_json, updated_at) VALUES (?, ?, ?, ?)',
          `com.bad.${key}`,
          key,
          astJson,
          nowIso
        );
        storage.run(
          'INSERT INTO shared_prefs_entries (package_name, pref_name, key_name, value_type, value_ast_json, updated_at) VALUES (?, ?, ?, ?, ?, ?)',
          `com.bad.${key}`,
          'prefs',
          key,
          'json',
          astJson,
          nowIso
        );

        assert.throws(
          () => cfg.defaults.get(`com.bad.${key}`, key),
          isTypedEinval,
          `defaults.get must throw typed OmniOSError(EINVAL) for ${key}`
        );
        assert.throws(
          () => cfg.defaults.readDomain(`com.bad.${key}`),
          isTypedEinval,
          `defaults.readDomain must throw typed OmniOSError(EINVAL) for ${key}`
        );
        assert.throws(
          () => cfg.defaults.exportPlistXml(`com.bad.${key}`),
          isTypedEinval,
          `defaults.exportPlistXml must throw typed OmniOSError(EINVAL) for ${key}`
        );
        assert.throws(
          () => cfg.sharedPrefs.get(`com.bad.${key}`, 'prefs', key),
          isTypedEinval,
          `sharedPrefs.get must throw typed OmniOSError(EINVAL) for ${key}`
        );
        assert.throws(
          () => cfg.sharedPrefs.getAll(`com.bad.${key}`, 'prefs'),
          isTypedEinval,
          `sharedPrefs.getAll must throw typed OmniOSError(EINVAL) for ${key}`
        );
      }

      // 2. Corrupt "{broken" in system_config throws typed OmniOSError(EINVAL) across get/getAll/set (never raw SyntaxError)
      storage.run(
        'INSERT INTO system_config (key_name, value_json, updated_at) VALUES (?, ?, ?)',
        'custom.corrupt',
        '{broken',
        nowIso
      );
      assert.throws(() => cfg.system.get('custom.corrupt'), isTypedEinval);
      assert.throws(() => cfg.system.getAll(), isTypedEinval);
      assert.throws(() => cfg.system.set('custom.corrupt', 'replacement'), isTypedEinval);

      // Corrupt canonical key in system_config also rejects cleanly on read & write
      storage.run(
        'UPDATE system_config SET value_json = ? WHERE key_name = ?',
        '{broken',
        'system.theme'
      );
      assert.throws(() => cfg.system.get('system.theme'), isTypedEinval);
      assert.throws(() => cfg.system.set('system.theme', 'light'), isTypedEinval);

      // 3. Corrupt REG_QWORD and REG_MULTI_SZ rows in registry_values throw typed OmniOSError(EINVAL)
      cfg.registry.createKey(REGISTRY_HIVES.HKCU, 'Software\\CorruptReg');
      storage.run(
        `INSERT INTO registry_values
          (hive, key_path_norm, value_name_norm, value_name_orig, value_type, data_text, data_blob, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        REGISTRY_HIVES.HKCU,
        'software\\corruptreg',
        'badqword',
        'BadQword',
        REGISTRY_TYPES.REG_QWORD,
        'not_a_bigint',
        null,
        nowIso
      );
      storage.run(
        `INSERT INTO registry_values
          (hive, key_path_norm, value_name_norm, value_name_orig, value_type, data_text, data_blob, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        REGISTRY_HIVES.HKCU,
        'software\\corruptreg',
        'emptyqword',
        'EmptyQword',
        REGISTRY_TYPES.REG_QWORD,
        '   ',
        null,
        nowIso
      );
      storage.run(
        `INSERT INTO registry_values
          (hive, key_path_norm, value_name_norm, value_name_orig, value_type, data_text, data_blob, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        REGISTRY_HIVES.HKCU,
        'software\\corruptreg',
        'badmultijson',
        'BadMultiJson',
        REGISTRY_TYPES.REG_MULTI_SZ,
        '{broken',
        null,
        nowIso
      );
      storage.run(
        `INSERT INTO registry_values
          (hive, key_path_norm, value_name_norm, value_name_orig, value_type, data_text, data_blob, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        REGISTRY_HIVES.HKCU,
        'software\\corruptreg',
        'badmultielem',
        'BadMultiElem',
        REGISTRY_TYPES.REG_MULTI_SZ,
        '[123,"ok"]',
        null,
        nowIso
      );

      assert.throws(
        () => cfg.registry.getValue(REGISTRY_HIVES.HKCU, 'Software\\CorruptReg', 'BadQword'),
        isTypedEinval
      );
      assert.throws(
        () => cfg.registry.getValue(REGISTRY_HIVES.HKCU, 'Software\\CorruptReg', 'EmptyQword'),
        isTypedEinval
      );
      assert.throws(
        () => cfg.registry.getValue(REGISTRY_HIVES.HKCU, 'Software\\CorruptReg', 'BadMultiJson'),
        isTypedEinval
      );
      assert.throws(
        () => cfg.registry.getValue(REGISTRY_HIVES.HKCU, 'Software\\CorruptReg', 'BadMultiElem'),
        isTypedEinval
      );
      assert.throws(
        () => cfg.registry.enumKey(REGISTRY_HIVES.HKCU, 'Software\\CorruptReg'),
        isTypedEinval
      );
    } finally {
      cfg.close();
      storage.close();
    }
  });

  it('19.3 (K3 + Obs-1 + Obs-2): Revoked processManager in ProcFsMount/VFS, registerConfigSyscalls validation & revoked eventBus across M2A', () => {
    const revObj = makeRevokedObj();

    // 1. Construction-time rejection of revoked processManager (direct and via kernel.processManager)
    assert.throws(
      () => new ProcFsMount({ processManager: revObj }),
      (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
    );
    assert.throws(
      () => new ProcFsMount({ kernel: { processManager: revObj } }),
      (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
    );
    assert.throws(
      () => new VirtualMountManager({ processManager: revObj }),
      (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
    );
    assert.throws(
      () => new VFS({ processManager: revObj }),
      (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
    );
    assert.throws(
      () => new VFS({ kernel: { processManager: revObj } }),
      (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
    );

    // 2. Post-construction revoked processManager in ProcFsMount & VFS
    const storage = new SqliteStorage(':memory:');
    const pmReal = new ProcessManager();
    const pcb = pmReal.spawn({ name: 'k3-proc', platform: 'universal', uid: 0, gid: 0 });
    const pmPair = Proxy.revocable(pmReal, {});
    const procFs = new ProcFsMount({ processManager: pmPair.proxy });
    const vfs = new VFS({ storage, processManager: pmPair.proxy });

    try {
      vfs.writeFile('/k3-open.txt', 'hello-k3', { uid: 0, gid: 0 });
      const handle = vfs.open('/k3-open.txt', OPEN_FLAGS.O_RDWR, { pid: pcb.pid, uid: 0, gid: 0 });

      // Revoke processManager AFTER construction & open handle creation
      pmPair.revoke();

      // ProcFsMount falls back cleanly to zeroed/static telemetry
      const memEntry = procFs.lookupChild(procFs.getRootNode(), 'meminfo');
      assert.ok(memEntry !== null && memEntry.node);
      const memInfoText = new TextDecoder().decode(procFs.readNode(memEntry.node));
      assert.ok(memInfoText.includes('MappedPages:\t0'));
      assert.ok(memInfoText.includes('TotalProcesses:\t0'));

      const procChildren = procFs.listChildren(procFs.getRootNode()).map((c) => c.name);
      assert.ok(procChildren.includes('meminfo'));
      assert.ok(procChildren.includes('uptime'));
      assert.ok(procChildren.includes('version'));

      // VFS /proc reads fall back cleanly
      const vfsMeminfo = vfs.readFile('/proc/meminfo', { encoding: 'utf8' });
      assert.ok(vfsMeminfo.includes('TotalProcesses:\t0'));
      const vfsProcDir = vfs.readdir('/proc').map((e) => e.name);
      assert.ok(vfsProcDir.includes('meminfo'));
      assert.ok(vfsProcDir.includes('uptime'));

      // Process-bound VFS operations reject with typed VfsError(EINVAL) (never raw TypeError)
      assert.throws(
        () => vfs.stat('/', { pid: pcb.pid }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => vfs.open('/k3-open.txt', OPEN_FLAGS.O_RDONLY, { pid: pcb.pid }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
      );

      // Already-open handle continues reading/seeking and closes cleanly without raw TypeError
      const readChunk = handle.read(8, 0);
      assert.equal(new TextDecoder().decode(readChunk), 'hello-k3');
      assert.equal(handle.seek(0, SEEK_WHENCE.SEEK_SET), 0);
      handle.close();
      assert.equal(handle.closed, true);

      // 3. Obs-1: registerConfigSyscalls rejects revoked syscalls & configStore + guards post-reg revocation
      const cfgReal = new UnifiedConfigStore({ storage });
      const syscallsReal = new SyscallDispatcher();
      assert.throws(() => registerConfigSyscalls(revObj, cfgReal), isTypedEinval);
      assert.throws(() => registerConfigSyscalls(syscallsReal, revObj), isTypedEinval);

      const cfgPair = Proxy.revocable(cfgReal, {});
      registerConfigSyscalls(syscallsReal, cfgPair.proxy);
      assert.equal(syscallsReal.dispatch('config.get', {}, 'system.theme'), 'dark');
      cfgPair.revoke();
      assert.throws(
        () => syscallsReal.dispatch('config.get', {}, 'system.theme'),
        isTypedEinval
      );

      // 4. Obs-2: Revoked eventBus across UserManager, PermissionBroker, VFS & UnifiedConfigStore
      assert.throws(
        () => new UserManager({ storage, eventBus: revObj }),
        (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => new PermissionBroker({ storage, eventBus: revObj }),
        (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => new VFS({ storage, eventBus: revObj }),
        (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL
      );
      assert.throws(
        () => new UnifiedConfigStore({ storage, eventBus: revObj }),
        isTypedEinval
      );

      const evUsers = Proxy.revocable(new KernelEventBus(), {});
      const evPerms = Proxy.revocable(new KernelEventBus(), {});
      const evVfs = Proxy.revocable(new KernelEventBus(), {});
      const evCfg = Proxy.revocable(new KernelEventBus(), {});

      const usersEv = new UserManager({ storage, eventBus: evUsers.proxy });
      const permsEv = new PermissionBroker({ storage, userManager: usersEv, eventBus: evPerms.proxy });
      const vfsEv = new VFS({ storage, userManager: usersEv, eventBus: evVfs.proxy });
      const cfgEv = new UnifiedConfigStore({ storage, eventBus: evCfg.proxy });

      evUsers.revoke();
      evPerms.revoke();
      evVfs.revoke();
      evCfg.revoke();

      // Mutations must commit cleanly to SQLite with zero raw TypeError
      const appUser = usersEv.allocateAppUid('com.obs2.app', { platform: 'universal' });
      assert.equal(usersEv.getUserByAppId('com.obs2.app')?.uid, appUser.uid);

      permsEv.setGrant('com.obs2.app', CAPABILITIES.CAMERA_DEVICE, PERMISSION_STATES.ALLOW);
      assert.equal(permsEv.getGrant('com.obs2.app', CAPABILITIES.CAMERA_DEVICE)?.state, PERMISSION_STATES.ALLOW);

      vfsEv.writeFile('/obs2-ev.txt', 'committed', { uid: 0, gid: 0 });
      assert.equal(vfsEv.readFile('/obs2-ev.txt', { encoding: 'utf8', uid: 0, gid: 0 }), 'committed');

      cfgEv.system.set('system.theme', 'light');
      assert.equal(cfgEv.system.get('system.theme'), 'light');

      cfgReal.close();
      cfgEv.close();
      vfsEv.close();
      permsEv.close();
      usersEv.close();
    } finally {
      vfs.close();
      storage.close();
    }
  });

  it('19.4 (L1): PackageManager.install() rejects symlinked default/parent dirs strictly BEFORE UID allocation, _vfsExtractPackage() & runtime.installPackage()', async () => {
    const ipa = createZip({ 'Payload/E.app/Info.plist': '<plist/>' });

    // Vector A: Pre-planted /var/appdata/ios/<appId> -> /etc with default dataDir
    {
      const storage = new SqliteStorage(':memory:');
      const users = new UserManager({ storage });
      const vfs = new VFS({ storage, userManager: users });
      const pm = new PackageManager({ storage, vfs, users });
      try {
        vfs.mkdir('/etc', { recursive: true, uid: 0, gid: 0 });
        vfs.mkdir('/var/appdata/ios', { recursive: true, uid: 0, gid: 0 });
        vfs.symlink('/etc', '/var/appdata/ios/com.vec.a', { uid: 0, gid: 0 });
        let installPkgCalled = false;
        pm.registerRuntime('ios', {
          platform: 'ios',
          inspectPackage: () => ({ appId: 'com.vec.a', name: 'VecA', platform: 'ios', format: 'ios-ipa' }),
          installPackage: () => {
            installPkgCalled = true;
            return {};
          },
          createExecutionContext: () => makeWorkExecContext({ totalWork: 1 }),
        });

        await assert.rejects(
          () => pm.install(ipa),
          (err) => err instanceof SecurityError && err.code === ERROR_CODES.E_PATH_TRAVERSAL
        );
        assert.equal(installPkgCalled, false, 'Vector A must reject before runtime.installPackage()');
        assert.equal(vfs.stat('/etc', { uid: 0, gid: 0 }).uid, 0, '/etc must retain uid 0');
        assert.equal(users.getUserByAppId('com.vec.a'), null, 'Vector A must allocate zero UIDs');
        assert.equal(pm.get('com.vec.a'), null);
      } finally {
        pm.close();
        storage.close();
      }
    }

    // Vector B: Pre-planted /var/appdata/ios/<appId> -> /etc with valid custom iOS UUID dataDir
    {
      const storage = new SqliteStorage(':memory:');
      const users = new UserManager({ storage });
      const vfs = new VFS({ storage, userManager: users });
      const pm = new PackageManager({ storage, vfs, users });
      try {
        vfs.mkdir('/etc', { recursive: true, uid: 0, gid: 0 });
        vfs.mkdir('/var/appdata/ios', { recursive: true, uid: 0, gid: 0 });
        vfs.symlink('/etc', '/var/appdata/ios/com.vec.b', { uid: 0, gid: 0 });
        let installPkgCalled = false;
        pm.registerRuntime('ios', {
          platform: 'ios',
          inspectPackage: () => ({ appId: 'com.vec.b', name: 'VecB', platform: 'ios', format: 'ios-ipa' }),
          installPackage: () => {
            installPkgCalled = true;
            return { dataDir: '/var/appdata/ios/containers/550e8400-e29b-41d4-a716-446655440000' };
          },
          createExecutionContext: () => makeWorkExecContext({ totalWork: 1 }),
        });

        await assert.rejects(
          () => pm.install(ipa),
          (err) => err instanceof SecurityError && err.code === ERROR_CODES.E_PATH_TRAVERSAL
        );
        assert.equal(installPkgCalled, false, 'Vector B must reject strictly before _vfsExtractPackage() & installPackage()');
        assert.equal(vfs.stat('/etc', { uid: 0, gid: 0 }).uid, 0, '/etc must retain uid 0');
        assert.equal(users.getUserByAppId('com.vec.b'), null, 'Vector B must allocate zero UIDs');
        assert.equal(pm.get('com.vec.b'), null, 'Vector B must NOT install package');
      } finally {
        pm.close();
        storage.close();
      }
    }

    // Vector C: Pre-planted parent /apps/ios -> /etc with /etc/conf.d/secret.cfg
    {
      const storage = new SqliteStorage(':memory:');
      const users = new UserManager({ storage });
      const vfs = new VFS({ storage, userManager: users });
      const pm = new PackageManager({ storage, vfs, users });
      try {
        vfs.mkdir('/etc/conf.d', { recursive: true, uid: 0, gid: 0 });
        vfs.writeFile('/etc/conf.d/secret.cfg', 'SECRET_KEEP', { uid: 0, gid: 0 });
        vfs.rmdir('/apps/ios', { uid: 0, gid: 0 });
        vfs.symlink('/etc', '/apps/ios', { uid: 0, gid: 0 });
        let installPkgCalled = false;
        pm.registerRuntime('ios', {
          platform: 'ios',
          inspectPackage: () => ({ appId: 'conf.d', name: 'VecC', platform: 'ios', format: 'ios-ipa' }),
          installPackage: () => {
            installPkgCalled = true;
            return {};
          },
          createExecutionContext: () => makeWorkExecContext({ totalWork: 1 }),
        });

        await assert.rejects(
          () => pm.install(ipa),
          (err) => err instanceof SecurityError && err.code === ERROR_CODES.E_PATH_TRAVERSAL
        );
        assert.equal(installPkgCalled, false, 'Vector C must NEVER invoke runtime.installPackage()');
        assert.equal(vfs.readFile('/etc/conf.d/secret.cfg', { encoding: 'utf8', uid: 0, gid: 0 }), 'SECRET_KEEP');
        assert.deepEqual(
          vfs.readdir('/etc/conf.d', { uid: 0, gid: 0 }).map((e) => e.name),
          ['secret.cfg']
        );
        assert.equal(users.getUserByAppId('conf.d'), null);
      } finally {
        pm.close();
        storage.close();
      }
    }

    // Exploit 1B: Pre-planted /apps/ios/<appId> -> /etc rejects with symlink untouched
    {
      const storage = new SqliteStorage(':memory:');
      const users = new UserManager({ storage });
      const vfs = new VFS({ storage, userManager: users });
      const pm = new PackageManager({ storage, vfs, users });
      try {
        vfs.mkdir('/etc', { recursive: true, uid: 0, gid: 0 });
        vfs.mkdir('/apps/ios', { recursive: true, uid: 0, gid: 0 });
        vfs.symlink('/etc', '/apps/ios/com.inst.sym', { uid: 0, gid: 0 });
        pm.registerRuntime('ios', {
          platform: 'ios',
          inspectPackage: () => ({ appId: 'com.inst.sym', name: 'InstSym', platform: 'ios', format: 'ios-ipa' }),
          installPackage: () => ({}),
          createExecutionContext: () => makeWorkExecContext({ totalWork: 1 }),
        });

        await assert.rejects(
          () => pm.install(ipa),
          (err) => err instanceof SecurityError && err.code === ERROR_CODES.E_PATH_TRAVERSAL
        );
        assert.equal(vfs.lstat('/apps/ios/com.inst.sym', { uid: 0, gid: 0 }).type, 'symlink');
        assert.equal(vfs.stat('/etc', { uid: 0, gid: 0 }).uid, 0);
        assert.equal(users.getUserByAppId('com.inst.sym'), null);
      } finally {
        pm.close();
        storage.close();
      }
    }

    // Parent /var/appdata/ios -> /etc rejects cleanly with /etc untouched
    {
      const storage = new SqliteStorage(':memory:');
      const users = new UserManager({ storage });
      const vfs = new VFS({ storage, userManager: users });
      const pm = new PackageManager({ storage, vfs, users });
      try {
        vfs.mkdir('/etc', { recursive: true, uid: 0, gid: 0 });
        vfs.rmdir('/var/appdata/ios', { uid: 0, gid: 0 });
        vfs.symlink('/etc', '/var/appdata/ios', { uid: 0, gid: 0 });
        pm.registerRuntime('ios', {
          platform: 'ios',
          inspectPackage: () => ({ appId: 'com.parent.data', name: 'ParData', platform: 'ios', format: 'ios-ipa' }),
          installPackage: () => ({}),
          createExecutionContext: () => makeWorkExecContext({ totalWork: 1 }),
        });

        await assert.rejects(
          () => pm.install(ipa),
          (err) => err instanceof SecurityError && err.code === ERROR_CODES.E_PATH_TRAVERSAL
        );
        assert.equal(vfs.stat('/etc', { uid: 0, gid: 0 }).uid, 0);
        assert.equal(users.getUserByAppId('com.parent.data'), null);
        assert.throws(
          () => vfs.stat('/etc/com.parent.data', { uid: 0, gid: 0 }),
          (err) => err instanceof VfsError && err.code === ERROR_CODES.ENOENT
        );
      } finally {
        pm.close();
        storage.close();
      }
    }

    // Legitimate custom iOS UUID container installs, allows app UID writes, and uninstalls cleanly
    {
      const storage = new SqliteStorage(':memory:');
      const users = new UserManager({ storage });
      const vfs = new VFS({ storage, userManager: users });
      const pm = new PackageManager({ storage, vfs, users });
      const uuidDir = '/var/appdata/ios/containers/550e8400-e29b-41d4-a716-446655440000';
      try {
        pm.registerRuntime('ios', {
          platform: 'ios',
          inspectPackage: () => ({ appId: 'com.ios.legit', name: 'LegitUUID', platform: 'ios', format: 'ios-ipa' }),
          installPackage: () => ({ dataDir: uuidDir }),
          createExecutionContext: () => makeWorkExecContext({ totalWork: 1 }),
        });

        const rec = await pm.install(ipa);
        assert.equal(rec.dataDir, uuidDir);
        assert.ok(rec.uid >= SANDBOX_UID_BASE);

        vfs.writeFile(`${uuidDir}/state.json`, '{"ok":true}', { uid: rec.uid, gid: rec.gid });
        assert.equal(
          vfs.readFile(`${uuidDir}/state.json`, { encoding: 'utf8', uid: rec.uid, gid: rec.gid }),
          '{"ok":true}'
        );

        const un = await pm.uninstall('com.ios.legit', { purgeData: true });
        assert.equal(un.removed, true);
        assert.equal(pm.get('com.ios.legit'), null);
        assert.throws(
          () => vfs.stat(uuidDir, { uid: 0, gid: 0 }),
          (err) => err instanceof VfsError && err.code === ERROR_CODES.ENOENT
        );
      } finally {
        pm.close();
        storage.close();
      }
    }
  });

  it('19.5 (L2): Post-construction revoked dependencies in PackageManager, Compositor._deliverToProcess() & M2B eventBus guards', async () => {
    const uapp = createZip({ 'omnios.manifest.json': '{"appId":"com.l2.app"}' });

    // 1. PackageManager.init() with post-construction revoked intentRouter hydrates cleanly (zero raw TypeError)
    {
      const storage = new SqliteStorage(':memory:');
      const irPair = Proxy.revocable({ registerHandlers: () => {}, unregisterApp: () => {} }, {});
      const pm = new PackageManager({ storage, intentRouter: irPair.proxy });
      try {
        pm.registerRuntime('universal', {
          platform: 'universal',
          inspectPackage: () => ({
            appId: 'com.l2.init',
            name: 'L2Init',
            platform: 'universal',
            format: 'universal-uapp',
            intents: [{ action: 'view', extension: '.l2' }],
          }),
          installPackage: () => ({}),
          createExecutionContext: () => makeWorkExecContext({ totalWork: 1 }),
        });
        pm.registerCatalogEntry({
          appId: 'com.l2.cat',
          name: 'L2Cat',
          platform: 'universal',
          format: 'universal-uapp',
        });
        await pm.install(uapp);
        irPair.revoke();

        pm.init(storage);
        assert.equal(pm.isReady(), true);
        assert.equal(pm.get('com.l2.init')?.appId, 'com.l2.init');
        assert.equal(pm.getCatalog().some((c) => c.appId === 'com.l2.cat'), true);
      } finally {
        pm.close();
        storage.close();
      }
    }

    // 2. PackageManager.uninstall({ purgeData: true }) with revoked permissions & intentRouter leaves ZERO ghost state
    {
      const storage = new SqliteStorage(':memory:');
      const users = new UserManager({ storage });
      const vfs = new VFS({ storage, userManager: users });
      const permPair = Proxy.revocable({ listGrants: () => [], setGrant: () => {}, revokeAllGrants: () => {} }, {});
      const irPair = Proxy.revocable({ registerHandlers: () => {}, unregisterApp: () => {} }, {});
      const pm = new PackageManager({
        storage,
        vfs,
        users,
        permissions: permPair.proxy,
        intentRouter: irPair.proxy,
      });
      try {
        pm.registerRuntime('universal', {
          platform: 'universal',
          inspectPackage: () => ({
            appId: 'com.l2.ghost',
            name: 'NoGhost',
            platform: 'universal',
            format: 'universal-uapp',
            intents: [{ action: 'open', extension: '.ng' }],
          }),
          installPackage: () => ({}),
          createExecutionContext: () => makeWorkExecContext({ totalWork: 1 }),
        });
        const rec = await pm.install(uapp);
        assert.equal(vfs.stat(rec.installDir, { uid: 0, gid: 0 }).type, 'dir');

        permPair.revoke();
        irPair.revoke();

        const summary = await pm.uninstall('com.l2.ghost', { purgeData: true });
        assert.equal(summary.removed, true);
        assert.equal(summary.purgedData, true);
        assert.equal(pm.get('com.l2.ghost'), null, 'Cache must have zero ghost entry');
        assert.equal(
          storage.get('SELECT app_id FROM installed_packages WHERE app_id = ?', 'com.l2.ghost'),
          null,
          'SQLite installed_packages row must be deleted'
        );
        assert.throws(
          () => vfs.stat(rec.installDir, { uid: 0, gid: 0 }),
          (err) => err instanceof VfsError && err.code === ERROR_CODES.ENOENT
        );
        assert.throws(
          () => vfs.stat(rec.dataDir, { uid: 0, gid: 0 }),
          (err) => err instanceof VfsError && err.code === ERROR_CODES.ENOENT
        );
      } finally {
        pm.close();
        storage.close();
      }
    }

    // 3. PackageManager.{inspect,install,launch,stop} with post-construction revoked deps -> typed OmniOSError(EINVAL)
    {
      const storage = new SqliteStorage(':memory:');
      try {
        // 3a. Revoked detector in inspect()
        const detPair = Proxy.revocable(new FormatDetector(), {});
        const pmDet = new PackageManager({ storage, detector: detPair.proxy });
        detPair.revoke();
        await assert.rejects(() => pmDet.inspect(uapp), isTypedEinval);
        pmDet.close();

        // 3b. Revoked users in install()
        const usersPair = Proxy.revocable(new UserManager({ storage }), {});
        const pmUsers = new PackageManager({ storage, users: usersPair.proxy });
        pmUsers.registerRuntime('universal', {
          platform: 'universal',
          inspectPackage: () => ({ appId: 'com.l2.u', name: 'U', platform: 'universal', format: 'universal-uapp' }),
          installPackage: () => ({}),
          createExecutionContext: () => makeWorkExecContext({ totalWork: 1 }),
        });
        usersPair.revoke();
        await assert.rejects(() => pmUsers.install(uapp), isTypedEinval);
        assert.equal(pmUsers.get('com.l2.u'), null);
        pmUsers.close();

        // 3c. Revoked permissions in install() rolls back atomically with OmniOSError(EINVAL)
        const permsPair = Proxy.revocable(new PermissionBroker({ storage }), {});
        const pmPerms = new PackageManager({ storage, permissions: permsPair.proxy });
        pmPerms.registerRuntime('universal', {
          platform: 'universal',
          inspectPackage: () => ({ appId: 'com.l2.p', name: 'P', platform: 'universal', format: 'universal-uapp' }),
          installPackage: () => ({}),
          createExecutionContext: () => makeWorkExecContext({ totalWork: 1 }),
        });
        permsPair.revoke();
        await assert.rejects(
          () => pmPerms.install(uapp, { grants: { [CAPABILITIES.CAMERA_DEVICE]: PERMISSION_STATES.ALLOW } }),
          isTypedEinval
        );
        assert.equal(pmPerms.get('com.l2.p'), null);
        pmPerms.close();

        // 3d. Revoked intentRouter in install() rolls back atomically with OmniOSError(EINVAL)
        const irPair = Proxy.revocable(new IntentRouter(), {});
        const pmIr = new PackageManager({ storage, intentRouter: irPair.proxy });
        pmIr.registerRuntime('universal', {
          platform: 'universal',
          inspectPackage: () => ({
            appId: 'com.l2.ir',
            name: 'IR',
            platform: 'universal',
            format: 'universal-uapp',
            intents: [{ action: 'view', extension: '.ir' }],
          }),
          installPackage: () => ({}),
          createExecutionContext: () => makeWorkExecContext({ totalWork: 1 }),
        });
        irPair.revoke();
        await assert.rejects(() => pmIr.install(uapp), isTypedEinval);
        assert.equal(pmIr.get('com.l2.ir'), null);
        pmIr.close();

        // 3e. Revoked processManager in launch() and stop()
        const procPair = Proxy.revocable(new ProcessManager(), {});
        const pmProc = new PackageManager({ storage, processManager: procPair.proxy });
        pmProc.registerRuntime('universal', {
          platform: 'universal',
          inspectPackage: () => ({ appId: 'com.l2.run', name: 'Run', platform: 'universal', format: 'universal-uapp' }),
          installPackage: () => ({}),
          createExecutionContext: () => makeWorkExecContext({ totalWork: 10 }),
        });
        await pmProc.install(uapp);
        procPair.revoke();
        await assert.rejects(() => pmProc.launch('com.l2.run'), isTypedEinval);
        assert.throws(() => pmProc.stop('com.l2.run'), isTypedEinval);
        assert.throws(() => pmProc.stop(1), isTypedEinval);
        pmProc.close();
      } finally {
        storage.close();
      }
    }

    // 4. Compositor._deliverToProcess() survives processManager revoked inside execCtx.deliverEvent() on BLOCKED PCB
    {
      let revokePm = null;
      let deliverCalled = false;
      const pmPair = Proxy.revocable(
        {
          get: () => ({
            pid: 7,
            state: PROCESS_STATES.BLOCKED,
            threads: new Map(),
            windowIds: new Set(),
            executionContext: {
              deliverEvent: () => {
                deliverCalled = true;
                revokePm();
              },
            },
          }),
          registerWindow: () => {},
          unregisterWindow: () => {},
          addCleanupHook: () => {},
          wake: () => {},
        },
        {}
      );
      revokePm = pmPair.revoke;

      const comp = new Compositor({ processManager: pmPair.proxy });
      const win = comp.createWindow(7, { title: 'BlockedRevokeWin' });
      const delivery = comp.dispatchInput(win.windowId, { type: 'click', x: 12, y: 34 });
      assert.equal(deliverCalled, true);
      assert.equal(delivery.delivered, true);
      assert.equal(delivery.windowId, win.windowId);
    }

    // 5. Post-construction revoked eventBus across all 6 M2B classes never leaks raw TypeError
    {
      const storage = new SqliteStorage(':memory:');
      const evIpc = Proxy.revocable(new KernelEventBus(), {});
      const evRouter = Proxy.revocable(new KernelEventBus(), {});
      const evClip = Proxy.revocable(new KernelEventBus(), {});
      const evNotif = Proxy.revocable(new KernelEventBus(), {});
      const evComp = Proxy.revocable(new KernelEventBus(), {});
      const evPkg = Proxy.revocable(new KernelEventBus(), {});

      const compPm = new ProcessManager();
      const compPcb = compPm.spawn({ name: 'ev-comp', platform: 'universal', uid: 0, gid: 0 });
      const ipc = new IPCManager({ eventBus: evIpc.proxy });
      const router = new IntentRouter({ eventBus: evRouter.proxy });
      const clip = new SharedClipboard({ eventBus: evClip.proxy });
      const notif = new NotificationCenter({ eventBus: evNotif.proxy });
      const comp = new Compositor({ processManager: compPm, eventBus: evComp.proxy });
      const pm = new PackageManager({ storage, eventBus: evPkg.proxy });

      try {
        evIpc.revoke();
        evRouter.revoke();
        evClip.revoke();
        evNotif.revoke();
        evComp.revoke();
        evPkg.revoke();

        const ch = ipc.createChannel('l2.ev.ch');
        ipc.send(ch.name, 1, { ok: true });
        assert.equal(ipc.recv(ch.name).payload.ok, true);

        router.registerHandlers('com.l2.ev', [{ action: 'view', extension: '.ev' }]);
        const dispatched = await router.dispatch({ action: 'view', uri: '/a.ev' });
        assert.equal(dispatched.status, 'DELIVERED');

        clip.set({ text: 'ev-safe' });
        assert.equal(clip.get().text, 'ev-safe');

        const n = notif.post({ appId: 'com.l2.ev', title: 'Hi', body: 'World' });
        assert.equal(notif.get(n.id)?.title, 'Hi');

        const w = comp.createWindow(compPcb.pid, { title: 'EvWin' });
        comp.focusWindow(w.windowId);
        assert.equal(comp.getWindow(w.windowId)?.title, 'EvWin');

        pm.registerRuntime('universal', {
          platform: 'universal',
          inspectPackage: () => ({ appId: 'com.l2.evpkg', name: 'EvPkg', platform: 'universal', format: 'universal-uapp' }),
          installPackage: () => ({}),
          createExecutionContext: () => makeWorkExecContext({ totalWork: 1 }),
        });
        const rec = await pm.install(uapp);
        assert.equal(pm.get(rec.appId)?.appId, 'com.l2.evpkg');
      } finally {
        pm.close();
        storage.close();
      }
    }
  });
});

// ============================================================================
// SUITE 20: Iteration 8 Final M2A Surgical Defect Regressions (M1–M3, Obs-A/B)
// ============================================================================

describe('Suite 20: Iteration 8 Final M2A Surgical Defect Regressions (M1–M3, Obs-A/B)', () => {
  function makeRevokedObj() {
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    return proxy;
  }

  function isTypedEinval(err) {
    return (
      err instanceof OmniOSError &&
      err.code === ERROR_CODES.EINVAL &&
      !(err instanceof TypeError) &&
      !(err instanceof SyntaxError) &&
      !(err instanceof RangeError)
    );
  }

  function makeDag25() {
    let d = { v: 1 };
    for (let i = 0; i < 25; i += 1) {
      d = [d, d];
    }
    return d;
  }

  function makeDeepObj(depth) {
    let o = { leaf: 1 };
    for (let i = 0; i < depth; i += 1) {
      o = { next: o };
    }
    return o;
  }

  it('20.1 (M1 + Obs-B): _systemSet() single-pass AST serialization blocks toJSON/TOCTOU/binary/BigInt bypasses & REG_QWORD enforces uint64 bounds', () => {
    const storage = new SqliteStorage(':memory:');
    const cfg = new UnifiedConfigStore({ storage });

    try {
      let toJsonCalls = 0;

      // (a) Non-enumerable .toJSON() returning 26-object DAG, depth-500 object & 100k-element array -> persists {} cleanly
      const nonEnumDag = {};
      Object.defineProperty(nonEnumDag, 'toJSON', {
        enumerable: false,
        value() {
          toJsonCalls += 1;
          return makeDag25();
        },
      });
      const nonEnumDeep = {};
      Object.defineProperty(nonEnumDeep, 'toJSON', {
        enumerable: false,
        value() {
          toJsonCalls += 1;
          return makeDeepObj(500);
        },
      });
      const nonEnumWide = {};
      Object.defineProperty(nonEnumWide, 'toJSON', {
        enumerable: false,
        value() {
          toJsonCalls += 1;
          return new Array(100_000).fill(1);
        },
      });

      const t0 = performance.now();
      assert.deepEqual(cfg.system.set('custom.m1.nonEnumDag', nonEnumDag), {});
      assert.deepEqual(cfg.system.set('custom.m1.nonEnumDeep', nonEnumDeep), {});
      assert.deepEqual(cfg.system.set('custom.m1.nonEnumWide', nonEnumWide), {});

      assert.deepEqual(cfg.system.get('custom.m1.nonEnumDag'), {});
      assert.deepEqual(cfg.system.get('custom.m1.nonEnumDeep'), {});
      assert.deepEqual(cfg.system.get('custom.m1.nonEnumWide'), {});
      assert.equal(
        storage.get('SELECT value_json FROM system_config WHERE key_name = ?', 'custom.m1.nonEnumDag')?.value_json,
        '{}'
      );
      assert.equal(
        storage.get('SELECT value_json FROM system_config WHERE key_name = ?', 'custom.m1.nonEnumDeep')?.value_json,
        '{}'
      );
      assert.equal(
        storage.get('SELECT value_json FROM system_config WHERE key_name = ?', 'custom.m1.nonEnumWide')?.value_json,
        '{}'
      );

      // (b) Prototype-inherited .toJSON() returning 26-object DAG & depth-500 -> persists {} cleanly
      const protoDag = Object.create({
        toJSON() {
          toJsonCalls += 1;
          return makeDag25();
        },
      });
      const protoDeep = Object.create({
        toJSON() {
          toJsonCalls += 1;
          return makeDeepObj(500);
        },
      });

      assert.deepEqual(cfg.system.set('custom.m1.protoDag', protoDag), {});
      assert.deepEqual(cfg.system.set('custom.m1.protoDeep', protoDeep), {});
      assert.deepEqual(cfg.system.get('custom.m1.protoDag'), {});
      assert.deepEqual(cfg.system.get('custom.m1.protoDeep'), {});
      assert.equal(
        storage.get('SELECT value_json FROM system_config WHERE key_name = ?', 'custom.m1.protoDag')?.value_json,
        '{}'
      );
      assert.equal(
        storage.get('SELECT value_json FROM system_config WHERE key_name = ?', 'custom.m1.protoDeep')?.value_json,
        '{}'
      );
      assert.equal(toJsonCalls, 0, '_systemSet() must never invoke user-defined toJSON() hooks');

      // (c) TOCTOU second-read getter returning 1 on read #1 and 26-object DAG on read #2 -> single-pass persists { x: 1 }
      let getterReads = 0;
      const toctou = {
        get x() {
          getterReads += 1;
          return getterReads === 1 ? 1 : makeDag25();
        },
      };
      const toctouRes = cfg.system.set('custom.m1.toctou', toctou);
      assert.equal(getterReads, 1, 'TOCTOU getter must only be evaluated once during single-pass AST encoding');
      assert.deepEqual(toctouRes, { x: 1 });
      assert.deepEqual(cfg.system.get('custom.m1.toctou'), { x: 1 });

      // (d) Genuine Uint8Array(5_000_000), ArrayBuffer(5_000_000) & BigInt (1n) reject instantaneously with OmniOSError(EINVAL)
      const tBin0 = performance.now();
      assert.throws(() => cfg.system.set('custom.m1.u8', new Uint8Array(5_000_000)), isTypedEinval);
      assert.throws(() => cfg.system.set('custom.m1.u8Nested', { data: new Uint8Array(5_000_000) }), isTypedEinval);
      assert.throws(() => cfg.system.set('custom.m1.ab', new ArrayBuffer(5_000_000)), isTypedEinval);
      assert.throws(() => cfg.system.set('custom.m1.bigint', 1n), isTypedEinval);
      assert.throws(() => cfg.system.set('custom.m1.bigintNested', { n: 1n }), isTypedEinval);
      const binRejectMs = performance.now() - tBin0;
      assert.ok(binRejectMs < 500, `Binary/BigInt system.set rejections must be O(1) (<500ms), got ${binRejectMs.toFixed(1)}ms`);

      assert.equal(cfg.system.get('custom.m1.u8'), null);
      assert.equal(cfg.system.get('custom.m1.u8Nested'), null);
      assert.equal(cfg.system.get('custom.m1.ab'), null);
      assert.equal(cfg.system.get('custom.m1.bigint'), null);
      assert.equal(cfg.system.get('custom.m1.bigintNested'), null);

      const totalM1Ms = performance.now() - t0;
      assert.ok(totalM1Ms < 1000, `M1 _systemSet checks must complete quickly (<1000ms), got ${totalM1Ms.toFixed(1)}ms`);

      // (e) Genuine Date, special reals (NaN/Infinity/-Infinity -> null, -0 -> 0) & own '__proto__' key round-trip cleanly
      const dt = new Date('2026-11-21T07:25:34.123Z');
      assert.equal(cfg.system.set('custom.m1.date', dt), '2026-11-21T07:25:34.123Z');
      assert.equal(cfg.system.get('custom.m1.date'), '2026-11-21T07:25:34.123Z');

      const realsRes = cfg.system.set('custom.m1.reals', {
        nan: NaN,
        posInf: Infinity,
        negInf: -Infinity,
        negZero: -0,
        finite: 3.25,
      });
      assert.deepEqual(realsRes, { nan: null, posInf: null, negInf: null, negZero: 0, finite: 3.25 });
      const realsRead = cfg.system.get('custom.m1.reals');
      assert.deepEqual(realsRead, { nan: null, posInf: null, negInf: null, negZero: 0, finite: 3.25 });
      assert.equal(Object.is(realsRead.negZero, 0), true);

      const protoPayload = JSON.parse('{"__proto__":{"polluted":"m1_sentinel"},"safe":42}');
      const protoSetRes = cfg.system.set('custom.m1.protoKey', protoPayload);
      const protoGetRes = cfg.system.get('custom.m1.protoKey');
      assert.equal(({}).polluted, undefined, 'Object.prototype must not be polluted');
      assert.equal(protoGetRes.polluted, undefined, 'Own __proto__ key must not modify object prototype');
      assert.equal(Object.prototype.hasOwnProperty.call(protoSetRes, '__proto__'), true);
      assert.equal(Object.prototype.hasOwnProperty.call(protoGetRes, '__proto__'), true);
      assert.deepEqual(protoGetRes['__proto__'], { polluted: 'm1_sentinel' });
      assert.equal(protoGetRes.safe, 42);

      // Obs-B: Tampered SQLite REG_QWORD negative & > uint64 overflow reject with OmniOSError(EINVAL),
      // while exact boundaries "0" and "18446744073709551615" deserialize accurately as 0n and 18446744073709551615n
      const nowIso = new Date().toISOString();
      cfg.registry.createKey(REGISTRY_HIVES.HKCU, 'Software\\QwordValid');
      cfg.registry.createKey(REGISTRY_HIVES.HKCU, 'Software\\QwordTampered');

      const insertQword = (keyPathNorm, nameNorm, nameOrig, rawText) => {
        storage.run(
          `INSERT INTO registry_values
            (hive, key_path_norm, value_name_norm, value_name_orig, value_type, data_text, data_blob, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          REGISTRY_HIVES.HKCU,
          keyPathNorm,
          nameNorm,
          nameOrig,
          REGISTRY_TYPES.REG_QWORD,
          rawText,
          null,
          nowIso
        );
      };

      insertQword('software\\qwordvalid', 'zero', 'Zero', '0');
      insertQword('software\\qwordvalid', 'max', 'Max', '18446744073709551615');
      insertQword('software\\qwordtampered', 'neg', 'Neg', '-1');
      insertQword('software\\qwordtampered', 'overflow', 'Overflow', '18446744073709551616');

      assert.equal(cfg.registry.getValue(REGISTRY_HIVES.HKCU, 'Software\\QwordValid', 'Zero')?.data, 0n);
      assert.equal(
        cfg.registry.getValue(REGISTRY_HIVES.HKCU, 'Software\\QwordValid', 'Max')?.data,
        18446744073709551615n
      );
      const validEnum = cfg.registry.enumKey(REGISTRY_HIVES.HKCU, 'Software\\QwordValid');
      assert.equal(validEnum.values.Zero?.data, 0n);
      assert.equal(validEnum.values.Max?.data, 18446744073709551615n);

      assert.throws(
        () => cfg.registry.getValue(REGISTRY_HIVES.HKCU, 'Software\\QwordTampered', 'Neg'),
        isTypedEinval
      );
      assert.throws(
        () => cfg.registry.getValue(REGISTRY_HIVES.HKCU, 'Software\\QwordTampered', 'Overflow'),
        isTypedEinval
      );
      assert.throws(
        () => cfg.registry.enumKey(REGISTRY_HIVES.HKCU, 'Software\\QwordTampered'),
        isTypedEinval
      );
    } finally {
      cfg.close();
      storage.close();
    }
  });

  it('20.2 (M2): PermissionBroker.safeJsonClone enforces shared node budget on 8-object DAGs, deterministic [Circular] preservation & O(1) binary preview cap', async () => {
    const storage = new SqliteStorage(':memory:');
    const pb = new PermissionBroker({ storage });

    function makeArrDag(levels, branch) {
      let node = { v: 1 };
      for (let i = 0; i < levels; i += 1) {
        node = new Array(branch).fill(node);
      }
      return node;
    }

    function makeObjDag(levels, branch) {
      let node = { v: 1 };
      for (let i = 0; i < levels; i += 1) {
        const next = {};
        for (let k = 0; k < branch; k += 1) {
          next[`k${k}`] = node;
        }
        node = next;
      }
      return node;
    }

    try {
      // (a) 8-object branching-10 AND branching-16 array & object DAGs (depth 7 < 8) -> bounded audit JSON with '[Truncated]', zero OOM
      const dagCases = [
        { id: 'com.m2.arr10', ctx: makeArrDag(7, 10) },
        { id: 'com.m2.arr16', ctx: makeArrDag(7, 16) },
        { id: 'com.m2.obj10', ctx: makeObjDag(7, 10) },
        { id: 'com.m2.obj16', ctx: makeObjDag(7, 16) },
      ];

      const tDag0 = performance.now();
      for (const tc of dagCases) {
        const res = await pb.checkPermission({
          appId: tc.id,
          capability: CAPABILITIES.NETWORK_OUTBOUND,
          context: tc.ctx,
        });
        assert.equal(typeof res.granted, 'boolean');
        const rows = pb.getAuditLog({ appId: tc.id, limit: 5 });
        assert.equal(rows.length, 1);
        const serialized = JSON.stringify(rows[0].context);
        assert.ok(serialized.includes('[Truncated]'), `${tc.id} audit context must contain [Truncated]`);
        assert.ok(
          serialized.length < 200_000,
          `${tc.id} audit context JSON must remain bounded, got ${serialized.length} chars`
        );
      }
      const dagElapsedMs = performance.now() - tDag0;
      assert.ok(dagElapsedMs < 1500, `4 DAG permission audits must complete quickly (<1500ms), got ${dagElapsedMs.toFixed(1)}ms`);

      // (b) Circular references (standalone AND combined with budget-exhausting DAG) deterministically preserve '[Circular]'
      const soloObjCyc = { label: 'solo' };
      soloObjCyc.self = soloObjCyc;
      await pb.checkPermission({
        appId: 'com.m2.cyc.obj',
        capability: CAPABILITIES.NETWORK_OUTBOUND,
        context: soloObjCyc,
      });
      const cycObjRows = pb.getAuditLog({ appId: 'com.m2.cyc.obj', limit: 5 });
      assert.equal(cycObjRows[0].context.self, '[Circular]');

      const soloArrCyc = ['head'];
      soloArrCyc.push(soloArrCyc);
      await pb.checkPermission({
        appId: 'com.m2.cyc.arr',
        capability: CAPABILITIES.NETWORK_OUTBOUND,
        context: soloArrCyc,
      });
      const cycArrRows = pb.getAuditLog({ appId: 'com.m2.cyc.arr', limit: 5 });
      assert.equal(cycArrRows[0].context[1], '[Circular]');

      // Exhaust shared 2048-node budget via 'dag' key FIRST, then visit ancestor 'self' -> MUST still report '[Circular]'
      const dagWithCycle = { dag: makeArrDag(7, 10), self: null };
      dagWithCycle.self = dagWithCycle;
      await pb.checkPermission({
        appId: 'com.m2.cyc.dag',
        capability: CAPABILITIES.NETWORK_OUTBOUND,
        context: dagWithCycle,
      });
      const dagCycRows = pb.getAuditLog({ appId: 'com.m2.cyc.dag', limit: 5 });
      assert.ok(
        JSON.stringify(dagCycRows[0].context.dag).includes('[Truncated]'),
        'DAG sibling must exhaust shared node budget before cycle check'
      );
      assert.equal(
        dagCycRows[0].context.self,
        '[Circular]',
        'Ancestor cycle check must take precedence over node budget truncation'
      );

      // (c) Genuine Uint8Array(5_000_000), cross-realm vm Uint8Array(5_000_000) & ArrayBuffer(5_000_000) -> bounded binary preview
      const hostU8 = new Uint8Array(5_000_000);
      const vmU8 = vm.runInNewContext('new Uint8Array(5_000_000)');
      const hostAb = new ArrayBuffer(5_000_000);
      const smallU8 = new Uint8Array([1, 2, 3]);

      const tBin0 = performance.now();
      await pb.checkPermission({ appId: 'com.m2.bin.host', capability: CAPABILITIES.UI_WINDOW, context: hostU8 });
      await pb.checkPermission({ appId: 'com.m2.bin.vm', capability: CAPABILITIES.UI_WINDOW, context: vmU8 });
      await pb.checkPermission({ appId: 'com.m2.bin.ab', capability: CAPABILITIES.UI_WINDOW, context: hostAb });
      await pb.checkPermission({ appId: 'com.m2.bin.small', capability: CAPABILITIES.UI_WINDOW, context: smallU8 });
      const binMs = performance.now() - tBin0;
      assert.ok(binMs < 500, `Large binary audit sanitization must be O(1) (<500ms), got ${binMs.toFixed(1)}ms`);

      assert.equal(pb.getAuditLog({ appId: 'com.m2.bin.host', limit: 5 })[0].context, '[Binary(5000000 bytes)]');
      assert.equal(pb.getAuditLog({ appId: 'com.m2.bin.vm', limit: 5 })[0].context, '[Binary(5000000 bytes)]');
      assert.equal(pb.getAuditLog({ appId: 'com.m2.bin.ab', limit: 5 })[0].context, '[Binary(5000000 bytes)]');
      assert.equal(pb.getAuditLog({ appId: 'com.m2.bin.small', limit: 5 })[0].context, 'AQID');
    } finally {
      pb.close();
      storage.close();
    }
  });

  it('20.3 (M3 + Obs-A): O(1) Proxy(Builtin)/sparse-array/boxed-primitive hardening across Config & Permissions + VFS constructor dependency validation', async () => {
    const storage = new SqliteStorage(':memory:');
    const cfg = new UnifiedConfigStore({ storage });
    const pb = new PermissionBroker({ storage });

    try {
      const protoMutProxyAb = new Proxy(new ArrayBuffer(8), {});
      Object.setPrototypeOf(protoMutProxyAb, Object.prototype);

      const trappedProxyDate = new Proxy(new Date(), { getPrototypeOf: () => Object.prototype });
      const trappedProxyAb = new Proxy(new ArrayBuffer(8), { getPrototypeOf: () => Object.prototype });
      const trappedProxyU8 = new Proxy(new Uint8Array(5_000_000), { getPrototypeOf: () => Object.prototype });
      const vmProxyU8 = vm.runInNewContext('new Proxy(new Uint8Array(5_000_000), {})');
      const vmProxyAb = vm.runInNewContext('new Proxy(new ArrayBuffer(8), {})');

      const sparseArr = [];
      sparseArr.length = 5_000_000;

      const fakeLenArrProxy = new Proxy([], {
        get(target, prop, receiver) {
          if (prop === 'length') return 5_000_000;
          return Reflect.get(target, prop, receiver);
        },
      });

      const revokedArrPair = Proxy.revocable([], {});
      revokedArrPair.revoke();
      const revokedArrProxy = revokedArrPair.proxy;

      const boxedStr5M = new String('a'.repeat(5_000_000));
      const vmBoxedStr5M = vm.runInNewContext("new String('a'.repeat(5_000_000))");
      const boxedNum = new Number(42);
      const boxedBool = new Boolean(true);

      const allHostileValues = [
        ['protoMutProxyAb', protoMutProxyAb, '[UnreadableObject]'],
        ['trappedProxyDate', trappedProxyDate, '[UnreadableObject]'],
        ['trappedProxyAb', trappedProxyAb, '[UnreadableObject]'],
        ['trappedProxyU8', trappedProxyU8, '[UnreadableObject]'],
        ['vmProxyU8', vmProxyU8, '[UnreadableObject]'],
        ['vmProxyAb', vmProxyAb, '[UnreadableObject]'],
        ['sparseArr', sparseArr, 'bounded-array'],
        ['fakeLenArrProxy', fakeLenArrProxy, 'bounded-array'],
        ['revokedArrProxy', revokedArrProxy, '[UnreadableObject]'],
        ['boxedStr5M', boxedStr5M, '[UnreadableObject]'],
        ['vmBoxedStr5M', vmBoxedStr5M, '[UnreadableObject]'],
        ['boxedNum', boxedNum, '[UnreadableObject]'],
        ['boxedBool', boxedBool, '[UnreadableObject]'],
      ];

      // 1. UnifiedConfigStore rejects every hostile Proxy(Builtin), sparse array, fake-length/revoked Array Proxy & boxed primitive in O(1)
      const tCfg0 = performance.now();
      for (const [label, bad] of allHostileValues) {
        assert.throws(() => cfg.defaults.set('com.m3.bad', label, bad), isTypedEinval, `defaults.set must reject ${label}`);
        assert.throws(
          () => cfg.sharedPrefs.edit('com.m3.bad', 'prefs', [{ op: 'put', key: label, value: bad }]),
          isTypedEinval,
          `sharedPrefs.edit must reject ${label}`
        );
        assert.throws(() => cfg.system.set(`custom.m3.${label}`, bad), isTypedEinval, `system.set must reject ${label}`);
        assert.equal(cfg.defaults.get('com.m3.bad', label), null);
        assert.equal(cfg.system.get(`custom.m3.${label}`), null);
      }
      const cfgMs = performance.now() - tCfg0;
      assert.ok(cfgMs < 1000, `UnifiedConfigStore M3 rejections must complete in O(1) (<1000ms), got ${cfgMs.toFixed(1)}ms`);

      // 2. PermissionBroker.checkPermission sanitizes every hostile value cleanly without OOM
      const tPb0 = performance.now();
      for (const [label, bad, expected] of allHostileValues) {
        const appId = `com.m3.pb.${label}`;
        const res = await pb.checkPermission({
          appId,
          capability: CAPABILITIES.FS_WRITE_SYSTEM,
          context: bad,
        });
        assert.equal(res.granted, false);
        const rows = pb.getAuditLog({ appId, limit: 5 });
        assert.equal(rows.length, 1);
        if (expected === 'bounded-array') {
          assert.equal(Array.isArray(rows[0].context), true, `${label} must sanitize to a bounded array`);
          assert.equal(rows[0].context.length, 256, `${label} audit array must be capped at 256 elements`);
        } else {
          assert.equal(rows[0].context, expected, `${label} audit context must equal ${expected}`);
        }
      }
      const pbMs = performance.now() - tPb0;
      assert.ok(pbMs < 1000, `PermissionBroker M3 sanitization must complete in O(1) (<1000ms), got ${pbMs.toFixed(1)}ms`);

      // 3. PermissionBroker constructor defaultPolicies rejects Uint8Array(5M), Proxy(Uint8Array(5M)), cross-realm & boxed String(5M) in O(1)
      const tDefPol0 = performance.now();
      for (const badPolicies of [
        new Uint8Array(5_000_000),
        new Proxy(new Uint8Array(5_000_000), {}),
        vmProxyU8,
        boxedStr5M,
      ]) {
        assert.throws(
          () => new PermissionBroker({ storage, defaultPolicies: badPolicies }),
          (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
        );
      }
      const defPolMs = performance.now() - tDefPol0;
      assert.ok(defPolMs < 500, `defaultPolicies rejections must be O(1) (<500ms), got ${defPolMs.toFixed(1)}ms`);

      // 4. Valid Array Proxies (Test 16.3 contract) remain 100% intact across UnifiedConfigStore & PermissionBroker
      const validArrProxy = new Proxy(['m3-alpha', 'm3-beta'], {});
      const throwingProtoArrProxy = new Proxy(['m3-gamma', 'm3-delta'], {
        getPrototypeOf() {
          throw new Error('m3-proto-trap');
        },
      });
      cfg.defaults.set('com.m3.ok', 'plainArr', validArrProxy);
      cfg.defaults.set('com.m3.ok', 'protoArr', throwingProtoArrProxy);
      assert.deepEqual(cfg.defaults.get('com.m3.ok', 'plainArr'), ['m3-alpha', 'm3-beta']);
      assert.deepEqual(cfg.defaults.get('com.m3.ok', 'protoArr'), ['m3-gamma', 'm3-delta']);

      assert.deepEqual(cfg.system.set('custom.m3.okArr', validArrProxy), ['m3-alpha', 'm3-beta']);
      assert.deepEqual(cfg.system.set('custom.m3.okProtoArr', throwingProtoArrProxy), ['m3-gamma', 'm3-delta']);
      assert.deepEqual(cfg.system.get('custom.m3.okArr'), ['m3-alpha', 'm3-beta']);
      assert.deepEqual(cfg.system.get('custom.m3.okProtoArr'), ['m3-gamma', 'm3-delta']);

      await pb.checkPermission({
        appId: 'com.m3.arrproxy',
        capability: CAPABILITIES.UI_WINDOW,
        context: throwingProtoArrProxy,
      });
      assert.deepEqual(pb.getAuditLog({ appId: 'com.m3.arrproxy', limit: 5 })[0].context, ['m3-gamma', 'm3-delta']);

      // 5. Obs-A: VFS constructor rejects revoked Proxies, non-objects & incomplete objects for userManager, pathTranslator & virtualMounts
      const revDep = makeRevokedObj();
      const isVfsEinval = (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL;

      for (const badDep of [revDep, 'bad-dep', 42, true, {}]) {
        assert.throws(() => new VFS({ storage, userManager: badDep }), isVfsEinval);
        assert.throws(() => new VFS({ storage, pathTranslator: badDep }), isVfsEinval);
        assert.throws(() => new VFS({ storage, virtualMounts: badDep }), isVfsEinval);
      }

      // Incomplete virtualMounts (revoked sub-mount) must also reject with VfsError(EINVAL)
      assert.throws(
        () =>
          new VFS({
            storage,
            virtualMounts: {
              getMountRoot: () => null,
              lookupStep: () => null,
              listChildren: () => [],
              clearTmp: () => {},
              tmpFs: revDep,
              procFs: { readNode: () => new Uint8Array(0) },
              devFs: { readDevice: () => new Uint8Array(0) },
            },
          }),
        isVfsEinval
      );

      // Valid injected dependencies still construct & operate cleanly
      const validUsers = new UserManager({ storage });
      const validTranslator = new PathTranslator();
      const validMounts = new VirtualMountManager();
      const validVfs = new VFS({
        storage,
        userManager: validUsers,
        pathTranslator: validTranslator,
        virtualMounts: validMounts,
      });
      try {
        assert.equal(validVfs.stat('/').type, 'dir');
        assert.ok(validVfs.readdir('/proc').some((e) => e.name === 'uptime'));
      } finally {
        validVfs.close();
        validUsers.close();
      }
    } finally {
      pb.close();
      cfg.close();
      storage.close();
    }
  });
});

// ============================================================================
// SUITE 21: Iteration 9 Cumulative Byte-Budget, O(1) M2B Object.keys() Parity & uiTree Quota Regressions
// ============================================================================

describe('Suite 21: Iteration 9 Cumulative Byte-Budget, O(1) M2B Object.keys() Parity & uiTree Quota Regressions (N1-A, N2-A, N1-B, Obs-2/Obs-3)', () => {
  function isTypedEinval(err) {
    return (
      err instanceof OmniOSError &&
      err.code === ERROR_CODES.EINVAL &&
      !(err instanceof TypeError) &&
      !(err instanceof SyntaxError) &&
      !(err instanceof RangeError)
    );
  }

  function isTypedQuota(err, expectedCode = ERROR_CODES.EQUOTA) {
    return (
      err instanceof QuotaExceededError &&
      err instanceof OmniOSError &&
      err.code === expectedCode &&
      !(err instanceof RangeError)
    );
  }

  function makeBinaryDag(leaf, levels) {
    let node = leaf;
    for (let i = 0; i < levels; i += 1) {
      node = [node, node];
    }
    return node;
  }

  function makeBranchingDag(levels, branch) {
    let node = { v: 1 };
    for (let i = 0; i < levels; i += 1) {
      node = new Array(branch).fill(node);
    }
    return node;
  }

  function makeRevokedArr() {
    const { proxy, revoke } = Proxy.revocable([], {});
    revoke();
    return proxy;
  }

  function makeFakeLenArrProxy(fakeLen = 5_000_000, elementFactory = null) {
    return new Proxy([], {
      get(target, prop, receiver) {
        if (prop === 'length') return fakeLen;
        if (elementFactory && typeof prop === 'string' && /^(0|[1-9]\d*)$/.test(prop)) {
          return elementFactory(Number(prop));
        }
        return Reflect.get(target, prop, receiver);
      },
    });
  }

  function makeThrowingProtoArr(items = ['n1b-alpha', 'n1b-beta']) {
    return new Proxy(items, {
      getPrototypeOf() {
        throw new Error('n1b-proto-trap');
      },
    });
  }

  it('21.1 (N1-A + Obs-2 + Obs-3): UnifiedConfigStore cumulative byte budgets, Registry/SharedPrefs caps, REG_DWORD bounds & ProcFsMount PCB isolation', () => {
    const storage = new SqliteStorage(':memory:');
    const eventBus = new KernelEventBus();
    const events = [];
    eventBus.on('config:changed', (evt) => events.push(evt));
    const cfg = new UnifiedConfigStore({ storage, eventBus });

    try {
      // 1. 18 KB 15-level string DAG (65,535 <= 65,536 nodes) & 6 KB 4KB-string DAG -> OmniOSError(EINVAL), never raw RangeError/OOM
      const dag16k = makeBinaryDag('A'.repeat(16_384), 15);
      const dag4k = makeBinaryDag('B'.repeat(4_096), 15);

      const tDag0 = performance.now();
      for (const [label, dag] of [
        ['dag16k', dag16k],
        ['dag4k', dag4k],
      ]) {
        assert.throws(() => cfg.defaults.set('com.n1a.dag', label, dag), isTypedEinval, `defaults.set must reject ${label}`);
        assert.throws(() => cfg.system.set(`custom.n1a.${label}`, dag), isTypedEinval, `system.set must reject ${label}`);
        assert.throws(
          () => cfg.sharedPrefs.edit('com.n1a.dag', 'prefs', [{ op: 'put', key: label, value: dag }]),
          isTypedEinval,
          `sharedPrefs.edit must reject ${label}`
        );
        assert.equal(cfg.defaults.get('com.n1a.dag', label), null);
        assert.equal(cfg.system.get(`custom.n1a.${label}`), null);
      }
      assert.deepEqual(cfg.sharedPrefs.getAll('com.n1a.dag', 'prefs'), {});
      const dagMs = performance.now() - tDag0;
      assert.ok(dagMs < 1500, `String DAG byte-budget rejections must be fast (<1500ms), got ${dagMs.toFixed(1)}ms`);

      // 2. 80 KB binary amplification Array(2000).fill(Uint8Array(65536)) (2,001 nodes) -> OmniOSError(EINVAL) in O(1)
      const binArr2000 = Array(2000).fill(new Uint8Array(65_536));
      const abArr2000 = Array(2000).fill(new ArrayBuffer(65_536));
      const tBin0 = performance.now();
      assert.throws(() => cfg.defaults.set('com.n1a.bin', 'u8', binArr2000), isTypedEinval);
      assert.throws(() => cfg.defaults.set('com.n1a.bin', 'ab', abArr2000), isTypedEinval);
      assert.throws(
        () => cfg.sharedPrefs.edit('com.n1a.bin', 'prefs', [{ op: 'put', key: 'u8', value: binArr2000 }]),
        isTypedEinval
      );
      const binMs = performance.now() - tBin0;
      assert.ok(binMs < 500, `Binary amplification rejection must be O(1) (<500ms), got ${binMs.toFixed(1)}ms`);
      assert.equal(cfg.defaults.get('com.n1a.bin', 'u8'), null);

      // 3. 3 MiB '<' XML 4x entity-expansion array -> persists under 4 MiB JSON budget, rejects cleanly in exportPlistXml() with OmniOSError(EINVAL)
      const ltPayload = Array(32).fill('<'.repeat(98_304)); // 3,145,728 raw chars -> >12.5 MiB when '&lt;' escaped
      cfg.defaults.set('com.n1a.xmlbomb', 'angles', ltPayload);
      assert.throws(
        () => cfg.defaults.exportPlistXml('com.n1a.xmlbomb'),
        isTypedEinval,
        'exportPlistXml must reject 4x XML entity-expansion overflow cleanly'
      );
      // Sanity: small valid XML with entities still exports cleanly
      cfg.defaults.set('com.n1a.xmlok', 'msg', '<tag attr="ok">&');
      const okXml = cfg.defaults.exportPlistXml('com.n1a.xmlok');
      assert.ok(okXml.includes('&lt;tag attr=&quot;ok&quot;&gt;&amp;'));

      // 4. Registry caps: REG_MULTI_SZ, REG_SZ (5 MB), REG_EXPAND_SZ (5 MB), REG_BINARY (5 MB / sparse / Proxy)
      const tReg0 = performance.now();
      assert.throws(
        () =>
          cfg.registry.setValue(
            REGISTRY_HIVES.HKCU,
            'Software\\N1A',
            'Multi100k',
            REGISTRY_TYPES.REG_MULTI_SZ,
            Array(100_000).fill('A'.repeat(6000))
          ),
        isTypedEinval
      );
      assert.throws(
        () =>
          cfg.registry.setValue(
            REGISTRY_HIVES.HKCU,
            'Software\\N1A',
            'Multi10k',
            REGISTRY_TYPES.REG_MULTI_SZ,
            Array(10_000).fill('A'.repeat(6000))
          ),
        isTypedEinval
      );
      assert.throws(
        () =>
          cfg.registry.setValue(
            REGISTRY_HIVES.HKCU,
            'Software\\N1A',
            'Sz5M',
            REGISTRY_TYPES.REG_SZ,
            'S'.repeat(5 * 1024 * 1024)
          ),
        isTypedEinval
      );
      assert.throws(
        () =>
          cfg.registry.setValue(
            REGISTRY_HIVES.HKCU,
            'Software\\N1A',
            'Expand5M',
            REGISTRY_TYPES.REG_EXPAND_SZ,
            'E'.repeat(5 * 1024 * 1024)
          ),
        isTypedEinval
      );
      const sparseBytes = [];
      sparseBytes.length = 5_000_000;
      const proxyBytes = makeFakeLenArrProxy(5_000_000, () => 0x41);
      for (const badBin of [new Uint8Array(5 * 1024 * 1024), new ArrayBuffer(5 * 1024 * 1024), sparseBytes, proxyBytes]) {
        assert.throws(
          () => cfg.registry.setValue(REGISTRY_HIVES.HKCU, 'Software\\N1A', 'BinBad', REGISTRY_TYPES.REG_BINARY, badBin),
          isTypedEinval
        );
      }
      const regMs = performance.now() - tReg0;
      assert.ok(regMs < 1000, `Registry cap rejections must be O(1) (<1000ms), got ${regMs.toFixed(1)}ms`);
      assert.equal(cfg.registry.getValue(REGISTRY_HIVES.HKCU, 'Software\\N1A', 'Multi100k'), null);
      assert.equal(cfg.registry.getValue(REGISTRY_HIVES.HKCU, 'Software\\N1A', 'Sz5M'), null);
      assert.equal(cfg.registry.getValue(REGISTRY_HIVES.HKCU, 'Software\\N1A', 'BinBad'), null);

      // 5. sharedPrefs.edit() 1_000_000-op Array Proxy AND 10 x 1 MB cumulative batch reject atomically with rollback
      cfg.sharedPrefs.edit('com.n1a.sp', 'atomic', [{ op: 'put', key: 'baseline', value: 'intact' }]);
      assert.deepEqual(cfg.sharedPrefs.getAll('com.n1a.sp', 'atomic'), { baseline: 'intact' });

      const millionOpProxy = makeFakeLenArrProxy(1_000_000, () => ({ op: 'clear' }));
      const tSp0 = performance.now();
      assert.throws(() => cfg.sharedPrefs.edit('com.n1a.sp', 'atomic', millionOpProxy), isTypedEinval);
      const spProxyMs = performance.now() - tSp0;
      assert.ok(spProxyMs < 500, `1M-op Proxy sharedPrefs.edit must reject in O(1) (<500ms), got ${spProxyMs.toFixed(1)}ms`);
      assert.deepEqual(cfg.sharedPrefs.getAll('com.n1a.sp', 'atomic'), { baseline: 'intact' });

      const tenByOneMbOps = [{ op: 'put', key: 'mutatedBeforeFail', value: 'must-rollback' }];
      const oneMbStr = 'M'.repeat(1_000_000);
      for (let i = 0; i < 10; i += 1) {
        tenByOneMbOps.push({ op: 'put', key: `chunk_${i}`, value: oneMbStr });
      }
      assert.throws(() => cfg.sharedPrefs.edit('com.n1a.sp', 'atomic', tenByOneMbOps), isTypedEinval);
      assert.deepEqual(
        cfg.sharedPrefs.getAll('com.n1a.sp', 'atomic'),
        { baseline: 'intact' },
        '10x1MB batch failure must roll back atomically without keeping earlier mutations'
      );

      // 6. Key-length DAG & gigantic 1n << 10_000_000n BigInt reject cleanly in O(1)
      const bigKeyA = `A${'K'.repeat(65_535)}`;
      const bigKeyB = `B${'K'.repeat(65_535)}`;
      let keyDag = { leaf: 1 };
      for (let i = 0; i < 10; i += 1) {
        keyDag = { [bigKeyA]: keyDag, [bigKeyB]: keyDag };
      }
      const giantBigInt = 1n << 10_000_000n;
      const negGiantBigInt = -giantBigInt;

      const tBig0 = performance.now();
      assert.throws(() => cfg.defaults.set('com.n1a.keydag', 'kd', keyDag), isTypedEinval);
      assert.throws(() => cfg.system.set('custom.n1a.kd', keyDag), isTypedEinval);
      assert.throws(
        () => cfg.sharedPrefs.edit('com.n1a.keydag', 'prefs', [{ op: 'put', key: 'kd', value: keyDag }]),
        isTypedEinval
      );
      const isTypedErange = (err) =>
        err instanceof OmniOSError &&
        err.code === ERROR_CODES.ERANGE &&
        err.message.includes('[BigInt(out-of-range)]');
      for (const bi of [giantBigInt, negGiantBigInt]) {
        assert.throws(() => cfg.defaults.set('com.n1a.bi', 'v', bi), isTypedEinval);
        assert.throws(() => cfg.system.set('custom.n1a.bi', bi), isTypedEinval);
        assert.throws(
          () => cfg.sharedPrefs.edit('com.n1a.bi', 'prefs', [{ op: 'put', key: 'v', value: bi }]),
          isTypedErange
        );
        assert.throws(
          () => cfg.sharedPrefs.edit('com.n1a.bi', 'prefs', [{ op: 'put', key: 'nested', value: { n: bi } }]),
          isTypedEinval
        );
        assert.throws(
          () => cfg.registry.setValue(REGISTRY_HIVES.HKCU, 'Software\\N1A', 'DwBig', REGISTRY_TYPES.REG_DWORD, bi),
          isTypedErange
        );
        assert.throws(
          () => cfg.registry.setValue(REGISTRY_HIVES.HKCU, 'Software\\N1A', 'QwBig', REGISTRY_TYPES.REG_QWORD, bi),
          isTypedErange
        );
      }
      const bigMs = performance.now() - tBig0;
      assert.ok(bigMs < 500, `Key-length DAG & 10M-bit BigInt rejections must be O(1) (<500ms), got ${bigMs.toFixed(1)}ms`);

      // 7. toJsonSafeEventValue bounds large binary/string events under MAX_EVENT_BYTES (256 KiB) while preserving [Circular]
      events.length = 0;
      // 30 x 64 KB binary (~2.6 MiB base64 < 4 MiB config limit) -> persists cleanly, emits bounded config:changed event
      cfg.defaults.set('com.n1a.ev', 'validBinArr', Array(30).fill(new Uint8Array(65_536)));
      assert.equal(events.length, 1);
      const binEvtJson = JSON.stringify(events[0].value);
      assert.ok(binEvtJson.length < 350_000, `Binary event payload must stay bounded under MAX_EVENT_BYTES, got ${binEvtJson.length}`);
      assert.ok(binEvtJson.includes('[Binary(65536 bytes)]'), 'Large binary array event must summarize overflow entries as [Binary(65536 bytes)]');

      events.length = 0;
      cfg.defaults.set('com.n1a.ev', 'validStrArr', Array(25).fill('X'.repeat(30_000)));
      assert.equal(events.length, 1);
      const strEvtJson = JSON.stringify(events[0].value);
      assert.ok(strEvtJson.length < 350_000, `String event payload must stay bounded under MAX_EVENT_BYTES, got ${strEvtJson.length}`);
      assert.ok(strEvtJson.includes('[Truncated]'), 'Large string array event must truncate under MAX_EVENT_BYTES');

      // Verify circular reference preservation AFTER byte-budget exhaustion in toJsonSafeEventValue
      events.length = 0;
      const circEvtPayload = { big: Array(250).fill('A'.repeat(500_000)), self: null };
      circEvtPayload.self = circEvtPayload;
      cfg._emitConfigChanged({
        source: 'defaults',
        key: 'com.n1a.ev:circ',
        oldValue: null,
        value: circEvtPayload,
        synced: false,
        origin: 'test',
      });
      assert.equal(events.length, 1);
      const circEvtJson = JSON.stringify(events[0].value);
      assert.ok(circEvtJson.length < 350_000, `Circular event payload must stay bounded, got ${circEvtJson.length}`);
      assert.ok(JSON.stringify(events[0].value.big).includes('[Truncated]'));
      assert.equal(events[0].value.self, '[Circular]', 'toJsonSafeEventValue must preserve [Circular] after byte-budget exhaustion');

      // 8. Obs-2: tampered SQLite REG_DWORD throws OmniOSError(EINVAL) on getValue() & enumKey(), while "0" and "4294967295" round-trip accurately
      const nowIso = new Date().toISOString();
      cfg.registry.createKey(REGISTRY_HIVES.HKCU, 'Software\\DwordValid');
      cfg.registry.createKey(REGISTRY_HIVES.HKCU, 'Software\\DwordTampered');

      const insertDword = (keyPathNorm, nameNorm, nameOrig, rawText) => {
        storage.run(
          `INSERT INTO registry_values
            (hive, key_path_norm, value_name_norm, value_name_orig, value_type, data_text, data_blob, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          REGISTRY_HIVES.HKCU,
          keyPathNorm,
          nameNorm,
          nameOrig,
          REGISTRY_TYPES.REG_DWORD,
          rawText,
          null,
          nowIso
        );
      };

      insertDword('software\\dwordvalid', 'min', 'Min', '0');
      insertDword('software\\dwordvalid', 'max', 'Max', '4294967295');

      const tamperedDwords = [
        ['nonnum', 'NonNum', 'abc'],
        ['neg', 'Neg', '-1'],
        ['overflow', 'Overflow', '4294967296'],
        ['float', 'Float', '12.5'],
        ['hex', 'Hex', '0x10'],
      ];
      for (const [norm, orig, raw] of tamperedDwords) {
        insertDword('software\\dwordtampered', norm, orig, raw);
      }

      assert.equal(cfg.registry.getValue(REGISTRY_HIVES.HKCU, 'Software\\DwordValid', 'Min')?.data, 0);
      assert.equal(cfg.registry.getValue(REGISTRY_HIVES.HKCU, 'Software\\DwordValid', 'Max')?.data, 4294967295);
      const validDwEnum = cfg.registry.enumKey(REGISTRY_HIVES.HKCU, 'Software\\DwordValid');
      assert.equal(validDwEnum.values.Min?.data, 0);
      assert.equal(validDwEnum.values.Max?.data, 4294967295);

      for (const [, orig] of tamperedDwords) {
        assert.throws(
          () => cfg.registry.getValue(REGISTRY_HIVES.HKCU, 'Software\\DwordTampered', orig),
          isTypedEinval,
          `Tampered REG_DWORD "${orig}" must throw OmniOSError(EINVAL)`
        );
      }
      assert.throws(() => cfg.registry.enumKey(REGISTRY_HIVES.HKCU, 'Software\\DwordTampered'), isTypedEinval);

      // 9. Obs-3: ProcFsMount with throwing-getter PCB resolves and reads status, cmdline, cwd, maps without throwing
      const throwingPcb = { pid: 4242, state: 'RUNNING' };
      for (const prop of [
        'name',
        'args',
        'cwd',
        'uid',
        'gid',
        'ppid',
        'platform',
        'arch',
        'appId',
        'priority',
        'threads',
        'fdTable',
        'windowIds',
        'stats',
        'addressSpace',
      ]) {
        Object.defineProperty(throwingPcb, prop, {
          enumerable: true,
          get() {
            throw new Error(`hostile-pcb-getter:${prop}`);
          },
        });
      }
      const hostilePm = {
        get(pid) {
          return pid === 4242 ? throwingPcb : null;
        },
        list() {
          return [throwingPcb];
        },
      };
      const vmMounts = new VirtualMountManager({ processManager: hostilePm });
      const vfsStorage = new SqliteStorage(':memory:');
      const vfs = new VFS({ storage: vfsStorage, virtualMounts: vmMounts });
      try {
        const statusText = vfs.readFile('/proc/4242/status', { encoding: 'utf8' });
        const cmdlineText = vfs.readFile('/proc/4242/cmdline', { encoding: 'utf8' });
        const cwdText = vfs.readFile('/proc/4242/cwd', { encoding: 'utf8' });
        const mapsText = vfs.readFile('/proc/4242/maps', { encoding: 'utf8' });

        assert.ok(statusText.includes('State:\tRUNNING'));
        assert.ok(statusText.includes('Pid:\t4242'));
        assert.equal(cmdlineText, '\n');
        assert.equal(cwdText, '/\n');
        assert.equal(mapsText, '');
      } finally {
        vfs.close();
        vfsStorage.close();
      }
    } finally {
      cfg.close();
      storage.close();
    }
  });

  it('21.2 (N2-A): PermissionBroker.safeJsonClone() cumulative byte & string budget + deterministic [Circular] after byte exhaustion', async () => {
    const storage = new SqliteStorage(':memory:');
    const pb = new PermissionBroker({ storage });

    try {
      // 1. 102 KB depth-2 string DAG (2,011 < 2,048 nodes)
      const dag2 = Array(10).fill(Array(200).fill('A'.repeat(100_000)));
      // 2. Depth-1 250 x 500 KB string array (251 << 2,048 nodes)
      const arr250 = Array(250).fill('B'.repeat(500_000));
      // 3. 200 x 16 KB binary array
      const bin200 = Array(200).fill(new Uint8Array(16_384));
      // 4. Key-length amplification (20 x 20 KB keys)
      const keyAmp = {};
      for (let i = 0; i < 20; i += 1) {
        keyAmp[`k${i}_${'X'.repeat(20_000)}`] = i;
      }
      // 5. Gigantic 1n << 10_000_000n BigInt (positive & negative)
      const giantBigInt = 1n << 10_000_000n;
      const negGiantBigInt = -giantBigInt;

      const cases = [
        { id: 'com.n2a.dag2', ctx: dag2, expectToken: '[Truncated]' },
        { id: 'com.n2a.arr250', ctx: arr250, expectToken: '[Truncated]' },
        { id: 'com.n2a.bin200', ctx: bin200, expectToken: '[Binary(16384 bytes)]' },
        { id: 'com.n2a.keyamp', ctx: keyAmp, expectToken: '[Truncated]' },
        { id: 'com.n2a.bigpos', ctx: { n: giantBigInt }, expectToken: '[BigInt(Truncated)]' },
        { id: 'com.n2a.bigneg', ctx: negGiantBigInt, expectToken: '[BigInt(Truncated)]' },
      ];

      const t0 = performance.now();
      for (const tc of cases) {
        const res = await pb.checkPermission({
          appId: tc.id,
          capability: CAPABILITIES.NETWORK_OUTBOUND,
          context: tc.ctx,
        });
        assert.equal(typeof res.granted, 'boolean');
        const rows = pb.getAuditLog({ appId: tc.id, limit: 5 });
        assert.equal(rows.length, 1);
        const serialized = JSON.stringify(rows[0].context);
        assert.ok(
          serialized.length < 150_000,
          `${tc.id} audit JSON must stay strictly bounded, got ${serialized.length} chars`
        );
        assert.ok(
          serialized.includes(tc.expectToken),
          `${tc.id} audit JSON must contain ${tc.expectToken}`
        );
      }

      // 6. Circular reference AFTER byte-budget exhaustion -> deterministically preserves self === '[Circular]'
      const bigObjWithCycle = { big: Array(250).fill('A'.repeat(500_000)), self: null };
      bigObjWithCycle.self = bigObjWithCycle;
      await pb.checkPermission({
        appId: 'com.n2a.cyc.obj',
        capability: CAPABILITIES.NETWORK_OUTBOUND,
        context: bigObjWithCycle,
      });
      const cycObjRows = pb.getAuditLog({ appId: 'com.n2a.cyc.obj', limit: 5 });
      assert.equal(cycObjRows.length, 1);
      const cycObjJson = JSON.stringify(cycObjRows[0].context);
      assert.ok(cycObjJson.length < 150_000, `Circular object audit JSON must stay bounded, got ${cycObjJson.length}`);
      assert.ok(JSON.stringify(cycObjRows[0].context.big).includes('[Truncated]'));
      assert.equal(
        cycObjRows[0].context.self,
        '[Circular]',
        'Ancestor circular reference MUST remain [Circular] even after byte-budget exhaustion'
      );

      // Also verify array circular reference after byte-budget exhaustion (index 250 < 256 cap)
      const bigArrWithCycle = Array(250).fill('C'.repeat(500_000));
      bigArrWithCycle.push(bigArrWithCycle);
      await pb.checkPermission({
        appId: 'com.n2a.cyc.arr',
        capability: CAPABILITIES.NETWORK_OUTBOUND,
        context: bigArrWithCycle,
      });
      const cycArrRows = pb.getAuditLog({ appId: 'com.n2a.cyc.arr', limit: 5 });
      assert.equal(cycArrRows.length, 1);
      assert.ok(Array.isArray(cycArrRows[0].context));
      assert.ok(cycArrRows[0].context.includes('[Truncated]'));
      assert.equal(cycArrRows[0].context[cycArrRows[0].context.length - 1], '[Circular]');

      const elapsedMs = performance.now() - t0;
      assert.ok(elapsedMs < 1500, `All N2-A permission audit checks must complete rapidly (<1500ms), got ${elapsedMs.toFixed(1)}ms`);
    } finally {
      pb.close();
      storage.close();
    }
  });

  it('21.3 (N1-B): M2B M3-parity O(1) Object.keys() hardening across all 7 M2B modules while preserving valid throwing-getPrototypeOf Array Proxies', async () => {
    const storage = new SqliteStorage(':memory:');
    const bus = new KernelEventBus();
    const pm = new ProcessManager({ eventBus: bus });
    const pb = new PermissionBroker({ storage });
    const ipc = new IPCManager({ eventBus: bus, processManager: pm });
    const clip = new SharedClipboard({ eventBus: bus });
    const notif = new NotificationCenter({ eventBus: bus, processManager: pm });
    const router = new IntentRouter({ eventBus: bus, processManager: pm });
    const comp = new Compositor({ eventBus: bus, processManager: pm });
    const pkgWithPb = new PackageManager({ storage, processManager: pm, permissions: pb });
    const pkgNoPb = new PackageManager({ storage, processManager: pm });

    try {
      const proc = pm.spawn({
        name: 'n1b-proc',
        appId: 'com.n1b.app',
        platform: 'universal',
        executionContext: makeWorkExecContext(),
      });
      const win = comp.createWindow(proc.pid, { title: 'N1BWin' });
      ipc.createChannel('ch.n1b', 0);

      const deliveredIntents = [];
      router.registerHandlers('com.n1b.app', [{ schemes: ['n1b'] }]);
      bus.on('intent:delivered', (evt) => deliveredIntents.push(evt));

      const uapp = buildUappFixture();
      const universalRuntime = {
        platform: 'universal',
        inspectPackage() {
          return {
            format: PACKAGE_FORMATS.UNIVERSAL_UAPP,
            platform: 'universal',
            arch: 'wasm',
            appId: 'com.n1b.uapp',
            name: 'N1B App',
            version: '1.0.0',
            permissions: [],
            intents: [],
          };
        },
        createExecutionContext() {
          return makeWorkExecContext();
        },
      };
      pkgWithPb.registerRuntime('universal', universalRuntime);
      pkgNoPb.registerRuntime('universal', universalRuntime);

      // Construct all N1-B hostile O(1) vectors
      const boxedStr5M = new String('a'.repeat(5_000_000));
      const vmBoxedStr5M = vm.runInNewContext("new String('a'.repeat(5_000_000))");
      const protoMutProxyU8 = new Proxy(new Uint8Array(5_000_000), {});
      Object.setPrototypeOf(protoMutProxyU8, Object.prototype);
      const vmProxyU8 = vm.runInNewContext('new Proxy(new Uint8Array(5_000_000), {})');
      const sab5M = new SharedArrayBuffer(5_000_000);
      const sparseArr5M = [];
      sparseArr5M.length = 5_000_000;
      const fakeLenArr5M = makeFakeLenArrProxy(5_000_000);
      const revokedArr = makeRevokedArr();
      const rawU8_5M = new Uint8Array(5_000_000);

      const clonerHostiles = [
        ['boxedStr5M', boxedStr5M],
        ['vmBoxedStr5M', vmBoxedStr5M],
        ['protoMutProxyU8', protoMutProxyU8],
        ['vmProxyU8', vmProxyU8],
        ['sab5M', sab5M],
        ['sparseArr5M', sparseArr5M],
        ['fakeLenArr5M', fakeLenArr5M],
        ['revokedArr', revokedArr],
      ];

      const t0 = performance.now();

      // A. All 6 M2B cloners reject/sanitize every N1-B vector instantaneously in O(1)
      for (let i = 0; i < clonerHostiles.length; i += 1) {
        const [label, bad] = clonerHostiles[i];

        // 1. IPCManager.send -> OmniOSError(EINVAL), queue stays empty
        assert.throws(() => ipc.send('ch.n1b', 0, bad), isTypedEinval, `IPCManager.send must reject ${label}`);

        // 2. SharedClipboard.set({ json }) -> OmniOSError(EINVAL)
        assert.throws(() => clip.set({ json: bad }), isTypedEinval, `SharedClipboard.set({json}) must reject ${label}`);

        // 3. NotificationCenter.post({ data }) -> '[Unreadable]'
        const posted = notif.post({ appId: 'com.n1b.app', title: `N1B-${label}`, data: bad });
        assert.equal(posted.data, '[Unreadable]', `NotificationCenter.post must sanitize ${label}`);

        // 4. IntentRouter.dispatch({ extras }) -> delivered with extras === '[Unreadable]'
        deliveredIntents.length = 0;
        const routed = router.dispatch({ action: 'view', uri: 'n1b://go', extras: bad });
        assert.equal(routed.status, 'DELIVERED');
        assert.equal(deliveredIntents.length, 1);
        assert.equal(deliveredIntents[0].intent.extras, '[Unreadable]', `IntentRouter.dispatch must sanitize ${label}`);

        // 5. Compositor.dispatchInput & updateSurface({ uiTree }) -> '[Unreadable]'
        const prevEvents = proc.executionContext.receivedEvents.length;
        comp.dispatchInput(win.windowId, { type: 'click', detail: bad });
        assert.equal(proc.executionContext.receivedEvents.length, prevEvents + 1);
        assert.equal(
          proc.executionContext.receivedEvents[prevEvents].detail,
          '[Unreadable]',
          `Compositor.dispatchInput must sanitize ${label}`
        );
        comp.updateSurface(win.windowId, { uiTree: bad });
        assert.equal(
          comp.getWindow(win.windowId).surface.uiTree,
          '[Unreadable]',
          `Compositor.updateSurface({uiTree}) must sanitize ${label}`
        );

        // 6. PackageManager.registerCatalogEntry({ metadata }) -> '[Unreadable]'
        const cat = pkgWithPb.registerCatalogEntry({
          appId: `com.n1b.cat.${i}`,
          name: `Cat ${label}`,
          platform: 'universal',
          metadata: bad,
        });
        assert.equal(cat.metadata, '[Unreadable]', `PackageManager.registerCatalogEntry must sanitize ${label}`);
      }
      assert.equal(ipc.listChannels().find((c) => c.name === 'ch.n1b')?.queueSize, 0);

      // B. Direct Object.keys() entry points: createZip(), clipboard.set({ formats }), packageManager.install({ grants })
      const directObjectHostiles = [
        ['rawU8_5M', rawU8_5M],
        ['boxedStr5M', boxedStr5M],
        ['vmBoxedStr5M', vmBoxedStr5M],
        ['protoMutProxyU8', protoMutProxyU8],
        ['vmProxyU8', vmProxyU8],
        ['sab5M', sab5M],
      ];

      for (const [label, badObj] of directObjectHostiles) {
        // 7. createZip() -> FormatError(EINVAL)
        assert.throws(
          () => createZip(badObj),
          (err) => err instanceof FormatError && err.code === ERROR_CODES.EINVAL,
          `createZip must reject ${label} in O(1)`
        );

        // clipboard.set({ formats }) -> OmniOSError(EINVAL)
        assert.throws(
          () => clip.set({ formats: badObj }),
          isTypedEinval,
          `SharedClipboard.set({formats}) must reject ${label} in O(1)`
        );

        // packageManager.install({ grants }) -> OmniOSError(EINVAL) BOTH with and without PermissionBroker!
        await assert.rejects(
          () => pkgWithPb.install(uapp, { grants: badObj }),
          isTypedEinval,
          `PackageManager.install({grants}) with PermissionBroker must reject ${label} in O(1)`
        );
        await assert.rejects(
          () => pkgNoPb.install(uapp, { grants: badObj }),
          isTypedEinval,
          `PackageManager.install({grants}) without PermissionBroker must reject ${label} in O(1)`
        );
      }
      assert.equal(pkgWithPb.get('com.n1b.uapp'), null, 'Rejected grants must never leave installed packages behind');

      // Also test PackageManager.launch({ intent }) against N1-B hostile vectors
      await pkgWithPb.install(uapp);
      for (const [label, bad] of clonerHostiles) {
        const launched = await pkgWithPb.launch('com.n1b.uapp', { intent: bad });
        assert.ok(launched.pid > 0, `launch({intent}) with ${label} must sanitize cleanly without OOM`);
        pkgWithPb.stop(launched.pid);
      }

      const hostileMs = performance.now() - t0;
      assert.ok(hostileMs < 1500, `All 7-module N1-B O(1) checks must finish rapidly (<1500ms), got ${hostileMs.toFixed(1)}ms`);

      // C. Valid throwing-getPrototypeOf Array Proxies remain 100% intact across ALL 6 M2B cloners!
      const validProxyArr = makeThrowingProtoArr(['keep-1', 'keep-2']);

      // 1. IPCManager
      ipc.send('ch.n1b', 0, validProxyArr);
      assert.deepEqual(ipc.recv('ch.n1b').payload, ['keep-1', 'keep-2']);

      // 2. SharedClipboard
      clip.set({ json: validProxyArr });
      assert.deepEqual(clip.get().json, ['keep-1', 'keep-2']);

      // 3. NotificationCenter
      const goodNotif = notif.post({ appId: 'com.n1b.app', title: 'ValidProxyArr', data: validProxyArr });
      assert.deepEqual(goodNotif.data, ['keep-1', 'keep-2']);

      // 4. IntentRouter
      deliveredIntents.length = 0;
      const goodIntent = router.dispatch({ action: 'view', uri: 'n1b://ok', extras: validProxyArr });
      assert.equal(goodIntent.status, 'DELIVERED');
      assert.deepEqual(deliveredIntents[0].intent.extras, ['keep-1', 'keep-2']);

      // 5. Compositor (uiTree & dispatchInput)
      comp.updateSurface(win.windowId, { uiTree: validProxyArr });
      assert.deepEqual(comp.getWindow(win.windowId).surface.uiTree, ['keep-1', 'keep-2']);
      const evIdx = proc.executionContext.receivedEvents.length;
      comp.dispatchInput(win.windowId, { type: 'click', detail: validProxyArr });
      assert.deepEqual(proc.executionContext.receivedEvents[evIdx].detail, ['keep-1', 'keep-2']);

      // 6. PackageManager (registerCatalogEntry & launch intent)
      const goodCat = pkgWithPb.registerCatalogEntry({
        appId: 'com.n1b.cat.valid',
        name: 'Valid Cat',
        platform: 'universal',
        metadata: validProxyArr,
      });
      assert.deepEqual(goodCat.metadata, ['keep-1', 'keep-2']);

      let capturedLaunchIntent = null;
      pkgWithPb.registerRuntime('universal', {
        ...universalRuntime,
        createExecutionContext(_pcb, _rec, _services, launchOpts) {
          capturedLaunchIntent = launchOpts.intent;
          return makeWorkExecContext();
        },
      });
      const launchedGood = await pkgWithPb.launch('com.n1b.uapp', { intent: validProxyArr });
      assert.deepEqual(capturedLaunchIntent, ['keep-1', 'keep-2']);
      pkgWithPb.stop(launchedGood.pid);
    } finally {
      ipc.stop();
      pkgWithPb.close();
      pkgNoPb.close();
      pb.close();
      storage.close();
    }
  });

  it('21.4 (M2B Proactive DAG Byte Budgets & Compositor uiTree Quota Parity): All 6 M2B cloners bound string/binary DAGs & BigInts, uiTree 16^7 DAG enforces atomic EQUOTA & appendDrawOps enforces cumulative byte cap', async () => {
    const storage = new SqliteStorage(':memory:');
    const bus = new KernelEventBus();
    const pm = new ProcessManager({ eventBus: bus });
    const ipc = new IPCManager({ eventBus: bus, processManager: pm });
    const clip = new SharedClipboard({ eventBus: bus });
    const notif = new NotificationCenter({ eventBus: bus, processManager: pm });
    const router = new IntentRouter({ eventBus: bus, processManager: pm });
    const comp = new Compositor({ eventBus: bus, processManager: pm });
    const pkg = new PackageManager({ storage, processManager: pm });

    try {
      const proc = pm.spawn({
        name: 'm2b-dag-proc',
        appId: 'com.m2b.dag',
        platform: 'universal',
        executionContext: makeWorkExecContext(),
      });
      const baseWin = comp.createWindow(proc.pid, {
        title: 'BaseWin',
        uiTree: { type: 'root', children: [] },
        drawOps: [{ op: 'clear', color: '#000' }],
      });
      ipc.createChannel('ch.dag', 0);

      const deliveredIntents = [];
      router.registerHandlers('com.m2b.dag', [{ schemes: ['dag'] }]);
      bus.on('intent:delivered', (evt) => deliveredIntents.push(evt));

      pkg.registerRuntime('universal', {
        platform: 'universal',
        inspectPackage() {
          return {
            format: PACKAGE_FORMATS.UNIVERSAL_UAPP,
            platform: 'universal',
            arch: 'wasm',
            appId: 'com.m2b.dag.uapp',
            name: 'DAG App',
            version: '1.0.0',
            permissions: [],
            intents: [],
          };
        },
        createExecutionContext() {
          return makeWorkExecContext();
        },
      });
      await pkg.install(buildUappFixture());

      // Four payload-amplification vectors
      const strArr250 = Array(250).fill('A'.repeat(500_000));
      const strDag2 = Array(10).fill(Array(200).fill('B'.repeat(100_000)));
      const binArr2000 = Array(2000).fill(new Uint8Array(65_536));
      const giantBigInt = 1n << 10_000_000n;

      const vectors = [
        ['strArr250', strArr250, true],
        ['strDag2', strDag2, true],
        ['binArr2000', binArr2000, false],
        ['giantBigInt', giantBigInt, false],
      ];

      const t0 = performance.now();

      for (const [label, vec, isJsonOverflow] of vectors) {
        // 1. IPCManager.send -> QuotaExceededError(EFBIG)
        assert.throws(
          () => ipc.send('ch.dag', 0, vec),
          (err) => isTypedQuota(err, ERROR_CODES.EFBIG),
          `IPCManager.send must reject ${label} with QuotaExceededError(EFBIG)`
        );

        // 2. SharedClipboard.set -> QuotaExceededError(EFBIG) on string DAGs, OmniOSError(EINVAL) on binary/BigInt JSON
        assert.throws(
          () => clip.set({ json: vec }),
          (err) => (isJsonOverflow ? isTypedQuota(err, ERROR_CODES.EFBIG) : isTypedEinval(err)),
          `SharedClipboard.set({json}) must reject ${label} cleanly`
        );

        // 3. NotificationCenter.post -> QuotaExceededError(EQUOTA)
        const notifsBefore = notif.list().length;
        assert.throws(
          () => notif.post({ appId: 'com.m2b.dag', title: `Dag-${label}`, data: vec }),
          (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
          `NotificationCenter.post must reject ${label} with QuotaExceededError(EQUOTA)`
        );
        assert.equal(notif.list().length, notifsBefore);

        // 4. IntentRouter.dispatch -> QuotaExceededError(EQUOTA)
        deliveredIntents.length = 0;
        assert.throws(
          () => router.dispatch({ action: 'view', uri: 'dag://test', extras: vec }),
          (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
          `IntentRouter.dispatch must reject ${label} with QuotaExceededError(EQUOTA)`
        );
        assert.equal(deliveredIntents.length, 0);

        // 5. Compositor createWindow / updateSurface / appendDrawOps -> QuotaExceededError(EQUOTA)
        const winsBefore = comp.listWindows().length;
        const revBefore = comp.getWindow(baseWin.windowId).surfaceRevision;
        assert.throws(
          () => comp.createWindow(proc.pid, { title: `Bad-${label}`, uiTree: vec }),
          (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
          `Compositor.createWindow({uiTree}) must reject ${label} with QuotaExceededError(EQUOTA)`
        );
        assert.equal(comp.listWindows().length, winsBefore);

        assert.throws(
          () => comp.updateSurface(baseWin.windowId, { uiTree: vec }),
          (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
          `Compositor.updateSurface({uiTree}) must reject ${label} with QuotaExceededError(EQUOTA)`
        );
        assert.throws(
          () => comp.updateSurface(baseWin.windowId, { appendDrawOps: [{ op: 'text', text: vec }] }),
          (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
          `Compositor.updateSurface({appendDrawOps}) must reject ${label} with QuotaExceededError(EQUOTA)`
        );
        assert.equal(comp.getWindow(baseWin.windowId).surfaceRevision, revBefore);

        // 6. PackageManager.launch({ intent }) -> QuotaExceededError(EQUOTA) with zero orphan PCBs
        const pcbsBefore = pm.list().length;
        await assert.rejects(
          () => pkg.launch('com.m2b.dag.uapp', { intent: { action: 'view', extras: vec } }),
          (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
          `PackageManager.launch({intent}) must reject ${label} with QuotaExceededError(EQUOTA)`
        );
        assert.equal(pm.list().length, pcbsBefore, `PackageManager.launch must leak 0 orphan PCBs on ${label}`);
      }
      assert.equal(ipc.listChannels().find((c) => c.name === 'ch.dag')?.queueSize, 0);

      // 7. Compositor uiTree 16^7 DAG -> QuotaExceededError(EQUOTA) atomically in BOTH createWindow() & updateSurface()
      const uiTreeDag16x7 = makeBranchingDag(7, 16);
      const winCountBefore = comp.listWindows().length;
      const pcbWinSlotsBefore = pm.get(proc.pid).windowIds.size;

      assert.throws(
        () => comp.createWindow(proc.pid, { title: 'UiTreeDagWin', uiTree: uiTreeDag16x7 }),
        (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
        'createWindow must reject 16^7 uiTree DAG with QuotaExceededError(EQUOTA)'
      );
      assert.equal(comp.listWindows().length, winCountBefore, 'createWindow rejection must leak 0 compositor windows');
      assert.equal(pm.get(proc.pid).windowIds.size, pcbWinSlotsBefore, 'createWindow rejection must leak 0 PCB window slots');

      const snapBefore = comp.getWindow(baseWin.windowId);
      assert.throws(
        () => comp.updateSurface(baseWin.windowId, { title: 'ShouldNotMutate', uiTree: uiTreeDag16x7 }),
        (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
        'updateSurface must reject 16^7 uiTree DAG with QuotaExceededError(EQUOTA)'
      );
      const snapAfter = comp.getWindow(baseWin.windowId);
      assert.equal(snapAfter.surfaceRevision, snapBefore.surfaceRevision, 'Failed updateSurface must not advance surfaceRevision');
      assert.equal(snapAfter.title, 'BaseWin', 'Failed updateSurface must not mutate title');
      assert.deepEqual(snapAfter.surface.uiTree, { type: 'root', children: [] }, 'Failed updateSurface must preserve existing uiTree');

      // 8. Cumulative appendDrawOps byte cap (MAX_SURFACE_BYTES = 2 MiB) enforced atomically across calls
      const drawWin = comp.createWindow(proc.pid, { title: 'AppendBytesWin' });
      const chunk400k = { op: 'text', text: 'D'.repeat(400_000) };
      let acceptedChunks = 0;
      let overflowThrown = false;
      for (let step = 0; step < 8; step += 1) {
        const beforeState = comp.getWindow(drawWin.windowId);
        try {
          comp.updateSurface(drawWin.windowId, { appendDrawOps: [chunk400k] });
          acceptedChunks += 1;
        } catch (err) {
          assert.ok(isTypedQuota(err, ERROR_CODES.EQUOTA), `Cumulative appendDrawOps overflow must throw QuotaExceededError(EQUOTA), got ${err}`);
          const afterFail = comp.getWindow(drawWin.windowId);
          assert.equal(afterFail.surface.drawOps.length, beforeState.surface.drawOps.length, 'Overflowing appendDrawOps must leave drawOps unchanged');
          assert.equal(afterFail.surfaceRevision, beforeState.surfaceRevision, 'Overflowing appendDrawOps must leave surfaceRevision unchanged');
          overflowThrown = true;
          break;
        }
      }
      assert.ok(acceptedChunks >= 4 && acceptedChunks <= 5, `Expected 4–5 accepted 400KB drawOps under 2 MiB cap, got ${acceptedChunks}`);
      assert.equal(overflowThrown, true, 'Cumulative appendDrawOps must enforce 2 MiB surface byte cap');

      const totalMs = performance.now() - t0;
      assert.ok(totalMs < 2000, `All M2B DAG byte-budget & uiTree quota checks must complete rapidly (<2000ms), got ${totalMs.toFixed(1)}ms`);
    } finally {
      ipc.stop();
      pkg.close();
      storage.close();
    }
  });
});

// ============================================================================
// SUITE 22: Iteration 10 Prompt Snapshot, O(1) Display/Coercion, Shared Multi-Field Budgets & Polish Regressions
// ============================================================================

describe('Suite 22: Iteration 10 Prompt Snapshot, O(1) Display/Coercion, Shared Multi-Field Budgets & Polish Regressions (P1-A..P2-A, P1-B..P6-B)', () => {
  function isTypedEinval(err) {
    return (
      err instanceof OmniOSError &&
      err.code === ERROR_CODES.EINVAL &&
      !(err instanceof TypeError) &&
      !(err instanceof SyntaxError) &&
      !(err instanceof RangeError)
    );
  }

  function isTypedQuota(err, expectedCode = ERROR_CODES.EQUOTA) {
    return (
      err instanceof QuotaExceededError &&
      err instanceof OmniOSError &&
      err.code === expectedCode &&
      !(err instanceof RangeError)
    );
  }

  function makeBinaryDag(leaf, levels) {
    let node = leaf;
    for (let i = 0; i < levels; i += 1) {
      node = [node, node];
    }
    return node;
  }

  function makeDepth31Bomb() {
    let node = Array(24_900).fill(Array(9).fill(1));
    for (let i = 0; i < 31; i += 1) {
      node = [node];
    }
    return node;
  }

  it('22.1 (P1-A + P2-A + M2A Polish): PermissionBroker PROMPT snapshot & TOCTOU immunity, O(1) safeDisplay/safeString/DevFsMount across all 6 M2A modules, mapNativePermissions budget, Obs-R1/Obs-R2/Obs-2', async () => {
    const storage = new SqliteStorage(':memory:');
    const eventBus = new KernelEventBus();
    const promptEvents = [];
    const handlerPayloads = [];
    eventBus.on('permission:prompt', (payload) => promptEvents.push(payload));

    const pb = new PermissionBroker({ storage, eventBus });
    pb.setPromptHandler((payload) => {
      handlerPayloads.push(payload);
      return 'pending';
    });

    const cfg = new UnifiedConfigStore({ storage, eventBus });
    const pt = new PathTranslator();
    const um = new UserManager({ storage });
    const vfs = new VFS({ storage, userManager: um });
    const devFs = new DevFsMount();

    const flushMicrotasks = async () => {
      await Promise.resolve();
      await Promise.resolve();
      await new Promise((resolve) => setImmediate(resolve));
    };

    const assertPromptSurfaceInvariants = (surface, label) => {
      assert.equal(typeof surface.createdAt, 'string', `${label}: createdAt must be a string`);
      assert.ok(!Number.isNaN(Date.parse(surface.createdAt)), `${label}: createdAt must be ISO-valid (${surface.createdAt})`);
      assert.equal(
        Object.hasOwn(surface, '__truncated__'),
        false,
        `${label}: top-level prompt envelope must NEVER have bogus __truncated__ property`
      );
    };

    try {
      // --- A. P1-A: PermissionBroker PROMPT flow across ALL FOUR surfaces ---
      // (a) Circular byte-exhausted context
      promptEvents.length = 0;
      handlerPayloads.length = 0;
      const circCtx = { big: Array(250).fill('A'.repeat(100_000)), self: null };
      circCtx.self = circCtx;
      const pCirc = pb.checkPermission({
        appId: 'com.p1a.circ',
        capability: CAPABILITIES.CAMERA_DEVICE,
        context: circCtx,
        timeoutMs: 5000,
      });
      await flushMicrotasks();

      const pendingCirc = pb.getPendingPrompts();
      assert.equal(pendingCirc.length, 1);
      assert.equal(promptEvents.length, 1);
      assert.equal(handlerPayloads.length, 1);

      const originalCreatedAt = pendingCirc[0].createdAt;
      for (const [label, surface] of [
        ['getPendingPrompts()[0]', pendingCirc[0]],
        ['permission:prompt', promptEvents[0]],
        ['promptHandler', handlerPayloads[0]],
      ]) {
        assertPromptSurfaceInvariants(surface, `circ:${label}`);
        assert.equal(surface.context.self, '[Circular]', `circ:${label} must preserve context.self === '[Circular]'`);
        assert.ok(JSON.stringify(surface.context).length < 150_000, `circ:${label} context must stay bounded`);
      }

      // Verify defensive copy isolation on getPendingPrompts()[0]
      pendingCirc[0].context.self = 'MUTATED_SELF';
      pendingCirc[0].context.injected = 'MUTATED_FIELD';
      pendingCirc[0].createdAt = 'MUTATED_TIME';
      const pendingCircReloaded = pb.getPendingPrompts();
      assert.equal(pendingCircReloaded[0].context.self, '[Circular]', 'Mutating returned pending prompt must not corrupt stored prompt');
      assert.equal(Object.hasOwn(pendingCircReloaded[0].context, 'injected'), false);
      assert.equal(pendingCircReloaded[0].createdAt, originalCreatedAt);

      pb.resolvePrompt(pendingCircReloaded[0].promptId, 'allow_once');
      const circRes = await pCirc;
      assert.equal(circRes.granted, true);
      const circAudit = pb.getAuditLog({ appId: 'com.p1a.circ', limit: 5 })[0];
      assert.equal(typeof circAudit.ts, 'string');
      assert.ok(!Number.isNaN(Date.parse(circAudit.ts)));
      assert.equal(Object.hasOwn(circAudit, '__truncated__'), false);
      assert.equal(circAudit.context.self, '[Circular]', 'Persisted audit row must preserve context.self === "[Circular]"');

      // (b1) Legitimate ~65 KB array context (16 x 4096 chars)
      promptEvents.length = 0;
      handlerPayloads.length = 0;
      const legitArrCtx = Array.from({ length: 16 }, (_, i) => String(i).padStart(4, '0') + 'a'.repeat(4080));
      const pLegitArr = pb.checkPermission({
        appId: 'com.p1a.legit.arr',
        capability: CAPABILITIES.CAMERA_DEVICE,
        context: legitArrCtx,
        timeoutMs: 5000,
      });
      await flushMicrotasks();

      const pendingLegitArr = pb.getPendingPrompts();
      assert.equal(pendingLegitArr.length, 1);
      assert.equal(promptEvents.length, 1);
      assert.equal(handlerPayloads.length, 1);
      for (const [label, surface] of [
        ['getPendingPrompts()[0]', pendingLegitArr[0]],
        ['permission:prompt', promptEvents[0]],
        ['promptHandler', handlerPayloads[0]],
      ]) {
        assertPromptSurfaceInvariants(surface, `legitArr:${label}`);
        assert.ok(Array.isArray(surface.context));
        assert.equal(surface.context[0], legitArrCtx[0]);
      }
      pb.resolvePrompt(pendingLegitArr[0].promptId, 'allow_once');
      await pLegitArr;
      const legitArrAudit = pb.getAuditLog({ appId: 'com.p1a.legit.arr', limit: 5 })[0];
      assert.equal(typeof legitArrAudit.ts, 'string');
      assert.ok(!Number.isNaN(Date.parse(legitArrAudit.ts)));
      assert.equal(Object.hasOwn(legitArrAudit, '__truncated__'), false);
      assert.ok(Array.isArray(legitArrAudit.context));
      assert.equal(legitArrAudit.context[0], legitArrCtx[0]);

      // (b2) Legitimate ~65 KB object context (16 x 4096 chars)
      promptEvents.length = 0;
      handlerPayloads.length = 0;
      const legitObjCtx = Object.fromEntries(Array.from({ length: 16 }, (_, i) => [`k${i}`, 'B'.repeat(4096)]));
      const pLegitObj = pb.checkPermission({
        appId: 'com.p1a.legit.obj',
        capability: CAPABILITIES.CAMERA_DEVICE,
        context: legitObjCtx,
        timeoutMs: 5000,
      });
      await flushMicrotasks();

      const pendingLegitObj = pb.getPendingPrompts();
      assert.equal(pendingLegitObj.length, 1);
      assert.equal(promptEvents.length, 1);
      assert.equal(handlerPayloads.length, 1);
      for (const [label, surface] of [
        ['getPendingPrompts()[0]', pendingLegitObj[0]],
        ['permission:prompt', promptEvents[0]],
        ['promptHandler', handlerPayloads[0]],
      ]) {
        assertPromptSurfaceInvariants(surface, `legitObj:${label}`);
        assert.equal(surface.context.k0, 'B'.repeat(4096));
      }
      pb.resolvePrompt(pendingLegitObj[0].promptId, 'allow_once');
      await pLegitObj;
      const legitObjAudit = pb.getAuditLog({ appId: 'com.p1a.legit.obj', limit: 5 })[0];
      assert.equal(typeof legitObjAudit.ts, 'string');
      assert.ok(!Number.isNaN(Date.parse(legitObjAudit.ts)));
      assert.equal(Object.hasOwn(legitObjAudit, '__truncated__'), false);
      assert.equal(legitObjAudit.context.k0, 'B'.repeat(4096));

      // (c) Valid depth-7 nested context (zero depth shrinkage to '[MaxDepth]')
      promptEvents.length = 0;
      handlerPayloads.length = 0;
      const depth7Ctx = { d1: { d2: { d3: { d4: { d5: { d6: { d7: { leaf: 'depth-7-intact' } } } } } } } };
      const pDepth7 = pb.checkPermission({
        appId: 'com.p1a.depth7',
        capability: CAPABILITIES.CAMERA_DEVICE,
        context: depth7Ctx,
        timeoutMs: 5000,
      });
      await flushMicrotasks();

      const pendingDepth7 = pb.getPendingPrompts();
      assert.equal(pendingDepth7.length, 1);
      assert.equal(promptEvents.length, 1);
      assert.equal(handlerPayloads.length, 1);
      for (const [label, surface] of [
        ['getPendingPrompts()[0]', pendingDepth7[0]],
        ['permission:prompt', promptEvents[0]],
        ['promptHandler', handlerPayloads[0]],
      ]) {
        assertPromptSurfaceInvariants(surface, `depth7:${label}`);
        assert.equal(
          surface.context.d1.d2.d3.d4.d5.d6.d7.leaf,
          'depth-7-intact',
          `depth7:${label} must NOT shrink valid depth-7 object to '[MaxDepth]'`
        );
      }
      pb.resolvePrompt(pendingDepth7[0].promptId, 'allow_once');
      await pDepth7;
      const depth7Audit = pb.getAuditLog({ appId: 'com.p1a.depth7', limit: 5 })[0];
      assert.equal(typeof depth7Audit.ts, 'string');
      assert.ok(!Number.isNaN(Date.parse(depth7Audit.ts)));
      assert.equal(Object.hasOwn(depth7Audit, '__truncated__'), false);
      assert.equal(depth7Audit.context.d1.d2.d3.d4.d5.d6.d7.leaf, 'depth-7-intact');

      // (d) Post-call mutation of caller's context BEFORE resolvePrompt() -> audit TOCTOU immunity
      promptEvents.length = 0;
      handlerPayloads.length = 0;
      const toctouCtx = { scope: 'photo-only', nested: { safe: true } };
      const pToctou = pb.checkPermission({
        appId: 'com.p1a.toctou',
        capability: CAPABILITIES.CAMERA_DEVICE,
        context: toctouCtx,
        timeoutMs: 5000,
      });
      // Mutate caller's object immediately after calling checkPermission and BEFORE promptHandler/resolvePrompt!
      toctouCtx.scope = 'EVIL-BACKGROUND-SURVEILLANCE';
      toctouCtx.nested.safe = false;
      toctouCtx.tampered = true;

      await flushMicrotasks();
      const pendingToctou = pb.getPendingPrompts();
      assert.equal(pendingToctou.length, 1);
      assert.equal(promptEvents.length, 1);
      assert.equal(handlerPayloads.length, 1);
      for (const [label, surface] of [
        ['getPendingPrompts()[0]', pendingToctou[0]],
        ['permission:prompt', promptEvents[0]],
        ['promptHandler', handlerPayloads[0]],
      ]) {
        assertPromptSurfaceInvariants(surface, `toctou:${label}`);
        assert.deepEqual(surface.context, { scope: 'photo-only', nested: { safe: true } });
      }
      pb.resolvePrompt(pendingToctou[0].promptId, 'allow_once');
      await pToctou;
      const toctouAudit = pb.getAuditLog({ appId: 'com.p1a.toctou', limit: 5 })[0];
      assert.equal(typeof toctouAudit.ts, 'string');
      assert.ok(!Number.isNaN(Date.parse(toctouAudit.ts)));
      assert.equal(Object.hasOwn(toctouAudit, '__truncated__'), false);
      assert.deepEqual(
        toctouAudit.context,
        { scope: 'photo-only', nested: { safe: true } },
        'Persisted audit row MUST match pre-mutation snapshot (TOCTOU immune)'
      );

      // --- B. P2-A: O(1) safeDisplay / safeString / DevFsMount across ALL 6 M2A modules ---
      const dag15 = makeBinaryDag('A'.repeat(4096), 15);
      const dag26 = makeBinaryDag('A', 26);
      const hugeBigInt = 1n << 50_000_000n;
      let toStringCalls = 0;
      const spyObj = {
        toString() {
          toStringCalls += 1;
          return 'bad';
        },
        [Symbol.toPrimitive]() {
          toStringCalls += 1;
          return 'bad';
        },
      };

      const p2aVectors = [
        ['dag15', dag15],
        ['dag26', dag26],
        ['hugeBigInt', hugeBigInt],
        ['spyObj', spyObj],
      ];

      const tP2a0 = performance.now();
      for (const [label, bad] of p2aVectors) {
        // 1. PermissionBroker
        const capRes = await pb.checkPermission({ appId: 'com.p2a.pb', capability: bad });
        assert.equal(capRes.granted, false, `PermissionBroker.checkPermission(capability:${label}) must deny`);
        assert.ok(String(capRes.capability).length < 1024);

        const nativeRes = await pb.checkPermission({ appId: 'com.p2a.pb', nativePermission: bad });
        assert.equal(nativeRes.granted, false, `PermissionBroker.checkPermission(nativePermission:${label}) must deny`);
        assert.ok(String(nativeRes.nativePermission).length < 1024);

        assert.throws(
          () => pb.setGrant('com.p2a.pb', bad, 'allow'),
          (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL && err.message.length < 1024,
          `PermissionBroker.setGrant(${label}) must throw bounded SecurityError(EINVAL)`
        );
        pb.cancelAllPendingPrompts(bad);

        // 2. UnifiedConfigStore
        assert.throws(
          () => cfg.registry.getValue(bad, 'Software', 'v'),
          (err) => isTypedEinval(err) && err.message.length < 1024,
          `UnifiedConfigStore.registry.getValue(${label}) must throw bounded EINVAL`
        );
        assert.throws(
          () => cfg.registry.setValue('HKCU', 'Software\\P2A', 'v', bad, 'x'),
          (err) => isTypedEinval(err) && err.message.length < 1024,
          `UnifiedConfigStore.registry.setValue(${label}) must throw bounded EINVAL`
        );
        assert.throws(
          () => cfg.sharedPrefs.edit('com.p2a', 'prefs', [{ op: 'put', key: 'k', type: bad, value: 1 }]),
          (err) => isTypedEinval(err) && err.message.length < 1024,
          `UnifiedConfigStore.sharedPrefs.edit(${label}) must throw bounded EINVAL`
        );

        // 3. PathTranslator
        assert.throws(
          () => pt.toCanonical(bad),
          (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL && err.message.length < 1024,
          `PathTranslator.toCanonical(${label}) must throw bounded VfsError(EINVAL)`
        );
        assert.throws(
          () => pt.toCanonical('/a', { platform: bad }),
          (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL && err.message.length < 1024,
          `PathTranslator.toCanonical(platform:${label}) must throw bounded VfsError(EINVAL)`
        );

        // 4. VFS
        assert.throws(
          () => vfs.stat(bad),
          (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL && err.message.length < 1024,
          `VFS.stat(${label}) must throw bounded VfsError(EINVAL)`
        );
        assert.throws(
          () => vfs.chmod('/home/user', bad),
          (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL && err.message.length < 1024,
          `VFS.chmod(${label}) must throw bounded VfsError(EINVAL)`
        );

        // 5. UserManager
        assert.throws(
          () => um.createUser({ username: `u_p2a_${label}`, sandboxRoot: bad }),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL && err.message.length < 1024,
          `UserManager.createUser(sandboxRoot:${label}) must throw bounded EINVAL`
        );

        // 6. DevFsMount
        assert.throws(
          () => devFs.readDevice(bad),
          (err) => err instanceof VfsError && err.code === ERROR_CODES.ENOENT && err.message.length < 1024,
          `DevFsMount.readDevice(name:${label}) must throw bounded VfsError(ENOENT)`
        );
        assert.throws(
          () => devFs.readDevice('zero', bad),
          (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL && err.message.length < 1024,
          `DevFsMount.readDevice(length:${label}) must throw bounded VfsError(EINVAL)`
        );
        assert.throws(
          () => devFs.writeDevice(bad, new Uint8Array(1)),
          (err) => err instanceof VfsError && err.code === ERROR_CODES.ENOENT && err.message.length < 1024,
          `DevFsMount.writeDevice(${label}) must throw bounded VfsError(ENOENT)`
        );
      }

      // 50 MB capability / nativePermission audit cap
      const huge50mCap = 'X'.repeat(50_000_000);
      const huge50mNative = 'Y'.repeat(50_000_000);
      const bigStrRes1 = await pb.checkPermission({
        appId: 'com.p2a.big50m',
        capability: huge50mCap,
        nativePermission: huge50mNative,
      });
      assert.equal(bigStrRes1.granted, false);
      assert.ok(bigStrRes1.capability.length < 1024 && bigStrRes1.capability.includes('...[Truncated]'));
      assert.ok(bigStrRes1.nativePermission.length < 1024 && bigStrRes1.nativePermission.includes('...[Truncated]'));

      const bigStrRes2 = await pb.checkPermission({
        appId: 'com.p2a.big50m.native',
        nativePermission: huge50mNative,
      });
      assert.equal(bigStrRes2.granted, false);
      assert.ok(bigStrRes2.nativePermission.length < 1024 && bigStrRes2.nativePermission.includes('...[Truncated]'));

      const bigAuditRows = pb.getAuditLog({ appId: 'com.p2a.big50m', limit: 5 });
      assert.equal(bigAuditRows.length, 1);
      assert.ok(bigAuditRows[0].capability.length < 1024);
      assert.ok(bigAuditRows[0].nativePermission.length < 1024);

      const p2aSweepMs = performance.now() - tP2a0;
      assert.equal(toStringCalls, 0, 'O(1) safeDisplay/safeString/DevFsMount MUST NEVER invoke toString/Symbol.toPrimitive on objects');
      assert.ok(p2aSweepMs < 1000, `6-module P2-A sweep + 50 MB audit cap must complete rapidly (<1000ms), got ${p2aSweepMs.toFixed(1)}ms`);

      // mapNativePermissions array amplification & pre-.trim() amplification -> O(1) without OOM
      const s10K = 'A'.repeat(10_000);
      const tMap0 = performance.now();
      assert.throws(
        () => mapNativePermissions(Array(65536).fill([s10K, s10K, s10K])),
        (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL,
        'mapNativePermissions nested array amplification must throw SecurityError(EINVAL)'
      );
      assert.throws(
        () => mapNativePermissions(Array(65536).fill(` ${s10K} `)),
        (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL,
        'mapNativePermissions pre-trim string amplification must throw SecurityError(EINVAL)'
      );
      const mapAmpMs = performance.now() - tMap0;
      assert.ok(mapAmpMs < 500, `mapNativePermissions amplification checks must reject rapidly (<500ms), got ${mapAmpMs.toFixed(1)}ms`);

      // Valid Android / iOS / macOS / Windows permissions still map cleanly
      const validMapped = mapNativePermissions([
        'android.permission.CAMERA',
        'NSCameraUsageDescription',
        'com.apple.security.network.client',
        'internetClient',
        'requireAdministrator',
      ]);
      assert.equal(validMapped.unmapped.length, 0);
      assert.ok(validMapped.capabilities.includes(CAPABILITIES.CAMERA_DEVICE));
      assert.ok(validMapped.capabilities.includes(CAPABILITIES.NETWORK_OUTBOUND));
      assert.ok(validMapped.capabilities.includes(CAPABILITIES.REGISTRY_SYSTEM_WRITE));
      assert.ok(validMapped.capabilities.includes(CAPABILITIES.FS_WRITE_SYSTEM));

      // --- C. M2A Polish: Obs-R1, Obs-R2/Obs-1, Obs-2 ---
      // Obs-R1: Exact RFC 4648 base64 length accounting in UnifiedConfigStore.defaults
      assert.throws(
        () => cfg.defaults.set('com.obs.r1', 'exactB64', [new Uint8Array(3_145_714), new Uint8Array(1), '']),
        (err) => isTypedEinval(err),
        'Obs-R1 boundary base64 payload must reject cleanly with OmniOSError(EINVAL)'
      );
      assert.equal(cfg.defaults.get('com.obs.r1', 'exactB64'), null, 'Rejected Obs-R1 write must roll back with no persisted row');

      // Obs-R2 / Obs-1: ProcFsMount with NaN & Infinity startedAt -> finite ISO timestamps, never RangeError
      const badTsPcbs = [
        { pid: 9001, name: 'nan-proc', state: 'RUNNING', uid: 1000, gid: 1000, stats: { startedAt: Number.NaN } },
        { pid: 9002, name: 'inf-proc', state: 'RUNNING', uid: 1000, gid: 1000, stats: { startedAt: Number.POSITIVE_INFINITY } },
      ];
      const badTsPm = {
        get(pid) {
          return badTsPcbs.find((p) => p.pid === pid) ?? null;
        },
        list() {
          return badTsPcbs;
        },
      };
      const procVm = new VirtualMountManager({ processManager: badTsPm });
      const procVfsStorage = new SqliteStorage(':memory:');
      const procVfs = new VFS({ storage: procVfsStorage, virtualMounts: procVm });
      try {
        for (const pid of [9001, 9002]) {
          const dirStat = procVfs.stat(`/proc/${pid}`);
          assert.equal(typeof dirStat.birthtime, 'string');
          assert.ok(!Number.isNaN(Date.parse(dirStat.birthtime)), `stat(/proc/${pid}) birthtime must be valid ISO`);
          assert.ok(Number.isFinite(dirStat.mtimeMs));

          const fileStat = procVfs.stat(`/proc/${pid}/status`);
          assert.equal(typeof fileStat.birthtime, 'string');
          assert.ok(!Number.isNaN(Date.parse(fileStat.birthtime)), `stat(/proc/${pid}/status) birthtime must be valid ISO`);
          assert.ok(Number.isFinite(fileStat.mtimeMs));

          const entries = procVfs.readdir(`/proc/${pid}`);
          assert.ok(entries.length >= 4);
          for (const ent of entries) {
            assert.equal(typeof ent.mtime, 'string');
            assert.ok(!Number.isNaN(Date.parse(ent.mtime)));
            assert.equal(typeof ent.ctime, 'string');
            assert.ok(!Number.isNaN(Date.parse(ent.ctime)));
          }
        }
      } finally {
        procVfs.close();
        procVfsStorage.close();
      }

      // Obs-2: PathTranslator length check BEFORE control-char regex + bounded err.path.length <= 128
      assert.throws(
        () => pt.toCanonical(`${'a'.repeat(5000)}\x00`),
        (err) =>
          err instanceof VfsError &&
          (err.code === ERROR_CODES.ENAMETOOLONG || err.code === ERROR_CODES.EINVAL) &&
          /maximum length/i.test(err.message) &&
          typeof err.path === 'string' &&
          err.path.length <= 128,
        'Obs-2 oversized path with NUL must trigger bounded length check first with err.path.length <= 128'
      );
    } finally {
      vfs.close();
      um.close();
      cfg.close();
      pb.close();
      storage.close();
    }
  });

  it('22.2 (P1-B + P4-B): NotificationCenter shared action/liveActivity budgets & sequential updateLiveActivity cap + IntentRouter cumulative manifest caps across all paths & replace:false merges', () => {
    const bus = new KernelEventBus();
    const notif = new NotificationCenter({ eventBus: bus });
    const router = new IntentRouter({ eventBus: bus });

    // --- A. P1-B: NotificationCenter ---
    const tNotif0 = performance.now();

    // 1. 1,000 actions sharing Uint8Array(100_000) -> QuotaExceededError(EQUOTA), 0 persisted notifications
    const sharedU8 = new Uint8Array(100_000);
    const actions1000 = Array.from({ length: 1000 }, (_, i) => ({
      id: `act-${i}`,
      label: 'Run',
      payload: sharedU8,
    }));
    assert.throws(
      () => notif.post({ appId: 'com.p1b.act', title: 'ActionBomb', actions: actions1000 }),
      (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
      '1,000 actions sharing Uint8Array(100_000) must throw QuotaExceededError(EQUOTA)'
    );
    assert.equal(notif.list().length, 0);
    assert.equal(notif.getLiveActivities().length, 0);

    // 2. data + 6 liveActivity fields sharing empty [] bomb, Uint8Array(0) bomb, and depth-31/32 24,900x9 array
    const emptyArrBomb = [Array(100_000).fill([]), Array(100_000).fill([])];
    const emptyU8Bomb = [Array(100_000).fill(new Uint8Array(0)), Array(100_000).fill(new Uint8Array(0))];
    const depth32Bomb = makeDepth31Bomb();

    for (const [label, bomb] of [
      ['emptyArrBomb', emptyArrBomb],
      ['emptyU8Bomb', emptyU8Bomb],
      ['depth32Bomb', depth32Bomb],
    ]) {
      assert.throws(
        () =>
          notif.post({
            appId: 'com.p1b.la',
            title: `LA-${label}`,
            data: bomb,
            liveActivity: {
              title: `Live-${label}`,
              compactLeading: bomb,
              compactTrailing: bomb,
              expandedBody: bomb,
              icon: bomb,
              payload: bomb,
              data: bomb,
            },
          }),
        (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
        `NotificationCenter.post 7-field ${label} must throw QuotaExceededError(EQUOTA)`
      );
      assert.equal(notif.list().length, 0, `${label} must leave 0 persisted notifications`);
      assert.equal(notif.getLiveActivities().length, 0, `${label} must leave 0 persisted live activities`);
    }

    // 3. Sequential updateLiveActivity() exceeding cumulative 2 MiB across untouched + patched fields
    const validPosted = notif.post({
      appId: 'com.p1b.seq',
      title: 'SeqLA',
      liveActivity: {
        title: 'InitialLA',
        compactLeading: { text: 'L'.repeat(1_300_000) },
      },
    });
    const laId = validPosted.liveActivity.id;
    const updated1 = notif.updateLiveActivity(laId, {
      compactTrailing: { text: 'T'.repeat(400_000) },
    });
    assert.equal(updated1.compactTrailing.text.length, 400_000);

    const beforeOverflow = notif.getLiveActivities().find((a) => a.id === laId);
    assert.throws(
      () =>
        notif.updateLiveActivity(laId, {
          title: 'MustNotCommit',
          expandedBody: { text: 'E'.repeat(600_000) },
        }),
      (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
      'Sequential updateLiveActivity exceeding cumulative 2 MiB must throw QuotaExceededError(EQUOTA)'
    );
    const afterOverflow = notif.getLiveActivities().find((a) => a.id === laId);
    assert.equal(afterOverflow.title, beforeOverflow.title);
    assert.equal(afterOverflow.compactLeading.text.length, 1_300_000);
    assert.equal(afterOverflow.compactTrailing.text.length, 400_000);
    assert.equal(afterOverflow.expandedBody, beforeOverflow.expandedBody);

    const notifMs = performance.now() - tNotif0;
    assert.ok(notifMs < 1500, `P1-B notification quota checks must finish rapidly (<1500ms), got ${notifMs.toFixed(1)}ms`);

    // --- B. P4-B: IntentRouter cumulative manifest caps ---
    const tRouter0 = performance.now();

    // Seed an existing valid registration on 'com.p4b.existing' to prove zero mutation on failed manifests
    router.registerHandlers('com.p4b.existing', [{ actions: ['view'], schemes: ['keepme'] }]);
    const baselineSnapshot = router.listHandlers('com.p4b.existing');
    assert.equal(baselineSnapshot.length, 1);

    const hostileManifests = [
      [
        'intentFilters x data (10k x 10k)',
        { intentFilters: Array(10_000).fill({ actions: ['view'], data: Array(10_000).fill({ scheme: 'https' }) }) },
      ],
      [
        'CFBundleDocumentTypes (5k x 5k)',
        { CFBundleDocumentTypes: Array(5_000).fill({ CFBundleTypeExtensions: Array(5_000).fill('txt') }) },
      ],
      [
        'flat handlers (10k x 1k)',
        Array(10_000).fill({ actions: Array(1_000).fill('view') }),
      ],
      [
        'fileAssociations (5k x 1k)',
        { fileAssociations: Array(5_000).fill({ extensions: Array(1_000).fill('.doc') }) },
      ],
      [
        'urlSchemes (5k x 1k)',
        { urlSchemes: Array(5_000).fill({ schemes: Array(1_000).fill('omnischeme') }) },
      ],
      [
        'nested handlers (5k x 1k)',
        { handlers: Array(5_000).fill({ actions: Array(1_000).fill('edit') }) },
      ],
    ];

    for (const [label, manifest] of hostileManifests) {
      assert.throws(
        () => router.registerHandlers('com.p4b.evil', manifest),
        (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
        `IntentRouter.registerHandlers(${label}) must throw QuotaExceededError(EQUOTA)`
      );
      assert.equal(router.listHandlers('com.p4b.evil').length, 0, `${label} must leak 0 handler registrations`);

      // Also verify attempting to replace an existing app's handlers leaves it untouched
      assert.throws(
        () => router.registerHandlers('com.p4b.existing', manifest, { replace: true }),
        (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
        `IntentRouter.registerHandlers(replace:true, ${label}) must throw QuotaExceededError(EQUOTA)`
      );
      assert.deepEqual(router.listHandlers('com.p4b.existing'), baselineSnapshot);
    }

    // Repeated replace:false merges exceeding MAX_MANIFEST_DESCRIPTORS (1024)
    for (let batch = 0; batch < 10; batch += 1) {
      const descriptors = Array.from({ length: 100 }, (_, i) => ({
        actions: ['view'],
        schemes: [`m${batch}x${i}`],
      }));
      router.registerHandlers('com.p4b.merge', descriptors, { replace: false });
    }
    assert.equal(router.listHandlers('com.p4b.merge')[0].handlers.length, 1000);

    const overflowBatch = Array.from({ length: 100 }, (_, i) => ({
      actions: ['view'],
      schemes: [`overflow${i}`],
    }));
    assert.throws(
      () => router.registerHandlers('com.p4b.merge', overflowBatch, { replace: false }),
      (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
      'Repeated replace:false merges exceeding MAX_MANIFEST_DESCRIPTORS must throw QuotaExceededError(EQUOTA)'
    );
    assert.equal(
      router.listHandlers('com.p4b.merge')[0].handlers.length,
      1000,
      'Failed replace:false merge must preserve existing 1000 handlers atomically'
    );

    const routerMs = performance.now() - tRouter0;
    assert.ok(routerMs < 1500, `P4-B router manifest quota checks must finish rapidly (<1500ms), got ${routerMs.toFixed(1)}ms`);
  });

  it('22.3 (P2-B + P3-B): PackageManager launch() & inspect() shared budgets with 0 orphan PCBs + Compositor 4-field/icon/cross-field cumulative 2 MiB surface budget', async () => {
    const storage = new SqliteStorage(':memory:');
    const bus = new KernelEventBus();
    const pm = new ProcessManager({ eventBus: bus });
    const pkg = new PackageManager({ storage, processManager: pm });
    const comp = new Compositor({ eventBus: bus, processManager: pm });

    try {
      const uapp = buildUappFixture();
      let inspectPayload = {
        format: PACKAGE_FORMATS.UNIVERSAL_UAPP,
        platform: 'universal',
        arch: 'wasm',
        appId: 'com.p2b.uapp',
        name: 'P2B App',
        version: '1.0.0',
        permissions: [],
        intents: [],
      };
      pkg.registerRuntime('universal', {
        platform: 'universal',
        inspectPackage() {
          return inspectPayload;
        },
        createExecutionContext() {
          return makeWorkExecContext();
        },
      });
      await pkg.install(uapp);

      const t0 = performance.now();

      // --- A. P2-B: PackageManager.launch() ---
      const pcbsBefore = pm.list().length;

      // 1. 31 keys x 100,000 Uint8Array(0)
      const u0 = new Uint8Array(0);
      const intentU0 = { extras: {} };
      for (let i = 0; i < 31; i += 1) {
        intentU0[`k${i}`] = Array(100_000).fill(u0);
      }
      await assert.rejects(
        () => pkg.launch('com.p2b.uapp', { intent: intentU0 }),
        (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
        'PackageManager.launch with 31 keys x 100k Uint8Array(0) must reject with QuotaExceededError(EQUOTA)'
      );
      assert.equal(pm.list().length, pcbsBefore, 'Failed launch(Uint8Array(0) bomb) must leak 0 orphan PCBs');

      // 2. 32 keys x depth-31/32 24,900 x 9 array
      const d32 = makeDepth31Bomb();
      const intentD32 = { extras: d32 };
      for (let i = 0; i < 31; i += 1) {
        intentD32[`k${i}`] = d32;
      }
      await assert.rejects(
        () => pkg.launch('com.p2b.uapp', { intent: intentD32 }),
        (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
        'PackageManager.launch with 32 keys x depth-31/32 bomb must reject with QuotaExceededError(EQUOTA)'
      );
      assert.equal(pm.list().length, pcbsBefore, 'Failed launch(depth-32 bomb) must leak 0 orphan PCBs');

      // 3. PackageManager.inspect() where runtime returns 249,000 {} across all 5 runtime fields
      const emptyObj = {};
      const arr249k = [Array(100_000).fill(emptyObj), Array(100_000).fill(emptyObj), Array(49_000).fill(emptyObj)];
      inspectPayload = {
        format: PACKAGE_FORMATS.UNIVERSAL_UAPP,
        platform: 'universal',
        arch: 'wasm',
        appId: 'com.p2b.biginspect',
        name: 'BigInspect',
        version: '1.0.0',
        permissions: arr249k,
        intents: arr249k,
        sectionsOrClasses: arr249k,
        importsOrMethods: arr249k,
        rawMetadata: { a: arr249k },
      };
      await assert.rejects(
        () => pkg.inspect(uapp),
        (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
        'PackageManager.inspect with 5 fields x 249k {} must reject with QuotaExceededError(EQUOTA)'
      );

      // --- B. P3-B: Compositor ---
      const proc = pm.spawn({
        name: 'p3b-proc',
        appId: 'com.p3b.app',
        platform: 'universal',
        executionContext: makeWorkExecContext(),
      });

      const winsBefore = comp.listWindows().length;
      const pcbSlotsBefore = pm.get(proc.pid).windowIds.size;

      // 1. createWindow() with 4 fields sharing 198,000 {}
      const obj198k = [Array(99_000).fill(emptyObj), Array(99_000).fill(emptyObj)];
      assert.throws(
        () =>
          comp.createWindow(proc.pid, {
            title: 'FourFieldBomb',
            menuBar: [obj198k],
            drawOps: [obj198k],
            uiTree: obj198k,
            icon: obj198k,
          }),
        (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
        'Compositor.createWindow with 4 fields sharing 198k {} must throw QuotaExceededError(EQUOTA)'
      );
      assert.equal(comp.listWindows().length, winsBefore, '4-field bomb must leak 0 windows');
      assert.equal(pm.get(proc.pid).windowIds.size, pcbSlotsBefore, '4-field bomb must leak 0 PCB window slots');

      // 2. createWindow() with oversized icon (> 65 KB)
      assert.throws(
        () =>
          comp.createWindow(proc.pid, {
            title: 'BigIconWin',
            icon: { svg: 'I'.repeat(70_000) },
          }),
        (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
        'Compositor.createWindow with icon > 65 KB must throw QuotaExceededError(EQUOTA)'
      );
      assert.equal(comp.listWindows().length, winsBefore, 'Oversized icon must leak 0 windows');
      assert.equal(pm.get(proc.pid).windowIds.size, pcbSlotsBefore, 'Oversized icon must leak 0 PCB window slots');

      // 3. Cross-field cumulative MAX_SURFACE_BYTES (2 MiB): valid 1.4 MiB uiTree + 1.0 MiB drawOps / menuBar
      const win = comp.createWindow(proc.pid, {
        title: 'CrossFieldWin',
        uiTree: { type: 'root', content: 'U'.repeat(1_400_000) },
        drawOps: [{ op: 'clear', color: '#111' }],
      });
      const snapBefore = comp.getWindow(win.windowId);

      assert.throws(
        () =>
          comp.updateSurface(win.windowId, {
            title: 'ShouldNotCommitDrawOps',
            drawOps: [{ op: 'text', text: 'D'.repeat(1_000_000) }],
          }),
        (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
        'updateSurface adding 1.0 MiB drawOps to 1.4 MiB uiTree must throw QuotaExceededError(EQUOTA)'
      );
      const snapAfterDraw = comp.getWindow(win.windowId);
      assert.equal(snapAfterDraw.surfaceRevision, snapBefore.surfaceRevision);
      assert.equal(snapAfterDraw.title, 'CrossFieldWin');
      assert.equal(snapAfterDraw.surface.uiTree.content.length, 1_400_000);
      assert.deepEqual(snapAfterDraw.surface.drawOps, [{ op: 'clear', color: '#111' }]);

      assert.throws(
        () =>
          comp.updateSurface(win.windowId, {
            title: 'ShouldNotCommitMenuBar',
            menuBar: [{ label: 'M'.repeat(1_000_000) }],
          }),
        (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
        'updateSurface adding 1.0 MiB menuBar to 1.4 MiB uiTree must throw QuotaExceededError(EQUOTA)'
      );
      const snapAfterMenu = comp.getWindow(win.windowId);
      assert.equal(snapAfterMenu.surfaceRevision, snapBefore.surfaceRevision);
      assert.equal(snapAfterMenu.title, 'CrossFieldWin');
      assert.equal(snapAfterMenu.surface.uiTree.content.length, 1_400_000);
      assert.deepEqual(snapAfterMenu.surface.drawOps, [{ op: 'clear', color: '#111' }]);

      const totalMs = performance.now() - t0;
      assert.ok(totalMs < 2000, `P2-B + P3-B quota regressions must complete rapidly (<2000ms), got ${totalMs.toFixed(1)}ms`);
    } finally {
      pkg.close();
      storage.close();
    }
  });

  it('22.4 (P5-B + P6-B + M2B Minor Polish): SharedClipboard early-abort pre-base64 quota, cross-cutting M2B O(1) BigInt + dag15/dag26 guards across all 7 modules, IPC boundary & zip.mjs giant comment', async () => {
    const storage = new SqliteStorage(':memory:');
    const bus = new KernelEventBus();
    const pm = new ProcessManager({ eventBus: bus });
    const ipc = new IPCManager({ eventBus: bus, processManager: pm });
    const clip = new SharedClipboard({ eventBus: bus });
    const router = new IntentRouter({ eventBus: bus, processManager: pm });
    const notif = new NotificationCenter({ eventBus: bus, processManager: pm });
    const comp = new Compositor({ eventBus: bus, processManager: pm });
    const pkg = new PackageManager({ storage, processManager: pm });

    try {
      const proc = pm.spawn({
        name: 'p6b-proc',
        appId: 'com.p6b.app',
        platform: 'universal',
        executionContext: makeWorkExecContext(),
      });

      // --- A. P5-B: SharedClipboard pre-base64 cumulative cap ---
      const raw3m = new Uint8Array(3 * 1024 * 1024 + 256);
      const formats128 = {};
      for (let i = 0; i < 128; i += 1) {
        formats128[`application/x-bin-${i}`] = raw3m.subarray(i, i + 3 * 1024 * 1024);
      }

      const tClip0 = performance.now();
      let clipErr = null;
      try {
        clip.set({ formats: formats128 });
      } catch (err) {
        clipErr = err;
      }
      const clipMs = performance.now() - tClip0;
      assert.ok(isTypedQuota(clipErr, ERROR_CODES.EFBIG), `Expected QuotaExceededError(EFBIG), got ${clipErr}`);
      assert.ok(
        clipErr.actual <= 9 * 1024 * 1024,
        `SharedClipboard must abort early on format #2 (actual <= 9 MiB), got ${clipErr.actual}`
      );
      assert.ok(clipMs < 200, `SharedClipboard early-abort must complete rapidly (<200ms), got ${clipMs.toFixed(1)}ms`);
      assert.equal(clip.get(), null, 'Rejected clipboard.set must not mutate clipboard state');

      // Overwriting an existing normalized MIME key within quota succeeds cleanly
      const raw2_5m = new Uint8Array(2_500_000);
      const overwrittenBin = clip.set({
        formats: {
          'application/x-overwrite': raw2_5m,
          'APPLICATION/X-OVERWRITE': new Uint8Array([1, 2, 3, 4]),
        },
      });
      assert.equal(overwrittenBin.formats['application/x-overwrite'], Buffer.from([1, 2, 3, 4]).toString('base64'));

      const overwrittenText = clip.set({
        formats: { 'text/plain': 'A'.repeat(2_500_000) },
        text: 'B'.repeat(2_500_000),
      });
      assert.equal(overwrittenText.text.length, 2_500_000);
      assert.ok(overwrittenText.text.startsWith('BBBB'));

      // --- B. P6-B: Cross-cutting O(1) BigInt + dag15/dag26 guard across ALL 7 M2B modules ---
      const hugeBigInt = 1n << 50_000_000n;
      const dag15 = makeBinaryDag('A'.repeat(4096), 15);
      const dag26 = makeBinaryDag('A', 26);
      const validZip = createZip([{ name: 'a.txt', data: 'hi' }]);
      const realZipMeta = listZipEntries(validZip).entries.get('a.txt');

      const p6bCases = [
        ['hugeBigInt', hugeBigInt, '[BigInt(out-of-range)]'],
        ['dag15', dag15, '[Array]'],
        ['dag26', dag26, '[Array]'],
      ];

      const tP6b0 = performance.now();
      for (const [label, vec, expectedMarker] of p6bCases) {
        // 1. IPCManager: safeDisplayValue + safeErrorMessage
        assert.throws(
          () => ipc.send(vec, 0, null),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.ENOENT && err.message.includes(expectedMarker),
          `IPCManager safeDisplayValue(${label}) must include ${expectedMarker}`
        );
        assert.throws(
          () => new IPCManager({ eventBus: { on() { throw vec; } } }),
          (err) => err instanceof OmniOSError && err.message.includes(expectedMarker),
          `IPCManager safeErrorMessage(${label}) must include ${expectedMarker}`
        );

        // 2. SharedClipboard: safeDisplayValue
        assert.throws(
          () => clip.set({ mime: vec, data: 'x' }),
          (err) => isTypedEinval(err) && err.message.includes(expectedMarker),
          `SharedClipboard safeDisplayValue(${label}) must include ${expectedMarker}`
        );

        // 3. IntentRouter: safeDisplayValue + safeErrorMessage
        assert.throws(
          () => router.resolveChooser(vec, 'com.p6b.app'),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.ENOENT && err.message.includes(expectedMarker),
          `IntentRouter safeDisplayValue(${label}) must include ${expectedMarker}`
        );
        const routerLogs = [];
        const errRouter = new IntentRouter({ log: (_lvl, _comp, msg) => routerLogs.push(msg) });
        errRouter.indexRegistryAssociations({
          registry: {
            enumKey() {
              throw vec;
            },
          },
        });
        assert.equal(routerLogs.length, 1);
        assert.ok(
          routerLogs[0].includes(expectedMarker),
          `IntentRouter safeErrorMessage(${label}) must include ${expectedMarker}`
        );

        // 4. NotificationCenter: safeDisplayValue + safeCoerceString + safeErrorMessage
        assert.throws(
          () => notif.dismiss(vec),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.ENOENT && err.message.includes(expectedMarker),
          `NotificationCenter safeDisplayValue(${label}) must include ${expectedMarker}`
        );
        assert.throws(
          () => notif.post({ appId: 'com.p6b.app', title: 'ok', body: vec }),
          (err) => isTypedEinval(err),
          `NotificationCenter safeCoerceString(${label}) must throw OmniOSError(EINVAL)`
        );
        const brokerSvc = createIpcBrokerService({
          ipc: {
            start() {
              throw vec;
            },
            stop() {},
          },
        });
        assert.throws(
          () => brokerSvc.start(),
          (err) => err instanceof OmniOSError && err.message.includes(expectedMarker),
          `NotificationCenter safeErrorMessage(${label}) must include ${expectedMarker}`
        );

        // 5. Compositor: safeDisplayValue + coerceWindowTitle + safeErrorMessage
        assert.throws(
          () => comp.setShellMode(vec),
          (err) => isTypedEinval(err) && err.message.includes(expectedMarker),
          `Compositor safeDisplayValue(${label}) must include ${expectedMarker}`
        );
        assert.throws(
          () => comp.createWindow(proc.pid, { title: vec }),
          (err) => isTypedEinval(err),
          `Compositor coerceWindowTitle(${label}) must throw OmniOSError(EINVAL)`
        );
        assert.throws(
          () => new Compositor({ processManager: pm, eventBus: { on() { throw vec; } } }),
          (err) => err instanceof OmniOSError && err.message.includes(expectedMarker),
          `Compositor safeErrorMessage(${label}) must include ${expectedMarker}`
        );

        // 6. zip.mjs: createZip / readZip / extractZipEntry safeDisplayValue
        assert.throws(
          () => createZip([{ name: 'a.txt', data: 'hi', method: vec }]),
          (err) => err instanceof FormatError && err.code === ERROR_CODES.EINVAL && err.message.includes(expectedMarker),
          `createZip(method:${label}) safeDisplayValue must include ${expectedMarker}`
        );
        assert.throws(
          () => createZip([{ name: vec, data: 'hi' }]),
          (err) => err instanceof FormatError && err.details?.name === expectedMarker,
          `createZip(name:${label}) safeDisplayValue must set details.name === ${expectedMarker}`
        );
        assert.throws(
          () => readZip(vec),
          (err) => err instanceof FormatError && err.code === ZIP_ERROR_CODES.E_MALFORMED_ZIP,
          `readZip(${label}) must throw FormatError(E_MALFORMED_ZIP) in O(1)`
        );
        assert.throws(
          () => extractZipEntry(validZip, { ...realZipMeta, method: vec }),
          (err) => err instanceof FormatError && err.message.includes(expectedMarker),
          `extractZipEntry(method:${label}) safeDisplayValue must include ${expectedMarker}`
        );

        // 7. PackageManager: safeDisplayValue + safeCoerceString + safeErrorMessage
        await assert.rejects(
          () => pkg.launch(vec),
          (err) => err instanceof OmniOSError && err.code === ERROR_CODES.ENOENT && err.message.includes(expectedMarker),
          `PackageManager safeDisplayValue(${label}) must include ${expectedMarker}`
        );
        assert.throws(
          () =>
            pkg.registerCatalogEntry({
              appId: `com.p6b.cat.${label}`,
              name: 'P6B',
              platform: 'universal',
              description: vec,
            }),
          (err) => isTypedEinval(err),
          `PackageManager safeCoerceString(${label}) must throw OmniOSError(EINVAL)`
        );
        let isOpenReads = 0;
        const errPkg = new PackageManager({
          storage: {
            get isOpen() {
              isOpenReads += 1;
              if (isOpenReads <= 2) return false;
              throw vec;
            },
          },
        });
        assert.throws(
          () => errPkg.init(),
          (err) => err instanceof OmniOSError && err.message.includes(expectedMarker),
          `PackageManager safeErrorMessage(${label}) must include ${expectedMarker}`
        );
      }

      const p6bMs = performance.now() - tP6b0;
      assert.ok(p6bMs < 200, `All 7-module P6-B O(1) BigInt + dag15/dag26 checks must complete in <200ms, got ${p6bMs.toFixed(1)}ms`);

      // --- C. M2B Minor Polish ---
      // 1. IPCManager: Uint8Array(0) array non-zero byte accounting + exact 4 MiB - 1032 boundary payload round-trip
      ipc.createChannel('x', 0);
      const exactBoundaryLen = 4 * 1024 * 1024 - 1032; // envelopeOverhead = 'x'.length(1) + 'message'.length(7) + 1024 = 1032
      const exactPayload = new Uint8Array(exactBoundaryLen);
      exactPayload[0] = 0x5a;
      exactPayload[exactBoundaryLen - 1] = 0xa5;
      ipc.send('x', 0, exactPayload);
      const exactRecvd = ipc.recv('x');
      assert.equal(exactRecvd.payload.byteLength, exactBoundaryLen);
      assert.equal(exactRecvd.payload[0], 0x5a);
      assert.equal(exactRecvd.payload[exactBoundaryLen - 1], 0xa5);

      // Exact +1 byte over boundary rejects with QuotaExceededError(EFBIG)
      assert.throws(
        () => ipc.send('x', 0, new Uint8Array(exactBoundaryLen + 1)),
        (err) => isTypedQuota(err, ERROR_CODES.EFBIG),
        '4 MiB - 1031 payload must exceed IPC byte budget with QuotaExceededError(EFBIG)'
      );

      // Uint8Array(0) array charges >= 128 bytes per element + 16B container (cannot bypass remaining 15,000-byte budget)
      const nearCapPayload = new Uint8Array(exactBoundaryLen - 15_000);
      const u0Arr10k = Array(10_000).fill(new Uint8Array(0)); // 16 + 10k * 128 = 1,280,016 > 15k
      assert.throws(
        () => ipc.send('x', 0, nearCapPayload, { meta: u0Arr10k }),
        (err) => isTypedQuota(err, ERROR_CODES.EFBIG),
        'Uint8Array(0) elements must charge >= 128 bytes each and throw EFBIG when overflowing remaining budget'
      );
      const u0Arr150 = Array(150).fill(new Uint8Array(0)); // 16 + 150 * 128 = 19,216 > 15,000
      assert.throws(
        () => ipc.send('x', 0, nearCapPayload, { meta: u0Arr150 }),
        (err) => isTypedQuota(err, ERROR_CODES.EFBIG),
        '150 x Uint8Array(0) (19,216B > 15,000B remaining) must throw QuotaExceededError(EFBIG)'
      );
      const u0Arr100 = Array(100).fill(new Uint8Array(0)); // 16 + 100 * 128 = 12,816 <= 15,000
      ipc.send('x', 0, nearCapPayload, { meta: u0Arr100 });
      const u0Recvd = ipc.recv('x');
      assert.equal(u0Recvd.payload.byteLength, exactBoundaryLen - 15_000);
      assert.equal(u0Recvd.meta.length, 100);
      assert.ok(u0Recvd.meta[0] instanceof Uint8Array && u0Recvd.meta[0].byteLength === 0);

      // 2. zip.mjs: giant comment rejects in O(1) (< 50 ms) with OmniOSError(EINVAL)
      const giantComment = 'C'.repeat(5_000_000);
      const tZip0 = performance.now();
      assert.throws(
        () => createZip([{ name: 'a.txt', data: 'hi' }], { comment: giantComment }),
        (err) => err instanceof FormatError && err instanceof OmniOSError && err.code === ERROR_CODES.EINVAL,
        'createZip with 5 MB comment must throw FormatError/OmniOSError(EINVAL)'
      );
      const zipCommentMs = performance.now() - tZip0;
      assert.ok(zipCommentMs < 50, `createZip 5 MB comment rejection must complete in O(1) (<50ms), got ${zipCommentMs.toFixed(1)}ms`);
    } finally {
      ipc.stop();
      pkg.close();
      storage.close();
    }
  });
});

// ============================================================================
// SUITE 23: Iteration 11 Zero-Day Hardening Regressions (Q1-A..Q3-A, Q1-B..Q5-B, Obs-1..3, Obs-W10)
// ============================================================================

describe('Suite 23: Iteration 11 Zero-Day Hardening Regressions (Q1-A..Q3-A, Q1-B..Q5-B, Obs-1..3, Obs-W10)', () => {
  function isTypedEinval(err) {
    return (
      err instanceof OmniOSError &&
      err.code === ERROR_CODES.EINVAL &&
      !(err instanceof TypeError) &&
      !(err instanceof SyntaxError) &&
      !(err instanceof RangeError)
    );
  }

  function isTypedQuota(err, expectedCode = ERROR_CODES.EQUOTA) {
    return (
      err instanceof QuotaExceededError &&
      err instanceof OmniOSError &&
      err.code === expectedCode &&
      !(err instanceof RangeError)
    );
  }

  function makeBinaryDag(leaf, levels) {
    let node = leaf;
    for (let i = 0; i < levels; i += 1) {
      node = [node, node];
    }
    return node;
  }

  it('23.1 (Q1-A + Obs-1 + Obs-2 + Proactive Store Bounds): Registry keyPath/valueName caps, valid depth-64 HKCU & HKLM VirtualStore, 50 MB Obs-1 O(1) bounded errors, Obs-2 tampered SQLite rows, defaults/sharedPrefs identifier & key caps', () => {
    const storage = new SqliteStorage(':memory:');
    const cfg = new UnifiedConfigStore({ storage });

    try {
      // Exported registry bound constants
      assert.equal(MAX_REG_KEY_PATH_CHARS, 4096);
      assert.equal(MAX_REG_KEY_DEPTH, 64);
      assert.equal(MAX_REG_SEGMENT_CHARS, 255);
      assert.equal(MAX_REG_VALUE_NAME_CHARS, 4096);

      // --- A. Q1-A: Oversized & over-depth Registry keyPath / valueName rejections (< 50 ms each) ---
      {
        const kp30k = 'a\\'.repeat(15_000);
        const t0 = performance.now();
        assert.throws(
          () => cfg.registry.createKey('HKCU', kp30k),
          (err) => isTypedEinval(err) && err.message.length <= 256,
          '30 KB HKCU createKey keyPath must reject with bounded OmniOSError(EINVAL)'
        );
        assert.ok(performance.now() - t0 < 50, '30 KB HKCU createKey rejection must be < 50 ms');
      }

      {
        const kp16k = 'a\\'.repeat(8_000);
        const t0 = performance.now();
        assert.throws(
          () => cfg.registry.createKey('HKLM', kp16k, { uid: 10000, appId: 'com.evil.app' }),
          (err) => isTypedEinval(err) && err.message.length <= 256,
          '16 KB unprivileged HKLM createKey keyPath must reject with OmniOSError(EINVAL)'
        );
        assert.ok(performance.now() - t0 < 50, '16 KB unprivileged HKLM createKey rejection must be < 50 ms');
      }

      {
        const kp60k = 'a\\'.repeat(30_000);
        const t0 = performance.now();
        assert.throws(
          () => cfg.registry.setValue('HKLM', kp60k, 'v', 'REG_SZ', 'x', { uid: 10000, appId: 'com.evil.app' }),
          (err) => isTypedEinval(err) && err.message.length <= 256,
          '60 KB unprivileged HKLM setValue keyPath must reject with OmniOSError(EINVAL)'
        );
        assert.ok(performance.now() - t0 < 50, '60 KB unprivileged HKLM setValue rejection must be < 50 ms');
      }

      // Depth-65 keyPath (well under 4096 chars) & 256-char segment
      {
        const depth65 = Array.from({ length: 65 }, (_, i) => `k${i}`).join('\\');
        assert.ok(depth65.length < MAX_REG_KEY_PATH_CHARS);
        const t0 = performance.now();
        assert.throws(
          () => cfg.registry.createKey('HKCU', depth65),
          (err) => isTypedEinval(err),
          'Depth-65 keyPath must reject with OmniOSError(EINVAL)'
        );
        assert.throws(
          () => cfg.registry.setValue('HKLM', depth65, 'v', 'REG_SZ', 'x', { uid: 10000, appId: 'com.evil.app' }),
          (err) => isTypedEinval(err),
          'Depth-65 unprivileged HKLM setValue must reject with OmniOSError(EINVAL)'
        );
        const seg256 = `Software\\${'s'.repeat(256)}`;
        assert.throws(
          () => cfg.registry.createKey('HKCU', seg256),
          (err) => isTypedEinval(err),
          '256-char segment keyPath must reject with OmniOSError(EINVAL)'
        );
        assert.ok(performance.now() - t0 < 50, 'Depth-65 & 256-char segment rejections must be < 50 ms');
      }

      // Read-only getValue & enumKey with 6 MB slash-dense path
      {
        const hugeReadPath = 'a/'.repeat(3_000_000);
        const t0 = performance.now();
        assert.throws(
          () => cfg.registry.getValue('HKCU', hugeReadPath, 'v'),
          (err) => isTypedEinval(err) && err.message.length <= 256,
          'Read-only getValue with 6 MB keyPath must reject in O(1) with OmniOSError(EINVAL)'
        );
        assert.throws(
          () => cfg.registry.enumKey('HKCU', hugeReadPath, { uid: 10000, appId: 'com.evil.app' }),
          (err) => isTypedEinval(err) && err.message.length <= 256,
          'Read-only enumKey with 6 MB keyPath must reject in O(1) with OmniOSError(EINVAL)'
        );
        assert.ok(performance.now() - t0 < 50, 'Read-only 6 MB keyPath rejections must be < 50 ms');
      }

      // 20 MB valueName
      {
        const hugeValName = 'V'.repeat(20_000_000);
        const t0 = performance.now();
        assert.throws(
          () => cfg.registry.setValue('HKLM', 'Software\\Test', hugeValName, 'REG_SZ', 'x', { uid: 10000, appId: 'com.evil.app' }),
          (err) => isTypedEinval(err) && err.message.length <= 256,
          '20 MB valueName setValue must reject with OmniOSError(EINVAL)'
        );
        assert.throws(
          () => cfg.registry.getValue('HKCU', 'Software\\Test', hugeValName),
          (err) => isTypedEinval(err) && err.message.length <= 256,
          '20 MB valueName getValue must reject with OmniOSError(EINVAL)'
        );
        assert.ok(performance.now() - t0 < 50, '20 MB valueName rejections must be < 50 ms');
      }

      // Valid depth-64 keyPath: both privileged HKCU and unprivileged HKLM VirtualStore with long appId commit & read back cleanly
      {
        const depth64 = Array.from({ length: 64 }, (_, i) => `d${i}`).join('\\');
        const longAppId = `com.valid.${'a'.repeat(240)}`; // 250 chars <= 256
        assert.ok(longAppId.length <= 256);

        cfg.registry.setValue('HKCU', depth64, 'ok', 'REG_SZ', 'priv-depth64');
        const privRead = cfg.registry.getValue('HKCU', depth64, 'ok');
        assert.equal(privRead?.data, 'priv-depth64');
        assert.equal(privRead?.virtualized, false);

        const unprivCtx = { uid: 10000, appId: longAppId };
        cfg.registry.setValue('HKLM', depth64, 'ok', 'REG_SZ', 'virt-depth64', unprivCtx);
        const virtRead = cfg.registry.getValue('HKLM', depth64, 'ok', unprivCtx);
        assert.equal(virtRead?.data, 'virt-depth64');
        assert.equal(virtRead?.virtualized, true);

        // Exact 255-char segment & 4096-char valueName boundary still succeed
        const seg255 = `Software\\${'z'.repeat(255)}`;
        const maxValName = 'v'.repeat(MAX_REG_VALUE_NAME_CHARS);
        cfg.registry.setValue('HKCU', seg255, maxValName, 'REG_DWORD', 77);
        assert.equal(cfg.registry.getValue('HKCU', seg255, maxValName)?.data, 77);
      }

      // --- B. Obs-1: validateTheme, validateShellMode, validateLocale, _spEdit unknown op with 50 MB strings ---
      {
        const huge50m = 'X'.repeat(50_000_000);
        const t0 = performance.now();
        for (const sysKey of ['system.theme', 'system.shellMode', 'system.locale']) {
          assert.throws(
            () => cfg.system.set(sysKey, huge50m),
            (err) => isTypedEinval(err) && err.message.length <= 256,
            `system.set(${sysKey}, 50MB) must throw OmniOSError(EINVAL) with err.message.length <= 256`
          );
        }
        assert.throws(
          () => cfg.sharedPrefs.edit('com.obs1.app', 'prefs', [{ op: huge50m }]),
          (err) => isTypedEinval(err) && err.message.length <= 256,
          'sharedPrefs.edit unknown 50MB op must throw OmniOSError(EINVAL) with err.message.length <= 256'
        );
        const obs1Ms = performance.now() - t0;
        assert.ok(obs1Ms < 50, `Obs-1 50 MB validator & _spEdit rejections must complete in O(1) (<50ms), got ${obs1Ms.toFixed(1)}ms`);
      }

      // --- C. Obs-2: Tampered oversized REG_QWORD & BigInt AST SQLite rows reject in O(1) before .trim() ---
      {
        cfg.registry.setValue('HKCU', 'Software\\Obs2', 'q', 'REG_QWORD', 42n);
        cfg.registry.setValue('HKCU', 'Software\\Obs2', 'd', 'REG_DWORD', 7);
        cfg.defaults.set('com.obs2.dom', 'big', 123n);

        const paddedQword = `${' '.repeat(2_000_000)}42`;
        const paddedDword = `${' '.repeat(200_000)}7`;
        const paddedBigAst = JSON.stringify(['I', `${' '.repeat(2_000_000)}123`]);

        storage.run(
          'UPDATE registry_values SET data_text = ? WHERE hive = ? AND key_path_norm = ? AND value_name_norm = ?',
          paddedQword,
          'HKCU',
          'software\\obs2',
          'q'
        );
        storage.run(
          'UPDATE registry_values SET data_text = ? WHERE hive = ? AND key_path_norm = ? AND value_name_norm = ?',
          paddedDword,
          'HKCU',
          'software\\obs2',
          'd'
        );
        storage.run(
          'UPDATE defaults_entries SET value_ast_json = ? WHERE domain = ? AND key_name = ?',
          paddedBigAst,
          'com.obs2.dom',
          'big'
        );

        const t0 = performance.now();
        assert.throws(
          () => cfg.registry.getValue('HKCU', 'Software\\Obs2', 'q'),
          (err) => isTypedEinval(err),
          'Tampered oversized REG_QWORD SQLite row must reject in O(1) with OmniOSError(EINVAL)'
        );
        assert.throws(
          () => cfg.registry.getValue('HKCU', 'Software\\Obs2', 'd'),
          (err) => isTypedEinval(err),
          'Tampered oversized REG_DWORD SQLite row must reject in O(1) with OmniOSError(EINVAL)'
        );
        assert.throws(
          () => cfg.defaults.get('com.obs2.dom', 'big'),
          (err) => isTypedEinval(err),
          'Tampered oversized BigInt AST SQLite row must reject in O(1) with OmniOSError(EINVAL)'
        );
        const obs2Ms = performance.now() - t0;
        assert.ok(obs2Ms < 50, `Obs-2 tampered SQLite row rejections must complete in O(1) (<50ms), got ${obs2Ms.toFixed(1)}ms`);
      }

      // --- D. Proactive Store Bounds: oversized defaults domain/key & sharedPrefs appId/prefName/key ---
      {
        const overId = 'd'.repeat(1025);
        const overKey = 'k'.repeat(4097);

        assert.throws(() => cfg.defaults.set(overId, 'k', 1), isTypedEinval);
        assert.throws(() => cfg.defaults.get(overId, 'k'), isTypedEinval);
        assert.throws(() => cfg.defaults.remove(overId, 'k'), isTypedEinval);
        assert.throws(() => cfg.defaults.set('com.valid.dom', overKey, 1), isTypedEinval);
        assert.throws(() => cfg.defaults.get('com.valid.dom', overKey), isTypedEinval);

        assert.throws(
          () => cfg.sharedPrefs.edit(overId, 'prefs', [{ op: 'put', key: 'k', type: 'string', value: 'v' }]),
          isTypedEinval
        );
        assert.throws(
          () => cfg.sharedPrefs.edit('com.valid.app', overId, [{ op: 'put', key: 'k', type: 'string', value: 'v' }]),
          isTypedEinval
        );
        assert.throws(
          () => cfg.sharedPrefs.edit('com.valid.app', 'prefs', [{ op: 'put', key: overKey, type: 'string', value: 'v' }]),
          isTypedEinval
        );
        assert.throws(() => cfg.sharedPrefs.get(overId, 'prefs', 'k'), isTypedEinval);
        assert.throws(() => cfg.sharedPrefs.get('com.valid.app', overId, 'k'), isTypedEinval);
        assert.throws(() => cfg.sharedPrefs.get('com.valid.app', 'prefs', overKey), isTypedEinval);
        assert.throws(() => cfg.sharedPrefs.getAll(overId, 'prefs'), isTypedEinval);
      }
    } finally {
      cfg.close();
      storage.close();
    }
  });

  it('23.2 (Q2-A + Q3-A + Obs-3 + Proactive M2A Guards): virtual-mounts O(1) numeric coercion & zero spyCalls, users isWithinRoot/checkSandboxAccess 20 MB path cap, shell/defaultUser/symlink length guards', () => {
    const storage = new SqliteStorage(':memory:');
    const um = new UserManager({ storage });
    const vfs = new VFS({ storage, userManager: um });

    try {
      const dag15 = makeBinaryDag('A'.repeat(4096), 15);
      const dag26 = makeBinaryDag('A', 26);
      let spyCalls = 0;
      const spy = {
        toString() {
          spyCalls += 1;
          return '123';
        },
        valueOf() {
          spyCalls += 1;
          return 123;
        },
        [Symbol.toPrimitive]() {
          spyCalls += 1;
          return 123;
        },
      };

      const hostileNums = [
        ['dag15', dag15],
        ['dag26', dag26],
        ['spy', spy],
      ];

      // --- A. Q2-A: ProcFsMount, makeStatObject, makeDirentObject, TmpFsMount ---
      const tQ2a0 = performance.now();

      // 1. ProcFsMount.listChildren() with hostile PIDs + valid integer PID 42
      const validPcb42 = {
        pid: 42,
        ppid: 1,
        uid: 1000,
        gid: 1000,
        name: 'good-proc',
        state: 'READY',
        platform: 'posix',
        arch: 'x86_64',
        appId: 'com.q2a.good',
        priority: 0,
        cwd: '/home/user',
        args: ['good-proc'],
        startedAt: Date.now(),
        addressSpace: {
          getStats: () => ({
            usedBytes: 4096,
            peakBytes: 8192,
            mappedPages: 1,
            regions: [{ base: 0x1000, end: 0x2000, size: 0x1000, perms: 3, label: 'code' }],
            guardRegions: [],
          }),
        },
      };
      const procList = new ProcFsMount({
        processManager: {
          get: (pid) => (pid === 42 ? validPcb42 : null),
          getAll: () => [
            { pid: dag15, state: 'READY' },
            { pid: dag26, state: 'READY' },
            { pid: spy, state: 'READY' },
            validPcb42,
          ],
        },
      });
      const rootChildren = procList.listChildren(procList.getRootNode());
      const childNames = rootChildren.map((d) => d.name);
      assert.ok(childNames.includes('42'), 'ProcFsMount.listChildren must preserve valid integer PID 42');
      assert.ok(childNames.includes('uptime') && childNames.includes('meminfo') && childNames.includes('version'));
      assert.equal(childNames.length, 4, 'Hostile non-integer PIDs must be skipped safely');

      // 2. ProcFsMount._getUptimeBytes() with BigInt, throwing valueOf, dag15, dag26, spy
      const uptimeCases = [
        ['hugeBigInt', () => 1n << 50_000_000n],
        ['throwingValueOf', () => ({ valueOf() { throw new Error('boom'); } })],
        ['dag15', () => dag15],
        ['dag26', () => dag26],
        ['spy', () => spy],
      ];
      for (const [label, getUptimeMs] of uptimeCases) {
        const procUp = new ProcFsMount({ kernel: { getUptimeMs } });
        const upEntry = procUp.lookupChild(procUp.getRootNode(), 'uptime');
        assert.ok(upEntry && upEntry.node, `uptime lookup must succeed for ${label}`);
        const upText = new TextDecoder().decode(procUp.readNode(upEntry.node));
        assert.match(upText, /^\d+\.\d{3} \d+\.\d{3}\n$/, `uptime text must remain well-formed for ${label}, got ${JSON.stringify(upText)}`);
      }

      // 3. _getMeminfoBytes(), _getPidStatusBytes(), _getPidMapsBytes() with dag15, dag26, spy
      for (const [label, bad] of hostileNums) {
        const hostilePcb = {
          pid: 77,
          ppid: 1,
          uid: 1000,
          gid: 1000,
          name: 'hostile-mem',
          state: 'RUNNING',
          addressSpace: {
            getStats: () => ({
              usedBytes: bad,
              peakBytes: bad,
              mappedPages: bad,
              regions: [{ base: bad, end: bad, size: bad, perms: bad, label: 'seg' }],
              guardRegions: [{ base: bad, end: bad, size: bad }],
            }),
          },
        };
        const procMem = new ProcFsMount({
          processManager: {
            get: (pid) => (pid === 77 ? hostilePcb : null),
            getAll: () => [hostilePcb],
            getAggregateMemoryStats: () => ({
              totalMappedPages: bad,
              totalUsedBytes: bad,
              totalPeakBytes: bad,
            }),
          },
        });
        const memEntry = procMem.lookupChild(procMem.getRootNode(), 'meminfo');
        const memText = new TextDecoder().decode(procMem.readNode(memEntry.node));
        assert.ok(memText.includes('MappedPages:\t0'), `_getMeminfoBytes(${label}) must coerce safely to 0`);
        assert.ok(memText.includes('UsedBytes:\t0'), `_getMeminfoBytes(${label}) UsedBytes must coerce safely to 0`);

        const pidDir = procMem.lookupChild(procMem.getRootNode(), '77');
        assert.ok(pidDir && pidDir.node);
        const statusEntry = procMem.lookupChild(pidDir.node, 'status');
        const statusText = new TextDecoder().decode(procMem.readNode(statusEntry.node));
        assert.ok(statusText.includes('VmSize:\t0 kB'), `_getPidStatusBytes(${label}) VmSize must coerce safely to 0`);
        assert.ok(statusText.includes('MappedPages:\t0'), `_getPidStatusBytes(${label}) MappedPages must coerce safely to 0`);

        const mapsEntry = procMem.lookupChild(pidDir.node, 'maps');
        const mapsText = new TextDecoder().decode(procMem.readNode(mapsEntry.node));
        assert.ok(mapsText.includes('0x00000000-0x00000000 ---p'), `_getPidMapsBytes(${label}) must coerce safely to 0`);
      }

      // 4. Exported makeStatObject() & makeDirentObject() with dag15, dag26, spy
      for (const [label, bad] of hostileNums) {
        const hostileNode = {
          ino: bad,
          type: 'file',
          size: bad,
          mode: bad,
          uid: bad,
          gid: bad,
          nlink: bad,
          mtimeMs: bad,
          ctimeMs: bad,
          atimeMs: bad,
          birthtimeMs: bad,
        };
        const st = makeStatObject(hostileNode);
        assert.equal(st.ino, 0, `makeStatObject(${label}).ino must fallback to 0`);
        assert.equal(st.size, 0, `makeStatObject(${label}).size must fallback to 0`);
        assert.equal(st.mode, 0, `makeStatObject(${label}).mode must fallback to 0`);
        assert.equal(st.uid, 0, `makeStatObject(${label}).uid must fallback to 0`);
        assert.equal(st.gid, 0, `makeStatObject(${label}).gid must fallback to 0`);
        assert.equal(st.nlink, 1, `makeStatObject(${label}).nlink must fallback to 1`);
        assert.equal(st.mtimeMs, 0);

        const de = makeDirentObject('f.txt', hostileNode);
        assert.equal(de.ino, 0, `makeDirentObject(${label}).ino must fallback to 0`);
        assert.equal(de.size, 0, `makeDirentObject(${label}).size must fallback to 0`);
        assert.equal(de.mode, 0, `makeDirentObject(${label}).mode must fallback to 0`);
      }

      // 5. TmpFsMount.createFile() & createDir() with dag15, dag26, spy
      const tmpFs = new TmpFsMount();
      const tmpRoot = tmpFs.getRootNode();
      for (const [label, bad] of hostileNums) {
        for (const optObj of [{ mode: bad }, { uid: bad }, { gid: bad }]) {
          assert.throws(
            () => tmpFs.createFile(tmpRoot, `f_${label}`, new Uint8Array(1), optObj),
            (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL,
            `TmpFsMount.createFile(${label}) must throw VfsError(EINVAL)`
          );
          assert.throws(
            () => tmpFs.createDir(tmpRoot, `d_${label}`, optObj),
            (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL,
            `TmpFsMount.createDir(${label}) must throw VfsError(EINVAL)`
          );
        }
      }
      // Valid TmpFsMount calls still work cleanly
      const createdFile = tmpFs.createFile(tmpRoot, 'ok.txt', new Uint8Array([1, 2, 3]), { mode: 0o644, uid: 1000, gid: 1000 });
      assert.equal(createdFile.size, 3);
      const createdDir = tmpFs.createDir(tmpRoot, 'okdir', { mode: 0o755, uid: 1000, gid: 1000 });
      assert.equal(createdDir.type, 'dir');

      const q2aMs = performance.now() - tQ2a0;
      assert.equal(spyCalls, 0, 'Q2-A virtual-mounts coercions MUST NEVER invoke toString/valueOf/Symbol.toPrimitive');
      assert.ok(q2aMs < 200, `All Q2-A virtual-mounts checks must complete rapidly (<200ms), got ${q2aMs.toFixed(1)}ms`);

      // --- B. Q3-A: users.mjs isWithinRoot & checkSandboxAccess 20 MB slash-dense path cap (< 50 ms under 128 MB heap) ---
      {
        const hugeSlashPath = `/${'a/'.repeat(10_000_000)}`;
        const t0 = performance.now();
        assert.equal(isWithinRoot(hugeSlashPath, '/home/user'), false);
        assert.equal(isWithinRoot('/home/user/doc', hugeSlashPath), false);
        assert.equal(isPathWithinRoot(hugeSlashPath, '/home/user'), false);
        const sbRes = um.checkSandboxAccess(1000, hugeSlashPath);
        assert.deepEqual(sbRes, { allowed: false, reason: 'invalid_path' });
        const q3aMs = performance.now() - t0;
        assert.ok(q3aMs < 50, `Q3-A 20 MB path rejections must complete in O(1) (<50ms), got ${q3aMs.toFixed(1)}ms`);
      }

      // --- C. Obs-3 & Proactive M2A Guards ---
      {
        assert.throws(
          () => um.createUser({ username: 'u_shell', shell: `/bin/${'s'.repeat(5000)}` }),
          (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL,
          'createUser with >4096-char shell must throw SecurityError(EINVAL)'
        );
        assert.throws(
          () => new PathTranslator({ defaultUser: 'u'.repeat(200) }),
          (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL,
          'PathTranslator with >128-char defaultUser must throw VfsError(EINVAL)'
        );
        const hugeTarget = 'x'.repeat(5_000_000);
        const t0 = performance.now();
        assert.throws(
          () => vfs.symlink(hugeTarget, '/tmp/bad_link'),
          (err) => err instanceof VfsError && err.code === ERROR_CODES.EINVAL,
          'vfs.symlink with 5 MB target must throw VfsError(EINVAL) in O(1)'
        );
        const symMs = performance.now() - t0;
        assert.ok(symMs < 50, `vfs.symlink 5 MB target rejection must complete in O(1) (<50ms), got ${symMs.toFixed(1)}ms`);
      }
    } finally {
      vfs.close();
      um.close();
      storage.close();
    }
  });

  it('23.3 (Q1-B + Q2-B + Q3-B + Obs-W10 ZIP): ZIP linear Trie & MAX_ZIP_PATH_DEPTH=256, .split() OOM bombs across zip/clipboard/router/package-manager, IPCManager 249k Uint8Array(0)/(1) EFBIG, PackageManager.install hostile rtPlatform sanitization', async () => {
    const storage = new SqliteStorage(':memory:');
    const ipc = new IPCManager();
    const cb = new SharedClipboard();
    const router = new IntentRouter();
    const pkg = new PackageManager({ storage });

    try {
      // --- A. Q1-B: zip.mjs Trie + MAX_ZIP_PATH_DEPTH + collision & prototype safety ---
      assert.equal(MAX_ZIP_PATH_DEPTH, 256);

      // Valid 40-entry x 200-segment ZIP parses in < 100 ms via linear Trie
      const deep200Entries = Array.from({ length: 40 }, (_, i) => ({
        name: `${`d${i}/`.repeat(199)}f.txt`,
        data: `payload-${i}`,
      }));
      const deep200Zip = createZip(deep200Entries);
      const tTrie0 = performance.now();
      const parsed200 = listZipEntries(deep200Zip);
      const trieMs = performance.now() - tTrie0;
      assert.equal(parsed200.entries.size, 40);
      assert.ok(trieMs < 100, `40-entry x 200-segment ZIP must parse in <100ms via linear Trie, got ${trieMs.toFixed(1)}ms`);
      const sampleBytes = extractZipEntry(deep200Zip, deep200Entries[7].name);
      assert.equal(new TextDecoder().decode(sampleBytes), 'payload-7');

      // File / dir / implicit-dir collisions throw FormatError(E_MALFORMED_ZIP)
      for (const [label, colliding] of [
        ['file_then_dir', [{ name: 'a', data: '1' }, { name: 'a/', data: '' }]],
        ['file_then_implicit_dir', [{ name: 'a', data: '1' }, { name: 'a/b.txt', data: '2' }]],
        ['implicit_dir_then_file', [{ name: 'a/b.txt', data: '2' }, { name: 'a', data: '1' }]],
        ['dup_explicit_dir', [{ name: 'a/', data: '' }, { name: 'a/', data: '' }]],
      ]) {
        assert.throws(
          () => createZip(colliding),
          (err) => err instanceof FormatError && err.code === ZIP_ERROR_CODES.E_MALFORMED_ZIP,
          `ZIP Trie collision (${label}) must throw FormatError(E_MALFORMED_ZIP)`
        );
      }

      // Implicit + explicit dir order is valid, and __proto__/constructor/prototype.txt succeeds safely
      const protoZip = createZip([
        { name: 'dir/item.txt', data: 'ok' },
        { name: 'dir/', data: '' },
        { name: '__proto__/constructor/prototype.txt', data: 'safe-proto' },
      ]);
      const protoArchive = readZip(protoZip);
      assert.equal(
        new TextDecoder().decode(protoArchive.readBytes('__proto__/constructor/prototype.txt')),
        'safe-proto'
      );
      assert.equal(Object.prototype.polluted, undefined);

      // Path depth > 256 throws FormatError(E_ARCHIVE_BOMB) in < 50 ms (both createZip AND Python-built ZIP -> listZipEntries)
      {
        const depth301Name = `${'d/'.repeat(300)}f.txt`;
        const t0 = performance.now();
        assert.throws(
          () => createZip([{ name: depth301Name, data: 'x' }]),
          (err) => err instanceof FormatError && err.code === ZIP_ERROR_CODES.E_ARCHIVE_BOMB,
          'createZip depth > 256 must throw FormatError(E_ARCHIVE_BOMB)'
        );
        assert.ok(performance.now() - t0 < 50, 'createZip depth > 256 rejection must be < 50 ms');

        // Build genuine >256-segment ZIP in-memory via Python zipfile (zero /tmp files)
        const pyB64 = runPython(
          'import io, base64, zipfile\n' +
          'buf = io.BytesIO()\n' +
          'with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:\n' +
          '    zf.writestr(("d/" * 300) + "f.txt", b"x")\n' +
          'print(base64.b64encode(buf.getvalue()).decode("ascii"))'
        ).trim();
        const pyDeepZip = new Uint8Array(Buffer.from(pyB64, 'base64'));
        const t1 = performance.now();
        assert.throws(
          () => listZipEntries(pyDeepZip),
          (err) => err instanceof FormatError && err.code === ZIP_ERROR_CODES.E_ARCHIVE_BOMB,
          'listZipEntries on depth-301 ZIP must throw FormatError(E_ARCHIVE_BOMB)'
        );
        assert.ok(performance.now() - t1 < 50, 'listZipEntries depth > 256 rejection must be < 50 ms');
      }

      // .split() bombs & Obs-W10 bounded ZIP error messages
      {
        const slash16m = `a${'/'.repeat(16_000_000)}`;
        const t0 = performance.now();
        assert.throws(
          () => createZip([{ name: slash16m, data: 'x' }]),
          (err) => err instanceof FormatError && err.code === ERROR_CODES.EINVAL && err.message.length <= 400,
          'createZip 16M-slash name must throw FormatError(EINVAL) with bounded message (<=400 chars)'
        );
        assert.ok(performance.now() - t0 < 50, 'createZip 16M-slash rejection must be < 50 ms');
      }

      {
        const name70k = 'x'.repeat(70_000);
        const trav60k = `../${'a'.repeat(60_000)}`;
        const t0 = performance.now();
        assert.throws(
          () => validateZipEntryName(name70k),
          (err) => err instanceof FormatError && err.code === ERROR_CODES.EINVAL && err.message.length <= 400,
          'validateZipEntryName(70k) must throw FormatError(EINVAL) with message <= 400 chars'
        );
        assert.throws(
          () => validateZipEntryName(trav60k),
          (err) => err instanceof FormatError && err.code === ZIP_ERROR_CODES.E_PATH_TRAVERSAL && err.message.length <= 400,
          'validateZipEntryName traversal with 60k chars must cap error message <= 400 chars (Obs-W10)'
        );
        assert.ok(performance.now() - t0 < 50, 'validateZipEntryName oversized rejections must be < 50 ms');
      }

      {
        const semi16m = ';'.repeat(16_000_000);
        const t0 = performance.now();
        assert.throws(
          () => cb.set({ mime: semi16m, data: 'x' }),
          (err) => isTypedEinval(err) && err.message.length <= 400,
          'SharedClipboard.set 16M semicolon MIME must throw EINVAL in O(1)'
        );
        const res = router.resolve({ mimeType: semi16m });
        assert.deepEqual(res, [], 'IntentRouter.resolve 16M semicolon MIME must return [] in O(1)');
        assert.ok(performance.now() - t0 < 50, 'Clipboard & Router 16M semicolon rejections must be < 50 ms');
      }

      // PackageManager oversized path (validatePackageDirPath -> SecurityError(E_PATH_TRAVERSAL))
      {
        const bigPathPkgZip = createZip([{ name: 'omnios.manifest.json', data: '{}' }]);
        const hugeInstallDir = `/apps/universal/${'a/'.repeat(2_000_000)}`;
        pkg.registerRuntime('universal', {
          platform: 'universal',
          inspectPackage: () => ({ format: 'universal-uapp', platform: 'universal', appId: 'com.q1b.bigpath' }),
          installPackage: () => ({ installDir: hugeInstallDir }),
          createExecutionContext: () => makeWorkExecContext(),
        });
        const t0 = performance.now();
        await assert.rejects(
          () => pkg.install(bigPathPkgZip),
          (err) => err instanceof SecurityError && err.code === ERROR_CODES.E_PATH_TRAVERSAL && err.message.length <= 400,
          'PackageManager oversized installDir must throw SecurityError(E_PATH_TRAVERSAL) in O(1)'
        );
        assert.ok(performance.now() - t0 < 50, 'PackageManager oversized path rejection must be < 50 ms');
      }

      // --- B. Q2-B: IPCManager 249k x Uint8Array(0) (with & without subscriber) and 249k x Uint8Array(1) ---
      {
        const u0 = new Uint8Array(0);
        const payload249kU0 = [Array(100_000).fill(u0), Array(100_000).fill(u0), Array(49_000).fill(u0)];
        ipc.createChannel('q2b-sub', 0);
        ipc.createChannel('q2b-nosub', 0);
        let subCalls = 0;
        ipc.subscribe('q2b-sub', () => {
          subCalls += 1;
        });

        const t0 = performance.now();
        assert.throws(
          () => ipc.send('q2b-sub', 0, payload249kU0),
          (err) => isTypedQuota(err, ERROR_CODES.EFBIG),
          'IPCManager.send (with subscriber) 249k x Uint8Array(0) must reject with QuotaExceededError(EFBIG)'
        );
        assert.equal(subCalls, 0, 'Rejected EFBIG send must deliver 0 messages to subscribers');
        assert.throws(
          () => ipc.send('q2b-nosub', 0, payload249kU0),
          (err) => isTypedQuota(err, ERROR_CODES.EFBIG),
          'IPCManager.send (no subscriber) 249k x Uint8Array(0) must reject with QuotaExceededError(EFBIG)'
        );
        const u1 = new Uint8Array(1);
        const payload249kU1 = [Array(100_000).fill(u1), Array(100_000).fill(u1), Array(49_000).fill(u1)];
        assert.throws(
          () => ipc.send('q2b-nosub', 0, payload249kU1),
          (err) => isTypedQuota(err, ERROR_CODES.EFBIG),
          'IPCManager.send 249k x Uint8Array(1) must reject with QuotaExceededError(EFBIG)'
        );
        const q2bMs = performance.now() - t0;
        assert.ok(q2bMs < 100, `All Q2-B IPC 249k Uint8Array rejections must complete in <100ms, got ${q2bMs.toFixed(1)}ms`);
      }

      // --- C. Q3-B: PackageManager.install() hostile rtPlatform (6 vectors, spyCalls === 0) ---
      {
        const dag15 = makeBinaryDag('X'.repeat(4096), 15);
        const dag26 = makeBinaryDag('X', 26);
        let spyCalls = 0;
        const spyObj = {
          toString() {
            spyCalls += 1;
            return 'evil';
          },
          [Symbol.toPrimitive]() {
            spyCalls += 1;
            return 'evil';
          },
        };
        const uappZip = createZip([{ name: 'omnios.manifest.json', data: '{}' }]);

        const rtPlatformCases = [
          ['posBigInt', 1n << 50_000_000n, '[BigInt(out-of-range)]'],
          ['negBigInt', -(1n << 50_000_000n), '[BigInt(out-of-range)]'],
          ['dag15', dag15, '[Array]'],
          ['dag26', dag26, '[Array]'],
          ['symbol', Symbol('S'), 'Symbol(S)'],
          ['spy', spyObj, '[Object]'],
        ];

        for (const [label, hostilePlatform, expectedMarker] of rtPlatformCases) {
          pkg.registerRuntime('universal', {
            platform: 'universal',
            inspectPackage: () => ({
              format: 'universal-uapp',
              platform: hostilePlatform,
              appId: `com.q3b.${label}`,
            }),
            createExecutionContext: () => makeWorkExecContext(),
          });

          const t0 = performance.now();
          await assert.rejects(
            () => pkg.install(uappZip),
            (err) =>
              err instanceof FormatError &&
              err.code === ERROR_CODES.ENOTSUP &&
              !(err instanceof TypeError) &&
              err.message.includes(expectedMarker) &&
              err.details?.platform === expectedMarker,
            `PackageManager.install(rtPlatform:${label}) must throw FormatError(ENOTSUP) containing ${expectedMarker}`
          );
          const elapsed = performance.now() - t0;
          assert.ok(elapsed < 50, `Q3-B install(${label}) must reject in <50ms, got ${elapsed.toFixed(1)}ms`);
        }
        assert.equal(spyCalls, 0, 'Q3-B PackageManager.install MUST NEVER invoke spy.toString/Symbol.toPrimitive');
      }
    } finally {
      ipc.stop();
      pkg.close();
      storage.close();
    }
  });

  it('23.4 (Q4-B + Q5-B + Obs-W10 Symbols): Pre-.trim() loop CPU DoS guards, NotificationCenter invokeAction cumulative byte & count=64 caps, SharedClipboard 249k {} EFBIG + _maxHistoryBytes eviction + lazy JSON clone isolation, 70x Symbol(5M) O(1) across all 7 M2B modules', async () => {
    const storage = new SqliteStorage(':memory:');
    const bus = new KernelEventBus();
    const pm = new ProcessManager();
    const ipc = new IPCManager({ eventBus: bus });
    const router = new IntentRouter({ eventBus: bus });
    const cb = new SharedClipboard({ eventBus: bus });
    const nc = new NotificationCenter({ eventBus: bus, processManager: pm });
    const comp = new Compositor({ eventBus: bus, processManager: pm });
    const pkg = new PackageManager({ storage, processManager: pm });

    try {
      // --- A. Q4-B: Pre-.trim() loops in NotificationCenter.post & IntentRouter.registerHandlers ---
      {
        const ws5mLabel = `${' '.repeat(5_000_000)}L`;
        const actions1k5m = Array.from({ length: 1000 }, (_, i) => ({ id: `a${i}`, label: ws5mLabel }));
        const t0 = performance.now();
        assert.throws(
          () => nc.post({ appId: 'com.q4b.notif', title: 't', actions: actions1k5m }),
          (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
          'NotificationCenter.post with 1000 actions sharing 5 MB whitespace label must throw QuotaExceededError(EQUOTA)'
        );
        assert.ok(performance.now() - t0 < 50, 'NotificationCenter 5 MB pre-trim rejection must be < 50 ms');
      }

      {
        const ws20mLabel = `${' '.repeat(20_000_000)}L`;
        const actions1k20m = Array.from({ length: 1000 }, (_, i) => ({ id: `b${i}`, label: ws20mLabel }));
        const t0 = performance.now();
        assert.throws(
          () => nc.post({ appId: 'com.q4b.notif', title: 't', actions: actions1k20m }),
          (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
          'NotificationCenter.post with 1000 actions sharing 20 MB whitespace label must throw QuotaExceededError(EQUOTA)'
        );
        assert.ok(performance.now() - t0 < 50, 'NotificationCenter 20 MB pre-trim rejection must be < 50 ms');
      }

      // IntentRouter baseline handler to prove 0 mutation on rejected calls
      router.registerHandlers('com.q4b.router', [{ action: 'view', extension: '.baseline', platform: 'android' }]);
      assert.equal(router.resolve({ action: 'view', extension: '.baseline' }).length, 1);

      {
        const ws5mPlatform = `${' '.repeat(5_000_000)}android`;
        const handlers1024 = Array.from({ length: 1024 }, (_, i) => ({
          action: 'view',
          extension: `.e${i}`,
          platform: ws5mPlatform,
        }));
        const t0 = performance.now();
        assert.throws(
          () => router.registerHandlers('com.q4b.router', handlers1024),
          (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
          'IntentRouter.registerHandlers 1024 handlers sharing 5 MB platform must throw QuotaExceededError(EQUOTA)'
        );
        assert.throws(
          () => router.registerHandlers('com.q4b.router', [{ action: 'view', extension: '.opt' }], { platform: ws5mPlatform }),
          (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
          'IntentRouter.registerHandlers 5 MB opts.platform must throw QuotaExceededError(EQUOTA)'
        );
        assert.ok(performance.now() - t0 < 50, 'IntentRouter 5 MB pre-trim rejections must be < 50 ms');
      }

      {
        const ws20mPlatform = `${' '.repeat(20_000_000)}android`;
        const handlers1024 = Array.from({ length: 1024 }, (_, i) => ({
          action: 'view',
          extension: `.f${i}`,
          platform: ws20mPlatform,
        }));
        const t0 = performance.now();
        assert.throws(
          () => router.registerHandlers('com.q4b.router', handlers1024),
          (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
          'IntentRouter.registerHandlers 1024 handlers sharing 20 MB platform must throw QuotaExceededError(EQUOTA)'
        );
        assert.throws(
          () => router.registerHandlers('com.q4b.router', [{ action: 'view', extension: '.opt2' }], { platform: ws20mPlatform }),
          (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
          'IntentRouter.registerHandlers 20 MB opts.platform must throw QuotaExceededError(EQUOTA)'
        );
        assert.ok(performance.now() - t0 < 50, 'IntentRouter 20 MB pre-trim rejections must be < 50 ms');
      }

      // Assert zero mutation of IntentRouter state
      assert.equal(router.resolve({ action: 'view', extension: '.baseline' }).length, 1);
      assert.equal(router.resolve({ action: 'view', extension: '.e0' }).length, 0);
      assert.equal(router.resolve({ action: 'view', extension: '.f0' }).length, 0);
      assert.equal(router.resolve({ action: 'view', extension: '.opt' }).length, 0);

      // --- B. Q5-B: Retained-state OOM guards ---
      // 1. NotificationCenter.invokeAction(): 20x with 120k {} input -> call #1 succeeds, #2-#20 throw EQUOTA atomically
      {
        const nBig = nc.post({
          appId: 'com.q5b.notif',
          title: 'Big Invoke',
          actions: [{ id: 'go', label: 'Go' }],
        });
        const big120k = [Array(60_000).fill({}), Array(60_000).fill({})];
        const firstInvoke = nc.invokeAction(nBig.id, 'go', { input: big120k });
        assert.equal(firstInvoke.ok, true);
        assert.equal(firstInvoke.actionId, 'go');
        assert.equal(nc.get(nBig.id).invokedActions.length, 1);

        for (let i = 1; i < 20; i += 1) {
          assert.throws(
            () => nc.invokeAction(nBig.id, 'go', { input: big120k }),
            (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
            `invokeAction call #${i + 1} with 120k {} must throw QuotaExceededError(EQUOTA)`
          );
        }
        assert.equal(nc.get(nBig.id).invokedActions.length, 1, 'Rejected invokeAction calls must be atomic (invokedActions.length === 1)');

        // MAX_INVOKED_ACTIONS = 64 count cap on tiny inputs
        const nTiny = nc.post({
          appId: 'com.q5b.notif',
          title: 'Count Cap',
          actions: [{ id: 'ping', label: 'Ping' }],
        });
        for (let i = 0; i < 64; i += 1) {
          nc.invokeAction(nTiny.id, 'ping', { input: { seq: i } });
        }
        assert.equal(nc.get(nTiny.id).invokedActions.length, 64);
        assert.throws(
          () => nc.invokeAction(nTiny.id, 'ping', { input: { seq: 64 } }),
          (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
          '65th invokeAction call must throw QuotaExceededError(EQUOTA) at MAX_INVOKED_ACTIONS = 64'
        );
        assert.equal(nc.get(nTiny.id).invokedActions.length, 64);
      }

      // 2. SharedClipboard: 249k {} rejects immediately on call #1 with EFBIG; 20x large JSON + history(20) enforces _maxHistoryBytes eviction & lazy clone isolation
      {
        const big249k = [Array(100_000).fill({}), Array(100_000).fill({}), Array(49_000).fill({})];
        const t0 = performance.now();
        assert.throws(
          () => cb.set({ json: big249k }),
          (err) => isTypedQuota(err, ERROR_CODES.EFBIG),
          'SharedClipboard.set({ json: 249k {} }) must reject immediately on call #1 with QuotaExceededError(EFBIG)'
        );
        const cbRejectMs = performance.now() - t0;
        assert.ok(cbRejectMs < 100, `SharedClipboard 249k {} rejection must complete in <100ms, got ${cbRejectMs.toFixed(1)}ms`);
        assert.equal(cb.get(), null, 'Rejected set() must leave clipboard untouched');

        // 20 x set({ json: validLargeObj }) (~1.5 MB each) + history(20) enforces cumulative _maxHistoryBytes eviction
        const blob1_5m = 'V'.repeat(1_500_000);
        for (let i = 0; i < 20; i += 1) {
          cb.set({
            json: {
              seq: i,
              nested: { tag: `item-${i}`, arr: [i, i + 1] },
              blob: blob1_5m,
            },
          });
        }
        const hist = cb.history(20);
        assert.ok(hist.length >= 1 && hist.length < 20, `Cumulative _maxHistoryBytes must evict oldest entries (expected <20, got ${hist.length})`);
        assert.equal(hist[0].json.seq, 19, 'Newest entry must be preserved at history[0]');
        assert.equal(hist[0].json.nested.tag, 'item-19');
        assert.ok(hist.every((entry) => entry.json.seq > 0), 'Oldest entry (seq=0) must have been evicted');

        // Lazy JSON clone isolation: mutating returned get().json, get('application/json'), and history()[0].json must NOT affect stored record
        const got1 = cb.get();
        got1.json.seq = -999;
        got1.json.nested.tag = 'CORRUPTED_GET';
        got1.json.nested.arr.push(999);

        const gotRawJson = cb.get('application/json');
        gotRawJson.seq = -888;
        gotRawJson.nested.tag = 'CORRUPTED_MIME';

        hist[0].json.seq = -777;
        hist[0].json.nested.tag = 'CORRUPTED_HIST';

        const got2 = cb.get();
        assert.equal(got2.json.seq, 19, 'Mutating returned get().json must not corrupt subsequent get().json');
        assert.equal(got2.json.nested.tag, 'item-19');
        assert.deepEqual(got2.json.nested.arr, [19, 20]);

        const hist2 = cb.history(20);
        assert.equal(hist2[0].json.seq, 19, 'Mutating returned get()/history() must not corrupt subsequent history()');
        assert.equal(hist2[0].json.nested.tag, 'item-19');
      }

      // --- C. Obs-W10: O(1) Symbol.description across all 7 M2B modules (70x Symbol('S'.repeat(5M)) in < 100 ms) ---
      {
        const hugeSym = Symbol('S'.repeat(5_000_000));
        const expectedSymMarker = 'Symbol([String(5000000)])';
        const tSym0 = performance.now();

        for (let i = 0; i < 10; i += 1) {
          // 1. IPCManager
          assert.throws(
            () => ipc.send(hugeSym, 0, null),
            (err) => err instanceof OmniOSError && err.code === ERROR_CODES.ENOENT && err.message.includes(expectedSymMarker)
          );
          // 2. SharedClipboard
          assert.throws(
            () => cb.set({ mime: hugeSym, data: 'x' }),
            (err) => isTypedEinval(err) && err.message.includes(expectedSymMarker)
          );
          // 3. IntentRouter
          assert.throws(
            () => router.resolveChooser(hugeSym, 'com.obsw10.app'),
            (err) => err instanceof OmniOSError && err.code === ERROR_CODES.ENOENT && err.message.includes(expectedSymMarker)
          );
          // 4. NotificationCenter
          assert.throws(
            () => nc.dismiss(hugeSym),
            (err) => err instanceof OmniOSError && err.code === ERROR_CODES.ENOENT && err.message.includes(expectedSymMarker)
          );
          // 5. Compositor
          assert.throws(
            () => comp.setShellMode(hugeSym),
            (err) => isTypedEinval(err) && err.message.includes(expectedSymMarker)
          );
          // 6. zip.mjs
          assert.throws(
            () => createZip([{ name: 'a.txt', data: 'hi', method: hugeSym }]),
            (err) => err instanceof FormatError && err.code === ERROR_CODES.EINVAL && err.message.includes(expectedSymMarker)
          );
          // 7. PackageManager
          await assert.rejects(
            () => pkg.launch(hugeSym),
            (err) => err instanceof OmniOSError && err.code === ERROR_CODES.ENOENT && err.message.includes(expectedSymMarker)
          );
        }

        const sym70Ms = performance.now() - tSym0;
        assert.ok(sym70Ms < 100, `70x Symbol(5M) across all 7 M2B modules must complete in <100ms, got ${sym70Ms.toFixed(1)}ms`);
      }
    } finally {
      comp.stop();
      ipc.stop();
      pkg.close();
      storage.close();
    }
  });
});

// ============================================================================
// SUITE 24: Iteration 12 Wave 11 Regressions (R1-A, R1-B, R2-B, R3-B, Obs-M2B, Obs-Rev2, Obs-W11)
// ============================================================================

describe('Suite 24: Iteration 12 Wave 11 Regressions (R1-A, R1-B, R2-B, R3-B, Obs-M2B, Obs-Rev2, Obs-W11)', () => {
  function isTypedEinval(err) {
    return (
      err instanceof OmniOSError &&
      err.code === ERROR_CODES.EINVAL &&
      !(err instanceof TypeError) &&
      !(err instanceof SyntaxError) &&
      !(err instanceof RangeError)
    );
  }

  function isTypedQuota(err, expectedCode = ERROR_CODES.EQUOTA) {
    return (
      err instanceof QuotaExceededError &&
      err instanceof OmniOSError &&
      err.code === expectedCode &&
      !(err instanceof RangeError)
    );
  }

  it('24.1 (R1-A + Obs-M2B): Iterative VFS /tmp (depth-4500) & SQLite (depth-6000) subtree deletion, open-FD deferred reclaim, sticky-bit atomic rollback, and PackageManager deep sandbox uninstall', async () => {
    const storage = new SqliteStorage(':memory:');
    const um = new UserManager({ storage });
    const vfs = new VFS({ storage, userManager: um, maxTmpBytes: 64 * 1024 });
    const pm = new PackageManager({ storage, vfs, users: um });

    const seg1500 = Array.from({ length: 1500 }, () => 'a').join('/');
    const userCtx = { uid: DEFAULT_USER_UID, gid: DEFAULT_USER_GID };
    const rootCtx = { uid: ROOT_UID, gid: ROOT_GID };

    try {
      // --- A. /tmp depth-4,500 (3 mkdir + 2 rename + rmdir recursive) with maxTmpBytes: 64 KiB ---
      {
        vfs.mkdir(`/tmp/d0/${seg1500}`, { recursive: true, ...userCtx });
        vfs.writeFile(`/tmp/d0/${seg1500}/fill.bin`, new Uint8Array(64 * 1024), userCtx);
        assert.equal(vfs.virtualMounts.tmpFs.usedBytes, 64 * 1024);

        vfs.mkdir(`/tmp/d1/${seg1500}`, { recursive: true, ...userCtx });
        vfs.rename('/tmp/d0', `/tmp/d1/${seg1500}/c`, userCtx);
        vfs.mkdir(`/tmp/d2/${seg1500}`, { recursive: true, ...userCtx });
        vfs.rename('/tmp/d1', `/tmp/d2/${seg1500}/c`, userCtx);

        // Iterative _assertCanDeleteTmpSubtree + _destroySubtree completes without RangeError
        vfs.rmdir('/tmp/d2', { recursive: true, ...userCtx });

        assert.equal(vfs.readdir('/tmp', rootCtx).length, 0, '/tmp must have 0 visible entries after deep rmdir');
        assert.equal(vfs.virtualMounts.tmpFs.usedBytes, 0, '/tmp usedBytes must reclaim completely to 0');
        assert.equal(vfs.virtualMounts.tmpFs._nodesByIno.size, 1, 'Only /tmp root inode must remain in _nodesByIno');

        // Subsequent root writeFile/readFile on /tmp succeeds cleanly
        vfs.writeFile('/tmp/root_after_deep.txt', 'healthy-tmpfs', rootCtx);
        assert.equal(vfs.readFile('/tmp/root_after_deep.txt', { encoding: 'utf8', ...rootCtx }), 'healthy-tmpfs');
        vfs.unlink('/tmp/root_after_deep.txt', rootCtx);
        assert.equal(vfs.virtualMounts.tmpFs.usedBytes, 0);
        assert.equal(vfs.virtualMounts.tmpFs._nodesByIno.size, 1);
      }

      // --- B. Deep /tmp subtree with open unlinked FD defers reclaim until close(fd) ---
      {
        vfs.mkdir(`/tmp/o0/${seg1500}`, { recursive: true, ...userCtx });
        const leafPayload = new Uint8Array(4096).fill(0x5a);
        const leafPath = `/tmp/o0/${seg1500}/open_leaf.bin`;
        vfs.writeFile(leafPath, leafPayload, userCtx);

        const fd = vfs.open(leafPath, OPEN_FLAGS.O_RDONLY, userCtx);
        try {
          vfs.mkdir(`/tmp/o1/${seg1500}`, { recursive: true, ...userCtx });
          vfs.rename('/tmp/o0', `/tmp/o1/${seg1500}/c`, userCtx);
          vfs.mkdir(`/tmp/o2/${seg1500}`, { recursive: true, ...userCtx });
          vfs.rename('/tmp/o1', `/tmp/o2/${seg1500}/c`, userCtx);
          // Add closed sibling file to verify non-open descendants reclaim immediately
          vfs.writeFile('/tmp/o2/closed_sibling.bin', new Uint8Array(2048).fill(0x3c), userCtx);
          assert.equal(vfs.virtualMounts.tmpFs.usedBytes, 4096 + 2048);

          vfs.rmdir('/tmp/o2', { recursive: true, ...userCtx });
          assert.equal(vfs.readdir('/tmp', rootCtx).length, 0);
          assert.equal(
            vfs.virtualMounts.tmpFs.usedBytes,
            4096,
            'Closed descendants must reclaim immediately while open unlinked FD defers its 4096 bytes'
          );
          assert.equal(
            vfs.virtualMounts.tmpFs._nodesByIno.size,
            2,
            'Only /tmp root + open unlinked leaf inode must remain while FD is open'
          );

          const readBack = vfs.read(fd, 4096);
          assert.equal(readBack.byteLength, 4096);
          assert.equal(readBack[0], 0x5a);
          assert.equal(readBack[4095], 0x5a);
        } finally {
          vfs.close(fd);
        }

        assert.equal(vfs.virtualMounts.tmpFs.usedBytes, 0, 'close(fd) must reclaim deferred unlinked /tmp bytes to 0');
        assert.equal(vfs.virtualMounts.tmpFs._nodesByIno.size, 1, 'close(fd) must remove unlinked inode from _nodesByIno');
      }

      // --- C. Deep sticky-bit 0o1777 EACCES rolls back atomically with zero partial deletion ---
      {
        vfs.mkdir(`/tmp/s0/${seg1500}`, { recursive: true, ...userCtx });
        const stickyDir = `/tmp/s0/${seg1500}`;
        vfs.chown(stickyDir, ROOT_UID, ROOT_GID, rootCtx);
        vfs.chmod(stickyDir, 0o1777, rootCtx);
        vfs.writeFile(`${stickyDir}/root_owned.bin`, new Uint8Array(512).fill(0x11), rootCtx);

        vfs.mkdir(`/tmp/s1/${seg1500}`, { recursive: true, ...userCtx });
        vfs.rename('/tmp/s0', `/tmp/s1/${seg1500}/c`, userCtx);
        vfs.mkdir(`/tmp/s2/${seg1500}`, { recursive: true, ...userCtx });
        vfs.rename('/tmp/s1', `/tmp/s2/${seg1500}/c`, userCtx);
        vfs.writeFile('/tmp/s2/user_owned.bin', new Uint8Array(256).fill(0x22), userCtx);

        const usedBefore = vfs.virtualMounts.tmpFs.usedBytes;
        const inosBefore = vfs.virtualMounts.tmpFs._nodesByIno.size;
        assert.equal(usedBefore, 512 + 256);

        assert.throws(
          () => vfs.rmdir('/tmp/s2', { recursive: true, ...userCtx }),
          (err) => err instanceof VfsError && err.code === ERROR_CODES.EACCES,
          'Deep sticky-bit root-owned file must deny unprivileged rmdir with VfsError(EACCES)'
        );

        assert.equal(vfs.virtualMounts.tmpFs.usedBytes, usedBefore, 'Sticky-bit EACCES must leave usedBytes untouched');
        assert.equal(vfs.virtualMounts.tmpFs._nodesByIno.size, inosBefore, 'Sticky-bit EACCES must leave all inodes intact');
        assert.equal(vfs.stat('/tmp/s2/user_owned.bin', rootCtx).size, 256, 'Sibling file must not be partially deleted');

        // Root cleanup succeeds cleanly
        vfs.rmdir('/tmp/s2', { recursive: true, ...rootCtx });
        assert.equal(vfs.virtualMounts.tmpFs.usedBytes, 0);
        assert.equal(vfs.virtualMounts.tmpFs._nodesByIno.size, 1);
      }

      // --- D. SQLite depth-6,000 (4 mkdir + 3 rename + rmdir recursive as root) ---
      {
        const baselineInodes = storage.get('SELECT COUNT(*) AS cnt FROM vfs_inodes').cnt;

        vfs.mkdir(`/home/user/sql0/${seg1500}`, { recursive: true, ...userCtx });
        vfs.writeFile(`/home/user/sql0/${seg1500}/deep.txt`, 'sqlite-depth-6000', userCtx);
        for (let i = 1; i <= 3; i += 1) {
          vfs.mkdir(`/home/user/sql${i}/${seg1500}`, { recursive: true, ...userCtx });
          vfs.rename(`/home/user/sql${i - 1}`, `/home/user/sql${i}/${seg1500}/c`, userCtx);
        }

        vfs.rmdir('/home/user/sql3', { recursive: true, ...rootCtx });

        assert.throws(
          () => vfs.stat('/home/user/sql3', rootCtx),
          (err) => err instanceof VfsError && err.code === ERROR_CODES.ENOENT,
          'SQLite depth-6000 root directory must be completely removed (ENOENT)'
        );
        const afterInodes = storage.get('SELECT COUNT(*) AS cnt FROM vfs_inodes').cnt;
        assert.equal(afterInodes, baselineInodes, 'SQLite recursive rmdir must leave zero leaked vfs_inodes rows');
      }

      // --- E. Cross-module Obs-M2B: PackageManager deep sandbox (depth 3,000+ + symlink + file) uninstall ---
      {
        const appId = 'com.iter12.deepsandbox';
        const apkZip = createZip([
          { name: 'AndroidManifest.xml', data: `<manifest package="${appId}"/>` },
          { name: 'classes.dex', data: 'dex\n035\0' },
          { name: 'res/raw/app.txt', data: 'binary-stub' },
        ]);
        pm.registerRuntime('android', {
          platform: 'android',
          inspectPackage: () => ({
            format: PACKAGE_FORMATS.ANDROID_APK,
            platform: 'android',
            appId,
            name: 'Deep Sandbox App',
            version: '1.0.0',
          }),
          createExecutionContext: () => makeWorkExecContext(),
        });

        const installed = await pm.install(apkZip, { filenameHint: 'deepsandbox.apk' });
        assert.equal(installed.appId, appId);
        assert.ok(installed.dataDir && installed.dataDir.startsWith('/var/appdata/android/'));
        assert.ok(installed.installDir && installed.installDir.startsWith('/apps/android/'));

        const appCtx = { uid: installed.uid, gid: installed.gid };
        // Build depth 3,000+ directory tree + file + symlink inside the app's sandbox as the sandboxed app
        vfs.mkdir(`${installed.dataDir}/b0/${seg1500}`, { recursive: true, ...appCtx });
        vfs.writeFile(`${installed.dataDir}/b0/${seg1500}/payload.dat`, 'nested-sandbox-data', appCtx);
        vfs.symlink('payload.dat', `${installed.dataDir}/b0/${seg1500}/link_to_payload`, appCtx);
        vfs.mkdir(`${installed.dataDir}/b1/${seg1500}`, { recursive: true, ...appCtx });
        vfs.rename(`${installed.dataDir}/b0`, `${installed.dataDir}/b1/${seg1500}/c`, appCtx);
        // Also place a nested symlink + file inside installDir
        vfs.symlink('app.txt', `${installed.installDir}/res/raw/app_link`, rootCtx);

        const tUn0 = performance.now();
        const uninstallSummary = await pm.uninstall(appId, { purgeData: true });
        const uninstallMs = performance.now() - tUn0;

        assert.equal(uninstallSummary.removed, true);
        assert.equal(uninstallSummary.purgedData, true);
        assert.ok(
          uninstallMs < 1000,
          `PackageManager.uninstall with depth-3000+ sandbox must complete in <1000ms, got ${uninstallMs.toFixed(1)}ms`
        );
        assert.equal(pm.get(appId), null);
        assert.throws(
          () => vfs.lstat(installed.dataDir, rootCtx),
          (err) => err instanceof VfsError && err.code === ERROR_CODES.ENOENT,
          'Uninstalled app sandbox dataDir must be completely removed (ENOENT)'
        );
        assert.throws(
          () => vfs.lstat(installed.installDir, rootCtx),
          (err) => err instanceof VfsError && err.code === ERROR_CODES.ENOENT,
          'Uninstalled app installDir must be completely removed (ENOENT)'
        );
      }
    } finally {
      pm.close();
      vfs.close();
      um.close();
      storage.close();
    }
  });

  it('24.2 (R1-B + Obs-W11): zip.mjs zero-Trie sorted-adjacent collision detector on Python 4,000x256-depth ZIP, all collision variants, depth 256/257 boundary, and bounded extractZipEntry errors', async () => {
    const storage = new SqliteStorage(':memory:');
    const pm = new PackageManager({ storage });

    try {
      assert.equal(MAX_ZIP_PATH_DEPTH, 256);

      // --- A. Real 4,000 x 256-depth valid ZIP built in-memory via host Python 3 zipfile (zero /tmp files) ---
      const zip4kBuf = execFileSync(
        'python3',
        [
          '-c',
          'import sys, io, zipfile\n' +
            'buf = io.BytesIO()\n' +
            'tail = "a/" * 254 + "f"\n' +
            'with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:\n' +
            '    for i in range(4000):\n' +
            '        zf.writestr(f"d{i}/{tail}", b"")\n' +
            'sys.stdout.buffer.write(buf.getvalue())\n',
        ],
        { maxBuffer: 16 * 1024 * 1024 }
      );
      const zip4kBytes = new Uint8Array(zip4kBuf.buffer, zip4kBuf.byteOffset, zip4kBuf.byteLength);

      const tList0 = performance.now();
      const parsed4k = listZipEntries(zip4kBytes);
      const listMs = performance.now() - tList0;
      assert.equal(parsed4k.entries.size, 4000, '4,000 x 256-depth ZIP must parse all 4,000 entries');
      assert.equal(parsed4k.entryList.length, 4000);
      assert.ok(parsed4k.entries.has(`d0/${'a/'.repeat(254)}f`));
      assert.ok(parsed4k.entries.has(`d3999/${'a/'.repeat(254)}f`));
      assert.ok(listMs < 500, `listZipEntries(4,000 x 256-depth) must complete in <500ms, got ${listMs.toFixed(1)}ms`);

      const detector = new FormatDetector();
      const tDet0 = performance.now();
      const detected4k = detector.detect(zip4kBytes, 'deep4000.zip');
      const detMs = performance.now() - tDet0;
      assert.equal(detected4k.details?.container, 'zip');
      assert.equal(detected4k.details?.entryCount, 4000);
      assert.ok(detMs < 500, `FormatDetector.detect(4,000 x 256-depth) must complete in <500ms, got ${detMs.toFixed(1)}ms`);

      const tInsp0 = performance.now();
      await assert.rejects(
        () => pm.inspect(zip4kBytes, 'deep4000.zip'),
        (err) =>
          err instanceof FormatError &&
          err.code === 'E_UNKNOWN_FORMAT' &&
          err.details?.container === 'zip' &&
          err.details?.entryCount === 4000,
        'PackageManager.inspect(4,000 x 256-depth generic ZIP) must parse all 4,000 entries cleanly and report E_UNKNOWN_FORMAT'
      );
      const inspMs = performance.now() - tInsp0;
      assert.ok(inspMs < 500, `PackageManager.inspect(4,000 x 256-depth) must complete in <500ms, got ${inspMs.toFixed(1)}ms`);

      // --- B. All collision variants throw FormatError(E_MALFORMED_ZIP) in BOTH createZip AND listZipEntries ---
      const collisionCases = [
        ['file_vs_file', ['item.txt', 'item.txt']],
        ['dir_vs_dir', ['sub/', 'sub/']],
        ['file_vs_file_dir', ['node', 'node/']],
        ['file_dir_vs_file', ['node/', 'node']],
        ['file_vs_file_child', ['leaf', 'leaf/child.txt']],
        ['file_child_vs_file', ['leaf/child.txt', 'leaf']],
      ];

      for (const [label, names] of collisionCases) {
        assert.throws(
          () => createZip(names.map((n) => ({ name: n, data: n.endsWith('/') ? '' : 'v' }))),
          (err) => err instanceof FormatError && err.code === ZIP_ERROR_CODES.E_MALFORMED_ZIP,
          `createZip collision (${label}) must throw FormatError(E_MALFORMED_ZIP)`
        );

        const pyCollideBuf = execFileSync(
          'python3',
          [
            '-c',
            'import sys, io, json, warnings, zipfile\n' +
              'warnings.simplefilter("ignore")\n' +
              'names = json.loads(sys.argv[1])\n' +
              'buf = io.BytesIO()\n' +
              'with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:\n' +
              '    for n in names:\n' +
              '        zf.writestr(n, b"" if n.endswith("/") else b"v")\n' +
              'sys.stdout.buffer.write(buf.getvalue())\n',
            JSON.stringify(names),
          ],
          { maxBuffer: 4 * 1024 * 1024 }
        );
        assert.throws(
          () => listZipEntries(pyCollideBuf),
          (err) => err instanceof FormatError && err.code === ZIP_ERROR_CODES.E_MALFORMED_ZIP,
          `listZipEntries collision (${label}) must throw FormatError(E_MALFORMED_ZIP)`
        );
      }

      // --- C. Valid dir/item.txt + dir/ (both orders), prototype-safe paths, and exact depth 256 vs 257 ---
      for (const [orderLabel, ordered] of [
        ['child_then_dir', [{ name: 'dir/item.txt', data: 'order1' }, { name: 'dir/', data: '' }]],
        ['dir_then_child', [{ name: 'dir/', data: '' }, { name: 'dir/item.txt', data: 'order2' }]],
      ]) {
        const z = createZip([...ordered, { name: '__proto__/constructor/prototype.txt', data: `proto-${orderLabel}` }]);
        const arc = readZip(z);
        assert.equal(arc.entries.size, 3);
        assert.equal(new TextDecoder().decode(arc.readBytes('dir/item.txt')), orderLabel === 'child_then_dir' ? 'order1' : 'order2');
        assert.equal(
          new TextDecoder().decode(arc.readBytes('__proto__/constructor/prototype.txt')),
          `proto-${orderLabel}`
        );
        assert.equal(Object.prototype.polluted, undefined);
      }

      const depth256Name = `${'p/'.repeat(255)}leaf.txt`;
      const depth257Name = `${'p/'.repeat(256)}leaf.txt`;
      const depth256Zip = createZip([{ name: depth256Name, data: 'exact-256' }]);
      assert.equal(new TextDecoder().decode(extractZipEntry(depth256Zip, depth256Name)), 'exact-256');

      assert.throws(
        () => createZip([{ name: depth257Name, data: 'too-deep' }]),
        (err) => err instanceof FormatError && err.code === ZIP_ERROR_CODES.E_ARCHIVE_BOMB,
        'createZip depth 257 must throw FormatError(E_ARCHIVE_BOMB)'
      );
      const pyDepth257Buf = execFileSync(
        'python3',
        [
          '-c',
          'import sys, io, zipfile\n' +
            'buf = io.BytesIO()\n' +
            'with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:\n' +
            '    zf.writestr(("p/" * 256) + "leaf.txt", b"x")\n' +
            'sys.stdout.buffer.write(buf.getvalue())\n',
        ],
        { maxBuffer: 4 * 1024 * 1024 }
      );
      assert.throws(
        () => listZipEntries(pyDepth257Buf),
        (err) => err instanceof FormatError && err.code === ZIP_ERROR_CODES.E_ARCHIVE_BOMB,
        'listZipEntries depth 257 must throw FormatError(E_ARCHIVE_BOMB)'
      );

      // --- D. Obs-W11: manual oversized ZipEntryMeta.name produces bounded error message (<= 512 chars) ---
      {
        const tinyZip = createZip([{ name: 'ok.txt', data: 'hello-zip' }]);
        const realMeta = listZipEntries(tinyZip).entries.get('ok.txt');
        const hugeName = 'x'.repeat(200_000);

        const badCrcMeta = { ...realMeta, name: hugeName, crc32: (realMeta.crc32 ^ 0xffffffff) >>> 0 };
        assert.throws(
          () => extractZipEntry(tinyZip, badCrcMeta),
          (err) =>
            err instanceof FormatError &&
            err.code === ZIP_ERROR_CODES.E_CRC_MISMATCH &&
            err.message.length <= 512 &&
            err.message.includes('[String(200000)]'),
          'extractZipEntry with oversized manual ZipEntryMeta.name (CRC error) must bound error message <= 512 chars'
        );

        const badSizeMeta = { ...realMeta, name: hugeName, uncompressedSize: 999_999_999 };
        assert.throws(
          () => extractZipEntry(tinyZip, badSizeMeta),
          (err) =>
            err instanceof FormatError &&
            err.code === ZIP_ERROR_CODES.E_ARCHIVE_BOMB &&
            err.message.length <= 512 &&
            err.message.includes('[String(200000)]'),
          'extractZipEntry with oversized manual ZipEntryMeta.name (size error) must bound error message <= 512 chars'
        );
      }
    } finally {
      pm.close();
      storage.close();
    }
  });

  it('24.3 (R2-B): SharedClipboard O(N) pre-JSON.parse scanner blocks 8.38 MB / 6.0 MB container bombs & depth-65 fast, preserves pretty/249k-float JSON, and stages 128 aliased MIME keys last-write-wins', () => {
    const cb = new SharedClipboard();

    // --- A. R2-B-1: Pre-JSON.parse O(N) scanner ---
    {
      // 8.38 MB object-array bomb -> QuotaExceededError(EFBIG) fast (< 150 ms)
      const objBomb = `[${'{},'.repeat(2_796_000)}{}]`;
      const t0 = performance.now();
      assert.throws(
        () => cb.set({ json: objBomb }),
        (err) => isTypedQuota(err, ERROR_CODES.EFBIG),
        '8.38 MB JSON object-array bomb must reject with QuotaExceededError(EFBIG) before JSON.parse'
      );
      const objBombMs = performance.now() - t0;
      assert.ok(objBombMs < 150, `8.38 MB JSON object-array bomb must reject in <150ms, got ${objBombMs.toFixed(1)}ms`);
      assert.equal(cb.get(), null, 'Rejected JSON bomb must leave clipboard empty');

      // 6.0 MB nested-array bomb -> QuotaExceededError(EFBIG) fast (< 150 ms)
      const nestedArrBomb = `[${`${'['.repeat(60)}${']'.repeat(60)},`.repeat(49_586)}0]`;
      const t1 = performance.now();
      assert.throws(
        () => cb.set({ json: nestedArrBomb }),
        (err) => isTypedQuota(err, ERROR_CODES.EFBIG),
        '6.0 MB nested-array JSON bomb must reject with QuotaExceededError(EFBIG) before JSON.parse'
      );
      const nestedMs = performance.now() - t1;
      assert.ok(nestedMs < 150, `6.0 MB nested-array JSON bomb must reject in <150ms, got ${nestedMs.toFixed(1)}ms`);
      assert.equal(cb.get(), null);

      // Depth-65 JSON string -> OmniOSError(EINVAL) fast (< 50 ms)
      const depth65 = `${'['.repeat(65)}0${']'.repeat(65)}`;
      const t2 = performance.now();
      assert.throws(
        () => cb.set({ json: depth65 }),
        (err) => isTypedEinval(err),
        'Depth-65 JSON string must reject with OmniOSError(EINVAL)'
      );
      assert.ok(performance.now() - t2 < 50, 'Depth-65 JSON string rejection must be < 50 ms');

      // Malformed "]]]" -> OmniOSError(EINVAL)
      assert.throws(
        () => cb.set({ json: ']]]' }),
        (err) => isTypedEinval(err),
        'Malformed "]]]" JSON string must reject with OmniOSError(EINVAL)'
      );

      // Valid depth-64 JSON string passes
      const depth64 = `${'['.repeat(64)}7${']'.repeat(64)}`;
      cb.set({ json: depth64 });
      let cur = cb.get('application/json');
      for (let d = 0; d < 64; d += 1) {
        assert.ok(Array.isArray(cur));
        cur = cur[0];
      }
      assert.equal(cur, 7);

      // Pretty-printed valid JSON with escaped quotes & fake braces/brackets inside string literals succeeds
      const prettyObj = {
        title: 'Escaped "quote" \\\\ and fake braces {{{[[[',
        nested: { ok: true, count: 42 },
        tags: ['a', 'b', 'c'],
      };
      const prettyStr = JSON.stringify(prettyObj, null, 4);
      cb.set({ json: prettyStr });
      assert.deepEqual(cb.get('application/json'), prettyObj);

      // Valid 249k-float JSON string succeeds
      const floats249kStr = JSON.stringify([
        Array(100_000).fill(1.123456789),
        Array(100_000).fill(1.123456789),
        Array(49_000).fill(1.123456789),
      ]);
      cb.set({ json: floats249kStr });
      const parsedFloats = cb.get('application/json');
      assert.equal(parsedFloats.length, 3);
      assert.equal(parsedFloats[0].length, 100_000);
      assert.equal(parsedFloats[1].length, 100_000);
      assert.equal(parsedFloats[2].length, 49_000);
      assert.equal(parsedFloats[0][0], 1.123456789);
    }

    // --- B. R2-B-2: 128 aliased MIME keys deduplicate last-write-wins & still validate earlier invalid MIME keys ---
    {
      const baseArr0 = Array(100_000).fill(1.123456789);
      const baseArr1 = Array(100_000).fill(1.123456789);
      const baseArr2 = Array(49_000).fill(1.123456789);
      const shared298mbStr = JSON.stringify([baseArr0, baseArr1, baseArr2]);
      const finalArr0 = baseArr0.slice();
      finalArr0[0] = 9.87654321;
      const finalAliasStr = JSON.stringify([finalArr0, baseArr1, baseArr2]);

      const aliasedFormats = {};
      for (let i = 0; i < 127; i += 1) {
        aliasedFormats[`application/json;k=${i}`] = shared298mbStr;
      }
      aliasedFormats['application/json;k=127'] = finalAliasStr;

      const tAlias0 = performance.now();
      cb.set({ formats: aliasedFormats });
      const aliasMs = performance.now() - tAlias0;
      assert.ok(
        aliasMs < 500,
        `128 aliased application/json keys sharing 2.98 MB payload must complete in <500ms, got ${aliasMs.toFixed(1)}ms`
      );

      const gotWinner = cb.get('application/json');
      assert.equal(gotWinner.length, 3);
      assert.equal(gotWinner[0].length, 100_000);
      assert.equal(gotWinner[0][0], 9.87654321, 'Last-write-wins staging must store final alias (k=127) payload');

      // An invalid MIME key in an earlier entry must still fail validation with EINVAL without mutating clipboard
      assert.throws(
        () =>
          cb.set({
            formats: {
              'invalid-mime-no-slash': 'bad',
              'application/json;k=0': '{"winner":"should-not-apply"}',
            },
          }),
        (err) => isTypedEinval(err),
        'Invalid MIME key in earlier staged format must still throw OmniOSError(EINVAL)'
      );
      assert.equal(cb.get('application/json')[0][0], 9.87654321, 'Rejected invalid MIME must leave clipboard untouched');
    }
  });

  it('24.4 (R3-B + Obs-Rev2 + Obs-W11): Linear ReDoS elimination & filenameHint cap in PackageManager, IntentRouter colon scheme & whitespace rawPlatform fallback budget, and IPCManager 1e15 timeout clamp with zero TimeoutOverflowWarning', async () => {
    const storage = new SqliteStorage(':memory:');
    const pm = new PackageManager({ storage });
    const router = new IntentRouter();
    const ipc = new IPCManager();
    const ipcHugeDefault = new IPCManager({ defaultRpcTimeoutMs: 1e15 });

    const warnings = [];
    const onWarning = (w) => {
      warnings.push(w);
    };
    process.on('warning', onWarning);

    try {
      // --- A. R3-B: PackageManager.inspect ReDoS & filenameHint length cap ---
      {
        const validWasm = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
        const oversizedHints = [
          ['slash80k', `${'/'.repeat(80_000)}a.wasm`],
          ['dot80k', `a${'.'.repeat(80_000)}a.wasm`],
          ['long16m', `${'a'.repeat(16_000_000)}.wasm`],
        ];

        for (const [label, badHint] of oversizedHints) {
          const t0 = performance.now();
          await assert.rejects(
            () => pm.inspect(validWasm, badHint),
            (err) => isTypedEinval(err),
            `PackageManager.inspect(${label}) must reject oversized filenameHint with OmniOSError(EINVAL)`
          );
          const elapsed = performance.now() - t0;
          assert.ok(elapsed < 50, `PackageManager.inspect(${label}) rejection must be <50ms, got ${elapsed.toFixed(1)}ms`);
        }

        // Valid <= 4096-char slash, dot, and long filenameHint inputs complete fast (< 50 ms) with derived appId.length <= 128
        const validHints = [
          ['slash4080', `${'/'.repeat(4080)}a.wasm`],
          ['dot4080', `a${'.'.repeat(4080)}a.wasm`],
          ['long4090', `${'a'.repeat(4090)}.wasm`],
        ];
        for (const [label, okHint] of validHints) {
          assert.ok(okHint.length <= 4096);
          const t0 = performance.now();
          const insp = await pm.inspect(validWasm, okHint);
          const elapsed = performance.now() - t0;
          assert.equal(insp.format, PACKAGE_FORMATS.UNIVERSAL_WASM);
          assert.ok(
            typeof insp.appId === 'string' && insp.appId.length > 0 && insp.appId.length <= 128,
            `PackageManager.inspect(${label}) derived fallback appId must have length 1..128, got ${insp.appId?.length}`
          );
          assert.ok(elapsed < 50, `PackageManager.inspect(${label}) must complete in <50ms, got ${elapsed.toFixed(1)}ms`);
        }
      }

      // --- B. R3-B + Obs-Rev2: IntentRouter trailing-colon linear strip & whitespace rawPlatform fallback budget ---
      {
        const tColon0 = performance.now();
        router.registerHandlers(
          'com.s',
          Array.from({ length: 240 }, () => ({ scheme: `${':'.repeat(4095)}a` }))
        );
        const colonMs = performance.now() - tColon0;
        assert.ok(colonMs < 100, `IntentRouter 240x 4KB colon scheme must complete in <100ms, got ${colonMs.toFixed(1)}ms`);

        // Valid trailing colons still strip cleanly
        router.registerHandlers('com.s.valid', [{ scheme: 'omnischeme:::', action: 'view' }]);
        const resolved = router.resolve({ uri: 'omnischeme://open/doc' });
        assert.equal(resolved.length, 1);
        assert.equal(resolved[0].appId, 'com.s.valid');

        // Obs-Rev2: whitespace-only rawPlatform falls back to opts.platform and charges platform.length to manifestBudget
        const platform4k = 'p'.repeat(4000);
        const wsFallbackHandlers = Array.from({ length: 300 }, (_, i) => ({
          action: 'view',
          extension: `.fb${i}`,
          platform: '   ',
        }));
        assert.throws(
          () => router.registerHandlers('com.obsrev2.over', wsFallbackHandlers, { platform: platform4k }),
          (err) => isTypedQuota(err, ERROR_CODES.EQUOTA),
          'Whitespace-only rawPlatform falling back to 4000-char opts.platform 300x must exceed 1 MiB manifestBudget (EQUOTA)'
        );
        assert.equal(router.resolve({ action: 'view', extension: '.fb0' }).length, 0);

        // Positive control: explicit non-whitespace descriptor platform does NOT charge fallback platform4k and succeeds
        const explicitHandlers = Array.from({ length: 300 }, (_, i) => ({
          action: 'view',
          extension: `.ex${i}`,
          platform: 'ios',
        }));
        router.registerHandlers('com.obsrev2.ok', explicitHandlers, { platform: platform4k });
        assert.equal(router.resolve({ action: 'view', extension: '.ex0' }).length, 1);
      }

      // --- C. Obs-W11: IPCManager callRpc / request / constructor defaultRpcTimeoutMs with 1e15 emits 0 warnings ---
      {
        ipc.registerRpc('obs.echo', (payload) => ({ echoed: payload }), { ownerPid: 1 });
        ipc.createChannel('obs.reqch', 1);
        ipc.subscribe('obs.reqch', (msg) => {
          ipc.reply(msg.correlationId, { replied: msg.payload });
        });

        ipcHugeDefault.registerRpc('obs.def.echo', (payload) => ({ defEchoed: payload }), { ownerPid: 1 });
        ipcHugeDefault.createChannel('obs.def.ch', 1);
        ipcHugeDefault.subscribe('obs.def.ch', (msg) => {
          ipcHugeDefault.reply(msg.correlationId, { defReplied: msg.payload });
        });

        const r1 = await ipc.callRpc('obs.echo', { k: 1 }, { timeoutMs: 1e15 });
        assert.deepEqual(r1, { echoed: { k: 1 } });

        const r2 = await ipc.request('obs.reqch', 1, { k: 2 }, { timeoutMs: 1e15 });
        assert.deepEqual(r2, { replied: { k: 2 } });

        const r3 = await ipcHugeDefault.callRpc('obs.def.echo', { k: 3 });
        assert.deepEqual(r3, { defEchoed: { k: 3 } });

        const r4 = await ipcHugeDefault.request('obs.def.ch', 1, { k: 4 });
        assert.deepEqual(r4, { defReplied: { k: 4 } });

        // Yield a macrotask so any deferred Node process warning listener fires before asserting
        await new Promise((resolve) => setTimeout(resolve, 15));

        const overflowWarnings = warnings.filter((w) => w?.name === 'TimeoutOverflowWarning');
        assert.equal(
          overflowWarnings.length,
          0,
          `IPCManager timeoutMs=1e15 must emit zero TimeoutOverflowWarning, got ${overflowWarnings.length}`
        );
        assert.equal(warnings.length, 0, `Expected 0 process warnings, got ${warnings.map((w) => w?.name).join(', ')}`);
      }
    } finally {
      process.off('warning', onWarning);
      ipcHugeDefault.stop();
      ipc.stop();
      pm.close();
      storage.close();
    }
  });

  it('24.5 (S1-A + Obs-Rev1 + Obs-Chal1 + Obs-W12-FD): UnifiedConfigStore linear registry key strip & 250x HKCR IntentRouter index bound, PathTranslator.isPathWithinRoot parity & speed, PermissionBroker 1e15 32-bit timeout clamp, and FormatDetector newline-safe batch regexes', async () => {
    const storage = new SqliteStorage(':memory:');
    const store = new UnifiedConfigStore({ storage });
    const router = new IntentRouter();
    const warnings = [];
    const onWarning = (w) => {
      warnings.push(w);
    };
    process.on('warning', onWarning);

    const brokerHugeDefault = new PermissionBroker({ storage, promptTimeoutMs: 1e15 });
    const brokerDefault = new PermissionBroker({ storage });

    try {
      // --- A. S1-A: UnifiedConfigStore.registry.normalizeKeyPath linear strip + IntentRouter.indexRegistryAssociations ---
      {
        const poisonBack = `a${'\\'.repeat(4094)}a`;
        const poisonFwd = `a${'/'.repeat(4094)}a`;
        assert.equal(poisonBack.length, MAX_REG_KEY_PATH_CHARS);
        assert.equal(poisonFwd.length, MAX_REG_KEY_PATH_CHARS);

        const tBack0 = performance.now();
        const missBack = store.registry.getValue('HKCU', poisonBack, 'v');
        const backMs = performance.now() - tBack0;
        assert.equal(missBack, null);
        assert.ok(
          backMs < 20,
          `Single 4096-char backslash registry getValue must complete in <20ms, got ${backMs.toFixed(2)}ms`
        );

        const tFwd0 = performance.now();
        const missFwd = store.registry.getValue('HKCU', poisonFwd, 'v');
        const fwdMs = performance.now() - tFwd0;
        assert.equal(missFwd, null);
        assert.ok(
          fwdMs < 20,
          `Single 4096-char forward-slash registry getValue must complete in <20ms, got ${fwdMs.toFixed(2)}ms`
        );

        // Mixed leading/trailing slashes normalize identically to 'a\\b'
        store.registry.setValue('HKCU', '\\\\\\a\\\\b///', 'v', REGISTRY_TYPES.REG_SZ, 'mixed-normalized');
        const canonRec = store.registry.getValue('HKCU', 'a\\b', 'v');
        assert.ok(canonRec !== null);
        assert.equal(canonRec.data, 'mixed-normalized');
        assert.equal(canonRec.keyPath, 'a\\b');

        const mixedRec = store.registry.getValue('HKCU', '///a///b\\\\\\', 'v');
        assert.ok(mixedRec !== null);
        assert.equal(mixedRec.data, 'mixed-normalized');
        assert.equal(mixedRec.keyPath, 'a\\b');

        // Backslash and forward-slash collapsed keyPaths map to identical 'a\\a' key
        store.registry.setValue('HKCU', poisonBack, 'v', REGISTRY_TYPES.REG_SZ, 'collapsed-val');
        assert.equal(store.registry.getValue('HKCU', 'a\\a', 'v')?.data, 'collapsed-val');
        assert.equal(store.registry.getValue('HKCU', poisonFwd, 'v')?.data, 'collapsed-val');

        // All-slashes throws EINVAL on getValue and succeeds on enumKey (allowEmpty: true)
        assert.throws(
          () => store.registry.getValue('HKCU', '\\\\\\', 'v'),
          (err) => isTypedEinval(err),
          'All-backslash keyPath on getValue must throw OmniOSError(EINVAL)'
        );
        assert.throws(
          () => store.registry.getValue('HKCU', '///', 'v'),
          (err) => isTypedEinval(err),
          'All-forward-slash keyPath on getValue must throw OmniOSError(EINVAL)'
        );
        const rootEnum = store.registry.enumKey('HKCU', '\\\\\\');
        assert.equal(rootEnum.exists, true);
        assert.equal(rootEnum.keyPath, '');
        assert.ok(Array.isArray(rootEnum.subkeys) && rootEnum.subkeys.includes('a'));

        // Exact Wave 12 cross-module exploit: unprivileged app writes 250 HKCR\.app0..app249 poisoned ProgIDs
        const evilCtx = { uid: 10000, appId: 'com.evil.app' };
        for (let i = 0; i < 250; i += 1) {
          store.registry.setValue('HKCR', `.app${i}`, '', REGISTRY_TYPES.REG_SZ, poisonBack, evilCtx);
        }
        // Plus one valid HKCR extension -> ProgID -> OmniOSAppId to confirm indexing genuinely runs
        store.registry.setValue('HKCR', '.legit13', '', REGISTRY_TYPES.REG_SZ, 'Legit13.Document');
        store.registry.setValue('HKCR', 'Legit13.Document', 'OmniOSAppId', REGISTRY_TYPES.REG_SZ, 'com.legit13.app');

        const tIdx0 = performance.now();
        const idxResult = router.indexRegistryAssociations(store);
        const idxMs = performance.now() - tIdx0;
        assert.ok(
          idxMs < 200,
          `IntentRouter.indexRegistryAssociations across 250 poisoned HKCR ProgIDs must complete in <200ms, got ${idxMs.toFixed(1)}ms`
        );
        assert.equal(idxResult.indexed, 1);
        const resolvedLegit = router.resolve({ action: 'view', extension: '.legit13' });
        assert.equal(resolvedLegit.length, 1);
        assert.equal(resolvedLegit[0].appId, 'com.legit13.app');
      }

      // --- B. Obs-Rev1: PathTranslator isPathWithinRoot parity and 1,000x 4,096-char linear bound ---
      {
        assert.equal(isPathWithinRoot('/', '/'), true);
        assert.equal(isPathWithinRoot('///', '/'), true);
        assert.equal(isPathWithinRoot('/', '///'), true);
        assert.equal(isPathWithinRoot('///', '///'), true);
        assert.equal(isPathWithinRoot('/home/user/', '/home/user'), true);
        assert.equal(isPathWithinRoot('/home/user', '/home/user/'), true);
        assert.equal(isPathWithinRoot('/home/user///', '/home/user///'), true);
        assert.equal(isPathWithinRoot('/home/user/docs', '/home/user'), true);
        assert.equal(isPathWithinRoot('/home/user/docs', '/home/user/'), true);
        assert.equal(isPathWithinRoot('/home/user2', '/home/user'), false);
        assert.equal(isPathWithinRoot('/home/user2', '/home/user/'), false);
        assert.equal(isPathWithinRoot('/home/user', '/home/user/docs'), false);
        assert.equal(isPathWithinRoot('/HOME/USER/docs', '/home/user/', { caseInsensitive: true }), true);
        assert.equal(isPathWithinRoot('/HOME/USER/docs', '/home/user/', { caseInsensitive: false }), false);

        const path4kTrailing = `/${'a'.repeat(4094)}/`;
        const root4kBase = `/${'a'.repeat(4094)}`;
        const path4kSibling = `/${'a'.repeat(4093)}b`;
        const slashHeavy4k = `/${'/'.repeat(4094)}a`;
        assert.equal(path4kTrailing.length, MAX_PATH_LENGTH);
        assert.equal(slashHeavy4k.length, MAX_PATH_LENGTH);

        const tPt0 = performance.now();
        for (let i = 0; i < 1000; i += 1) {
          const mode = i % 3;
          if (mode === 0) {
            assert.equal(isPathWithinRoot(path4kTrailing, root4kBase), true);
          } else if (mode === 1) {
            assert.equal(isPathWithinRoot(path4kSibling, root4kBase), false);
          } else {
            assert.equal(isPathWithinRoot(slashHeavy4k, '/a/'), true);
          }
        }
        const ptMs = performance.now() - tPt0;
        assert.ok(
          ptMs < 50,
          `1,000x worst-case 4,096-char isPathWithinRoot calls must complete in <50ms, got ${ptMs.toFixed(2)}ms`
        );
      }

      // --- C. Obs-Chal1: PermissionBroker 32-bit signed timeout clamp (constructor & per-request) ---
      {
        assert.equal(brokerHugeDefault._promptTimeoutMs, 2_147_483_647);

        // 1. Constructor promptTimeoutMs: 1e15 stays pending past 35ms (does not overflow to 1ms) and resolves cleanly
        let settledCtor = false;
        const pCtor = brokerHugeDefault.checkPermission({
          appId: 'com.iter13.huge.ctor',
          capability: CAPABILITIES.CAMERA_DEVICE,
        });
        pCtor.then(() => {
          settledCtor = true;
        });

        await new Promise((resolve) => setTimeout(resolve, 35));
        assert.equal(
          settledCtor,
          false,
          'PermissionBroker constructor promptTimeoutMs=1e15 must keep prompt pending past 35ms'
        );

        const pendingCtor = brokerHugeDefault.getPendingPrompts();
        assert.equal(pendingCtor.length, 1);
        assert.equal(pendingCtor[0].appId, 'com.iter13.huge.ctor');

        const resolveCtor = brokerHugeDefault.resolvePrompt(pendingCtor[0].promptId, 'allow_once');
        assert.equal(resolveCtor.ok, true);
        assert.equal(resolveCtor.granted, true);

        const outCtor = await pCtor;
        assert.equal(outCtor.granted, true);
        assert.equal(outCtor.policy, PERMISSION_STATES.PROMPT);
        assert.equal(outCtor.reason, 'prompt_allowed_once');
        assert.equal(outCtor.promptId, pendingCtor[0].promptId);

        // 2. Per-request timeoutMs: 1e15 stays pending past 35ms and resolves cleanly via resolvePrompt()
        let settledReq = false;
        const pReq = brokerDefault.checkPermission({
          appId: 'com.iter13.huge.req',
          capability: CAPABILITIES.CAMERA_DEVICE,
          timeoutMs: 1e15,
        });
        pReq.then(() => {
          settledReq = true;
        });

        await new Promise((resolve) => setTimeout(resolve, 35));
        assert.equal(
          settledReq,
          false,
          'PermissionBroker per-request timeoutMs=1e15 must keep prompt pending past 35ms'
        );

        const pendingReq = brokerDefault.getPendingPrompts();
        assert.equal(pendingReq.length, 1);
        assert.equal(pendingReq[0].appId, 'com.iter13.huge.req');

        const resolveReq = brokerDefault.resolvePrompt(pendingReq[0].promptId, 'allow_once');
        assert.equal(resolveReq.ok, true);
        assert.equal(resolveReq.granted, true);

        const outReq = await pReq;
        assert.equal(outReq.granted, true);
        assert.equal(outReq.policy, PERMISSION_STATES.PROMPT);
        assert.equal(outReq.reason, 'prompt_allowed_once');
        assert.equal(outReq.promptId, pendingReq[0].promptId);

        // Negative & non-finite timeouts still reject with SecurityError(EINVAL)
        assert.throws(
          () => new PermissionBroker({ storage, promptTimeoutMs: -1 }),
          (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
        );
        assert.throws(
          () => new PermissionBroker({ storage, promptTimeoutMs: Number.POSITIVE_INFINITY }),
          (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
        );
        await assert.rejects(
          () =>
            brokerDefault.checkPermission({
              appId: 'com.iter13.bad.timeout',
              capability: CAPABILITIES.CAMERA_DEVICE,
              timeoutMs: Number.NaN,
            }),
          (err) => err instanceof SecurityError && err.code === ERROR_CODES.EINVAL
        );

        // Yield macrotask so any deferred Node process warnings are observed
        await new Promise((resolve) => setTimeout(resolve, 15));
        const overflowWarnings = warnings.filter((w) => w?.name === 'TimeoutOverflowWarning');
        assert.equal(
          overflowWarnings.length,
          0,
          `PermissionBroker 1e15 timeouts must emit zero TimeoutOverflowWarning, got ${overflowWarnings.length}`
        );
        assert.equal(warnings.length, 0, `Expected 0 process warnings, got ${warnings.map((w) => w?.name).join(', ')}`);
      }

      // --- D. Obs-W12-FD: FormatDetector newline-safe BATCH_STRONG_PATTERNS ---
      {
        const detector = new FormatDetector();
        const lfBuf = Buffer.from(`${'\n'.repeat(8191)}x`);
        const crBuf = Buffer.from(`${'\r'.repeat(8191)}x`);
        const crlfBuf = Buffer.from(`${'\r\n'.repeat(4095)}x`);

        const tLf0 = performance.now();
        const lfRes = detector.detect(lfBuf);
        const lfMs = performance.now() - tLf0;
        assert.equal(lfRes.format, PACKAGE_FORMATS.UNKNOWN);
        assert.equal(lfRes.platform, 'unknown');
        assert.ok(lfMs < 30, `FormatDetector 8KB LF buffer must complete in <30ms, got ${lfMs.toFixed(2)}ms`);

        const tCr0 = performance.now();
        const crRes = detector.detect(crBuf);
        const crMs = performance.now() - tCr0;
        assert.equal(crRes.format, PACKAGE_FORMATS.UNKNOWN);
        assert.equal(crRes.platform, 'unknown');
        assert.ok(crMs < 30, `FormatDetector 8KB CR buffer must complete in <30ms, got ${crMs.toFixed(2)}ms`);

        const tCrlf0 = performance.now();
        const crlfRes = detector.detect(crlfBuf);
        const crlfMs = performance.now() - tCrlf0;
        assert.equal(crlfRes.format, PACKAGE_FORMATS.UNKNOWN);
        assert.equal(crlfRes.platform, 'unknown');
        assert.ok(crlfMs < 30, `FormatDetector 8KB CRLF buffer must complete in <30ms, got ${crlfMs.toFixed(2)}ms`);

        // Real Windows .bat scripts with leading spaces/tabs/CRLF still detect as windows_bat
        const realBats = [
          '  \t@echo off\r\nsetlocal\r\n',
          '  \tset /a x=1+2\r\n\tgoto :done\r\n',
          '\trem startup script\r\nif %ERRORLEVEL% neq 0 exit /b 1\r\n',
        ];
        for (const script of realBats) {
          const det = detector.detect(Buffer.from(script));
          assert.equal(det.format, PACKAGE_FORMATS.WINDOWS_BAT);
          assert.equal(det.platform, 'windows');
        }

        // Cross-line tokens that must NOT match single-line batch directives
        for (const nonBat of ['@echo\noff\n', 'set\n/a x=1\n']) {
          const det = detector.detect(Buffer.from(nonBat));
          assert.equal(det.format, PACKAGE_FORMATS.UNKNOWN);
          assert.equal(det.platform, 'unknown');
        }
      }
    } finally {
      process.off('warning', onWarning);
      brokerHugeDefault.close();
      brokerDefault.close();
      store.close();
      storage.close();
    }
  });

  it('24.6 (T1-B + Obs-W13-FD): Unprivileged HKCR fault isolation in IntentRouter.indexRegistryAssociations (V1-V4 + WAL close/reopen) and FormatDetector >8 KB UTF-8 boundary handling in detectWindowsBat', () => {
    const evilCtx = { uid: SANDBOX_UID_BASE, appId: 'com.evil.app' };

    // --- A. T1-B V1: Direct NUL OmniOSAppId in unprivileged HKCR\.!dos ---
    {
      const storage = new SqliteStorage(':memory:');
      const store = new UnifiedConfigStore({ storage });
      const router = new IntentRouter();
      try {
        store.registry.setValue('HKCR', '.txt', 'OmniOSAppId', REGISTRY_TYPES.REG_SZ, 'com.sys.notepad');
        store.registry.setValue('HKCR', '.pdf', 'OmniOSAppId', REGISTRY_TYPES.REG_SZ, 'com.sys.pdf');
        store.registry.setValue('HKCR', 'omnios', 'URL Protocol', REGISTRY_TYPES.REG_SZ, '');
        store.registry.setValue('HKCR', 'omnios', 'OmniOSAppId', REGISTRY_TYPES.REG_SZ, 'com.sys.shell');

        store.registry.setValue('HKCR', '.!dos', 'OmniOSAppId', REGISTRY_TYPES.REG_SZ, 'x\0y', evilCtx);

        const res = router.indexRegistryAssociations(store);
        assert.equal(res.indexed, 3);
        assert.deepEqual(
          router.resolve({ action: 'view', extension: '.txt' }).map((c) => c.appId),
          ['com.sys.notepad']
        );
        assert.deepEqual(
          router.resolve({ action: 'view', extension: '.pdf' }).map((c) => c.appId),
          ['com.sys.pdf']
        );
        assert.deepEqual(
          router.resolve({ uri: 'omnios://home' }).map((c) => c.appId),
          ['com.sys.shell']
        );
        assert.deepEqual(router.resolve({ action: 'view', extension: '.!dos' }), []);
      } finally {
        store.close();
        storage.close();
      }
    }

    // --- B. T1-B V2: ProgID indirection to NUL OmniOSAppId (.!prog -> Evil.Prog -> 'evil\0app') ---
    {
      const storage = new SqliteStorage(':memory:');
      const store = new UnifiedConfigStore({ storage });
      const router = new IntentRouter();
      try {
        store.registry.setValue('HKCR', '.txt', 'OmniOSAppId', REGISTRY_TYPES.REG_SZ, 'com.sys.notepad');
        store.registry.setValue('HKCR', '.!prog', '', REGISTRY_TYPES.REG_SZ, 'Evil.Prog', evilCtx);
        store.registry.setValue('HKCR', 'Evil.Prog', 'OmniOSAppId', REGISTRY_TYPES.REG_SZ, 'evil\0app', evilCtx);

        const res = router.indexRegistryAssociations(store);
        assert.equal(res.indexed, 1);
        assert.deepEqual(
          router.resolve({ action: 'view', extension: '.txt' }).map((c) => c.appId),
          ['com.sys.notepad']
        );
        assert.deepEqual(router.resolve({ action: 'view', extension: '.!prog' }), []);
      } finally {
        store.close();
        storage.close();
      }
    }

    // --- C. T1-B V3: Oversized 1.05 MB Content Type safely dropped without aborting loop ---
    {
      const storage = new SqliteStorage(':memory:');
      const store = new UnifiedConfigStore({ storage });
      const router = new IntentRouter();
      try {
        store.registry.setValue('HKCR', '.txt', 'OmniOSAppId', REGISTRY_TYPES.REG_SZ, 'com.sys.notepad');
        store.registry.setValue('HKCR', '.!mime', 'OmniOSAppId', REGISTRY_TYPES.REG_SZ, 'com.evil', evilCtx);
        store.registry.setValue(
          'HKCR',
          '.!mime',
          'Content Type',
          REGISTRY_TYPES.REG_SZ,
          `text/${'a'.repeat(1_050_000)}`,
          evilCtx
        );

        const res = router.indexRegistryAssociations(store);
        assert.equal(res.indexed, 2);
        assert.deepEqual(
          router.resolve({ action: 'view', extension: '.txt' }).map((c) => c.appId),
          ['com.sys.notepad']
        );
        const evilList = router.listHandlers('com.evil');
        assert.equal(evilList.length, 1);
        assert.equal(evilList[0].handlers.length, 1);
        assert.deepEqual(evilList[0].handlers[0].extensions, ['.!mime']);
        assert.deepEqual(evilList[0].handlers[0].mimeTypes, []);
      } finally {
        store.close();
        storage.close();
      }
    }

    // --- D. T1-B V4: 1,025-key descriptor quota flood + dot-whitespace + invalid URL protocol + WAL close/reopen ---
    {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'omnios-m2-t1b-wal-'));
      const dbPath = path.join(tmpDir, 'hkcr-fault-isolation.sqlite');
      let storage1 = null;
      let store1 = null;
      let storage2 = null;
      let store2 = null;

      try {
        storage1 = new SqliteStorage(dbPath);
        store1 = new UnifiedConfigStore({ storage: storage1 });
        const router1 = new IntentRouter();
        const floodCtx = { uid: SANDBOX_UID_BASE, appId: 'com.evil.flood' };

        // Root registers legitimate OS-wide file & URL associations
        store1.registry.setValue('HKCR', '.txt', 'OmniOSAppId', REGISTRY_TYPES.REG_SZ, 'com.sys.notepad');
        store1.registry.setValue('HKCR', '.pdf', 'OmniOSAppId', REGISTRY_TYPES.REG_SZ, 'com.sys.pdf');
        store1.registry.setValue('HKCR', 'omnios', 'URL Protocol', REGISTRY_TYPES.REG_SZ, '');
        store1.registry.setValue('HKCR', 'omnios', 'OmniOSAppId', REGISTRY_TYPES.REG_SZ, 'com.sys.shell');

        // Unprivileged app floods 1,025 extensions (.!e0000.. .!e1024), dot-whitespace HKCR\.   , and invalid !badproto
        for (let i = 0; i < 1025; i += 1) {
          const extKey = `.!e${String(i).padStart(4, '0')}`;
          store1.registry.setValue('HKCR', extKey, 'OmniOSAppId', REGISTRY_TYPES.REG_SZ, 'com.evil.flood', floodCtx);
        }
        store1.registry.setValue('HKCR', '.   ', 'OmniOSAppId', REGISTRY_TYPES.REG_SZ, 'com.evil.wildcard', floodCtx);
        store1.registry.setValue('HKCR', '!badproto', 'URL Protocol', REGISTRY_TYPES.REG_SZ, '', floodCtx);
        store1.registry.setValue('HKCR', '!badproto', 'OmniOSAppId', REGISTRY_TYPES.REG_SZ, 'com.evil.badproto', floodCtx);

        const assertIndexedState = (rtr, res, phase) => {
          assert.equal(res.indexed, 1027, `${phase}: expected 1024 flood + 3 root = 1027 indexed`);
          const floodList = rtr.listHandlers('com.evil.flood');
          assert.equal(floodList.length, 1, `${phase}: com.evil.flood should have handler entry`);
          assert.equal(
            floodList[0].handlers.length,
            1024,
            `${phase}: com.evil.flood must be capped at 1,024 descriptors`
          );

          assert.deepEqual(
            rtr.resolve({ action: 'view', extension: '.txt' }).map((c) => c.appId),
            ['com.sys.notepad'],
            `${phase}: root .txt must resolve intact`
          );
          assert.deepEqual(
            rtr.resolve({ action: 'view', extension: '.pdf' }).map((c) => c.appId),
            ['com.sys.pdf'],
            `${phase}: root .pdf must resolve intact`
          );
          assert.deepEqual(
            rtr.resolve({ uri: 'omnios://home' }).map((c) => c.appId),
            ['com.sys.shell'],
            `${phase}: root omnios:// must resolve intact`
          );

          // Dot-whitespace HKCR\.    must NOT register a wildcard action:'view' handler
          assert.deepEqual(
            rtr.listHandlers('com.evil.wildcard'),
            [],
            `${phase}: HKCR\\.   must not register any handler`
          );
          assert.ok(
            !rtr.resolve({ action: 'view' }).some((c) => c.appId === 'com.evil.wildcard'),
            `${phase}: HKCR\\.   must not register a wildcard action:'view' handler`
          );
          assert.ok(
            !rtr.resolve({ action: 'view', extension: '.unregistered_ext' }).some((c) => c.appId === 'com.evil.wildcard'),
            `${phase}: HKCR\\.   must not hijack unrelated extension view intents`
          );

          // Invalid URL protocol !badproto must NOT register
          assert.deepEqual(
            rtr.listHandlers('com.evil.badproto'),
            [],
            `${phase}: invalid URL protocol !badproto must not register`
          );
        };

        const res1 = router1.indexRegistryAssociations(store1);
        assertIndexedState(router1, res1, 'Boot 1');

        // Close store + WAL storage, then reopen from the SAME WAL DB file into brand-new instances
        store1.close();
        store1 = null;
        storage1.close();
        storage1 = null;
        assert.ok(fs.existsSync(dbPath), 'WAL SQLite file must exist on disk prior to reopen');

        storage2 = new SqliteStorage(dbPath);
        store2 = new UnifiedConfigStore({ storage: storage2 });
        const router2 = new IntentRouter();

        const res2 = router2.indexRegistryAssociations(store2);
        assertIndexedState(router2, res2, 'Boot 2 (WAL reopen)');
      } finally {
        if (store2) store2.close();
        if (storage2) storage2.close();
        if (store1) store1.close();
        if (storage1) storage1.close();
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    }

    // --- E. Obs-W13-FD: FormatDetector >8 KB UTF-8 boundary handling in detectWindowsBat ---
    {
      const detector = new FormatDetector();
      const header = '@echo off\r\nrem ';
      const headerLen = Buffer.byteLength(header, 'utf8');

      // Construct a >8 KB .bat buffer placing `seqBytes` at exact byte offset `offset`
      const makeBatWithBytesAt = (offset, seqBytes, tail = ' end\r\n') => {
        const padLen = offset - headerLen;
        assert.ok(padLen >= 0);
        const prefix = Buffer.from(header + 'a'.repeat(padLen), 'utf8');
        assert.equal(prefix.byteLength, offset);
        const mid = Buffer.from(seqBytes);
        const suffix = Buffer.from(tail, 'utf8');
        const combined = Buffer.concat([prefix, mid, suffix]);
        assert.ok(combined.byteLength > 8192, 'Fixture must exceed 8,192 bytes');
        return combined;
      };

      // Valid multi-byte UTF-8 sequences straddling byte offset 8191..8192 detect cleanly as windows-bat
      const validStraddleCases = [
        ['2-byte é at 8191..8192', 8191, Buffer.from('é', 'utf8')],
        ['3-byte € at 8190..8192', 8190, Buffer.from('€', 'utf8')],
        ['3-byte € at 8191..8193', 8191, Buffer.from('€', 'utf8')],
        ['4-byte 😀 at 8189..8192', 8189, Buffer.from('😀', 'utf8')],
        ['4-byte 😀 at 8190..8193', 8190, Buffer.from('😀', 'utf8')],
        ['4-byte 😀 at 8191..8194', 8191, Buffer.from('😀', 'utf8')],
      ];
      for (const [label, offset, utf8Bytes] of validStraddleCases) {
        const buf = makeBatWithBytesAt(offset, utf8Bytes);
        const detWithHint = detector.detect(buf, 'utf8-boundary.bat');
        assert.equal(
          detWithHint.format,
          PACKAGE_FORMATS.WINDOWS_BAT,
          `${label} (with .bat hint) must detect as windows-bat`
        );
        assert.equal(detWithHint.platform, 'windows');

        const detNoHint = detector.detect(buf);
        assert.equal(
          detNoHint.format,
          PACKAGE_FORMATS.WINDOWS_BAT,
          `${label} (syntax-only, no hint) must detect as windows-bat`
        );
        assert.equal(detNoHint.platform, 'windows');
      }

      // Genuine invalid UTF-8 / binary bytes at or straddling 8191..8192 must return unknown
      const invalidBoundaryCases = [
        ['invalid 0xFF at 8191', 8191, [0xff]],
        ['lone 0x80 0x80 0x80 at 8189..8191', 8189, [0x80, 0x80, 0x80]],
        ['split invalid 0xC2 0x00 at 8191..8192', 8191, [0xc2, 0x00]],
        ['split invalid 0xC2 0x41 at 8191..8192', 8191, [0xc2, 0x41]],
      ];
      for (const [label, offset, badBytes] of invalidBoundaryCases) {
        const buf = makeBatWithBytesAt(offset, badBytes);
        const det = detector.detect(buf, 'corrupt-boundary.bat');
        assert.equal(det.format, PACKAGE_FORMATS.UNKNOWN, `${label} must return unknown`);
        assert.equal(det.platform, 'unknown');
      }
    }
  });
});
