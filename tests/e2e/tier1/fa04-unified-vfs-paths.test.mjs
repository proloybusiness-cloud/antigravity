/**
 * Tier 1 E2E Tests — FA-04: Unified Cross-Platform VFS, Path Translation & Virtual Mounts
 * Features covered: F-016, F-017, F-018, F-019, F-020
 * Contracts: Contract 2 (IVFS, IPathTranslator), Contract 7 (REST), Contract 8 (CLI)
 *
 * Strictly opaque-box: interacts ONLY through public OmniOS entrypoints via ../lib/env.mjs.
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  createTempDataDir,
  loadPublicOmniOS,
  startOmniServer,
} from '../lib/env.mjs';

function makeNonce() {
  return `${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`;
}

function getInode(st) {
  assert.ok(st && typeof st === 'object', 'stat/lstat must return a metadata object');
  const ino = st.ino ?? st.inode ?? st.inodeId ?? st.id;
  assert.ok(ino !== undefined && ino !== null, `stat result must include an inode identifier: ${JSON.stringify(st)}`);
  return ino;
}

function toByteArray(val) {
  if (val instanceof Uint8Array) return val;
  if (ArrayBuffer.isView(val)) return new Uint8Array(val.buffer, val.byteOffset, val.byteLength);
  if (typeof val === 'string') return Buffer.from(val, 'utf8');
  if (Array.isArray(val)) return Uint8Array.from(val);
  throw new TypeError(`Expected binary buffer/Uint8Array, got ${typeof val}`);
}

function normalizeDirNames(entries) {
  assert.ok(Array.isArray(entries), 'readdir must return an Array');
  return entries.map((e) => (typeof e === 'string' ? e : String(e?.name ?? e?.filename ?? e?.path ?? '')));
}

async function restMutate(api, urlPath, body, { query } = {}) {
  let res = await api.put(urlPath, body, { query });
  if (res.status === 404 || res.status === 405) {
    res = await api.post(urlPath, body, { query });
  }
  if (res.status === 404 || res.status === 405) {
    res = await api.patch(urlPath, body, { query });
  }
  return res;
}

function unwrapList(payload, keys = ['entries', 'files', 'mounts', 'items', 'data', 'list']) {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== 'object') return [];
  for (const key of keys) {
    if (Array.isArray(payload[key])) return payload[key];
  }
  if (payload.data && typeof payload.data === 'object') {
    for (const key of keys) {
      if (Array.isArray(payload.data[key])) return payload.data[key];
    }
  }
  return [];
}

function extractTextField(res) {
  if (typeof res.json === 'string') return res.json;
  if (res.json && typeof res.json === 'object') {
    const candidate =
      res.json.content ??
      res.json.text ??
      res.json.data?.content ??
      res.json.data?.text ??
      (typeof res.json.data === 'string' ? res.json.data : null);
    if (typeof candidate === 'string') return candidate;
  }
  return res.text;
}

function isSymlinkStat(st) {
  if (!st || typeof st !== 'object') return false;
  if (st.type === 'symlink' || st.isSymlink === true) return true;
  if (typeof st.isSymbolicLink === 'function') return Boolean(st.isSymbolicLink());
  if (st.isSymbolicLink === true) return true;
  if (typeof st.mode === 'number' && (st.mode & 0o170000) === 0o120000) return true;
  return false;
}

function makeDummyContext() {
  return {
    step() {
      return { status: 'YIELD', instructionsExecuted: 1 };
    },
    deliverEvent() {},
    getDebugState() {
      return { arch: 'test', pc: 0, sp: 0x1000, registers: {}, instructionsExecuted: 0, lastSyscall: null, stackTop: 0x1000 };
    },
    dispose() {},
  };
}

describe('Tier 1 — FA-04: Unified Cross-Platform VFS, Path Translation & Virtual Mounts', () => {
  test('T1 [F-016]: Persistent SQLite POSIX VFS full CRUD, metadata & persistence across reopen', async () => {
    const temp = await createTempDataDir('omnios-fa04-vfs-');
    let os1 = null;
    let os2 = null;
    try {
      const nonce = makeNonce();
      os1 = await loadPublicOmniOS({ dataDir: temp.dir });
      const vfs = os1.require('vfs');

      const dir = `/home/user/Documents/vfs-${nonce}`;
      const subDir = `${dir}/sub`;
      const f1 = `${dir}/note-${nonce}.txt`;
      const f2 = `${dir}/renamed-${nonce}.txt`;
      const fBin = `${dir}/bin-${nonce}.dat`;

      await vfs.mkdir(subDir, { recursive: true, mode: 0o755 });

      const part1 = `part1-${nonce}`;
      const part2 = '-part2';
      const expectedText = `${part1}${part2}`;

      await vfs.writeFile(f1, part1, { mode: 0o644 });
      await vfs.writeFile(f1, part2, { append: true });
      assert.equal(
        await vfs.readFile(f1, { encoding: 'utf8' }),
        expectedText,
        'writeFile(append: true) must append cleanly to existing file content'
      );

      // Binary round-trip
      const binPayload = new Uint8Array([0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff]);
      await vfs.writeFile(fBin, binPayload, { mode: 0o644 });
      const binRead = toByteArray(await vfs.readFile(fBin));
      assert.ok(Buffer.from(binRead).equals(Buffer.from(binPayload)), 'Binary readFile must match exact written bytes');

      // stat, chmod, chown
      const st1 = await vfs.stat(f1);
      assert.equal(st1.size, Buffer.byteLength(expectedText, 'utf8'));
      getInode(st1);
      assert.equal(st1.mode & 0o777, 0o644);

      await vfs.chmod(f1, 0o600);
      assert.equal((await vfs.stat(f1)).mode & 0o777, 0o600, 'chmod() must update POSIX permission bits');

      const targetUid = st1.uid === 10042 ? 10043 : 10042;
      const targetGid = st1.gid === 10042 ? 10043 : 10042;
      await vfs.chown(f1, targetUid, targetGid, { uid: 0, gid: 0 });
      const chowned = await vfs.stat(f1);
      assert.equal(chowned.uid, targetUid, `chown() must change uid from ${st1.uid} to ${targetUid}`);
      assert.equal(chowned.gid, targetGid, `chown() must change gid from ${st1.gid} to ${targetGid}`);

      // readdir
      const names = normalizeDirNames(await vfs.readdir(dir));
      assert.ok(names.includes('sub'), `readdir must include "sub", got ${JSON.stringify(names)}`);
      assert.ok(names.includes(`note-${nonce}.txt`), `readdir must include "note-${nonce}.txt"`);
      assert.ok(names.includes(`bin-${nonce}.dat`), `readdir must include "bin-${nonce}.dat"`);

      // open (using the new owner context since mode is 0o600)
      const handle = await vfs.open(f1, 'r', { uid: targetUid, gid: targetGid });
      assert.ok(handle !== null && handle !== undefined, 'vfs.open() must return a valid FD or handle');
      if (typeof handle?.close === 'function') await handle.close();

      // rename
      await vfs.rename(f1, f2);
      assert.equal(await vfs.readFile(f2, { encoding: 'utf8', uid: targetUid, gid: targetGid }), expectedText);
      await assert.rejects(async () => vfs.stat(f1), (err) => err?.code === 'ENOENT');

      // unlink & rmdir
      await vfs.unlink(fBin);
      await assert.rejects(async () => vfs.stat(fBin), (err) => err?.code === 'ENOENT');
      await vfs.rmdir(subDir);
      await assert.rejects(async () => vfs.stat(subDir), (err) => err?.code === 'ENOENT');

      // Persistence across SQLite reopen
      await os1.shutdown();
      os1 = null;

      os2 = await loadPublicOmniOS({ dataDir: temp.dir });
      const vfs2 = os2.require('vfs');
      assert.equal(
        await vfs2.readFile(f2, { encoding: 'utf8', uid: targetUid, gid: targetGid }),
        expectedText,
        'Renamed VFS file content must persist across OS reboot'
      );
      const persistedStat = await vfs2.stat(f2);
      assert.equal(
        persistedStat.mode & 0o777,
        0o600,
        'Updated chmod mode bits must persist across OS reboot'
      );
      assert.equal(persistedStat.uid, targetUid, 'Updated chown uid must persist across OS reboot');
    } finally {
      await os1?.shutdown();
      await os2?.shutdown();
      await temp.cleanup();
    }
  });

  test('T2 [F-017]: Bidirectional PathTranslator across POSIX, Windows, macOS, Android & iOS', async () => {
    const os = await loadPublicOmniOS();
    try {
      const pt = os.require('pathTranslator');
      const nonce = makeNonce();
      const uuid = crypto.randomUUID().toUpperCase();
      const pkg = `com.e2e.pkg_${nonce.replace(/-/g, '_')}`;

      const cases = [
        { raw: `/home/user/Documents/f-${nonce}.txt`, platform: 'posix', expected: `/home/user/Documents/f-${nonce}.txt`, ci: false },
        { raw: `C:\\Users\\user\\Documents\\f-${nonce}.txt`, platform: 'windows', expected: `/home/user/Documents/f-${nonce}.txt`, ci: true },
        { raw: `C:\\Windows\\System32\\ntdll.dll`, platform: 'windows', expected: `/system/windows/System32/ntdll.dll`, ci: true },
        { raw: `C:\\Program Files\\App-${nonce}\\run.exe`, platform: 'windows', expected: `/apps/windows/App-${nonce}/run.exe`, ci: true },
        { raw: `Z:\\etc\\hosts`, platform: 'windows', expected: `/etc/hosts`, ci: true },
        { raw: `/Users/user/Documents/f-${nonce}.txt`, platform: 'macos', expected: `/home/user/Documents/f-${nonce}.txt` },
        { raw: `/Applications/Studio-${nonce}.app`, platform: 'macos', expected: `/apps/macos/Studio-${nonce}.app` },
        { raw: `/Users/user/Library/Preferences/p-${nonce}.plist`, platform: 'macos', expected: `/var/appdata/macos/Library/Preferences/p-${nonce}.plist` },
        { raw: `/sdcard/Documents/f-${nonce}.txt`, platform: 'android', expected: `/home/user/Documents/f-${nonce}.txt` },
        { raw: `/storage/emulated/0/Downloads/f-${nonce}.txt`, platform: 'android', expected: `/home/user/Downloads/f-${nonce}.txt` },
        { raw: `/data/data/${pkg}/files/d-${nonce}.bin`, platform: 'android', expected: `/var/appdata/android/${pkg}/files/d-${nonce}.bin` },
        { raw: `/var/mobile/Documents/f-${nonce}.txt`, platform: 'ios', expected: `/home/user/Documents/f-${nonce}.txt` },
        { raw: `/var/mobile/Containers/Data/Application/${uuid}/Documents/s-${nonce}.plist`, platform: 'ios', expected: `/var/appdata/ios/${uuid}/Documents/s-${nonce}.plist` },
      ];

      for (const tc of cases) {
        const res = pt.toCanonical(tc.raw, { platform: tc.platform, appId: pkg, containerUuid: uuid });
        assert.equal(
          res?.canonicalPath,
          tc.expected,
          `toCanonical(${tc.raw}, ${tc.platform}) expected "${tc.expected}", got "${res?.canonicalPath}"`
        );
        assert.equal(res?.originalPath, tc.raw, 'toCanonical must preserve originalPath');
        if (typeof tc.ci === 'boolean') {
          assert.equal(
            res?.caseInsensitive,
            tc.ci,
            `Expected caseInsensitive=${tc.ci} for platform=${tc.platform} (${tc.raw})`
          );
        }
      }

      // Reverse translation & round-trip identity across all 5 platforms
      const sharedCanonical = `/home/user/Documents/rt-${nonce}.txt`;
      for (const platform of ['posix', 'windows', 'macos', 'android', 'ios']) {
        const platPath = pt.toPlatform(sharedCanonical, platform, { appId: pkg, containerUuid: uuid });
        assert.equal(typeof platPath, 'string', `toPlatform(${platform}) must return a string`);
        assert.ok(platPath.length > 0, `toPlatform(${platform}) must be non-empty`);
        if (platform === 'windows') {
          assert.match(platPath, /^[A-Za-z]:\\/, `Windows toPlatform path must start with drive letter: ${platPath}`);
        }
        const back = pt.toCanonical(platPath, { platform, appId: pkg, containerUuid: uuid });
        assert.equal(
          back.canonicalPath,
          sharedCanonical,
          `Round-trip toPlatform->toCanonical failed for ${platform}: ${platPath} -> ${back.canonicalPath}`
        );
      }
    } finally {
      await os.shutdown();
    }
  });

  test('T3 [F-018]: Shared cross-platform user space resolving to identical inodes', async () => {
    const os = await loadPublicOmniOS();
    try {
      const vfs = os.require('vfs');
      const nonce = makeNonce();

      // Verify all 4 shared user directories exist and share identical inodes across platforms
      for (const folder of ['Documents', 'Downloads', 'Desktop', 'Pictures']) {
        const stPosix = await vfs.stat(`/home/user/${folder}`, { platform: 'posix' });
        const stWin = await vfs.stat(`C:\\Users\\user\\${folder}`, { platform: 'windows' });
        const stMac = await vfs.stat(`/Users/user/${folder}`, { platform: 'macos' });
        const stAnd = await vfs.stat(`/sdcard/${folder}`, { platform: 'android' });

        const ino = getInode(stPosix);
        assert.equal(getInode(stWin), ino, `Windows C:\\Users\\user\\${folder} must match POSIX inode`);
        assert.equal(getInode(stMac), ino, `macOS /Users/user/${folder} must match POSIX inode`);
        assert.equal(getInode(stAnd), ino, `Android /sdcard/${folder} must match POSIX inode`);
      }

      // Write via Windows path, read & stat via all 6 platform path representations
      const payload = `xplat-payload-${nonce}`;
      const fileName = `shared-${nonce}.txt`;
      await vfs.writeFile(`C:\\Users\\user\\Documents\\${fileName}`, payload, { platform: 'windows' });

      const views = [
        { path: `/home/user/Documents/${fileName}`, platform: 'posix' },
        { path: `C:\\Users\\user\\Documents\\${fileName}`, platform: 'windows' },
        { path: `/Users/user/Documents/${fileName}`, platform: 'macos' },
        { path: `/sdcard/Documents/${fileName}`, platform: 'android' },
        { path: `/storage/emulated/0/Documents/${fileName}`, platform: 'android' },
        { path: `/var/mobile/Documents/${fileName}`, platform: 'ios' },
      ];

      let expectedInode = null;
      for (const view of views) {
        const content = await vfs.readFile(view.path, { encoding: 'utf8', platform: view.platform });
        assert.equal(content, payload, `Read mismatch for ${view.platform} path "${view.path}"`);

        const st = await vfs.stat(view.path, { platform: view.platform });
        const ino = getInode(st);
        if (expectedInode === null) {
          expectedInode = ino;
        } else {
          assert.equal(ino, expectedInode, `Inode mismatch for ${view.platform} path "${view.path}"`);
        }
      }
    } finally {
      await os.shutdown();
    }
  });

  test('T4 [F-019]: Symlinks (symlink/readlink, lstat vs stat) & live vfs:changed bus events', async () => {
    const os = await loadPublicOmniOS();
    const bus =
      os.raw.eventBus ??
      os.kernel?.eventBus ??
      os.raw.events ??
      os.kernel?.events ??
      os.raw.bus ??
      os.kernel?.bus;
    let unsub = null;
    try {
      const vfs = os.require('vfs');
      const nonce = makeNonce();

      assert.ok(bus && typeof bus === 'object', 'Public OmniOS runtime must expose KernelEventBus for live vfs:changed events');
      const events = [];
      const handler = (ev) => events.push(ev);
      if (typeof bus.on === 'function') {
        const ret = bus.on('vfs:changed', handler);
        unsub = typeof ret === 'function' ? ret : () => bus.off?.('vfs:changed', handler);
      } else if (typeof bus.subscribe === 'function') {
        unsub = bus.subscribe('vfs:changed', handler);
      } else {
        throw new Error('KernelEventBus must expose on() or subscribe()');
      }

      const target = `/home/user/Documents/sym-tgt-${nonce}.txt`;
      const link = `/home/user/Documents/sym-lnk-${nonce}.txt`;
      const body = `sym-body-${nonce}`;

      await vfs.writeFile(target, body);
      assert.ok(
        events.some((e) => JSON.stringify(e).includes(target)),
        'writeFile() must emit a live vfs:changed event referencing the mutated path'
      );

      await vfs.symlink(target, link);
      assert.equal(await vfs.readlink(link), target, 'readlink() must return exact symlink target');

      const lstatRes = await vfs.lstat(link);
      const statLinkRes = await vfs.stat(link);
      const statTargetRes = await vfs.stat(target);

      assert.ok(isSymlinkStat(lstatRes), `lstat(link) must identify a symlink: ${JSON.stringify(lstatRes)}`);
      assert.notEqual(
        getInode(lstatRes),
        getInode(statTargetRes),
        'lstat(link) inode must differ from target file inode'
      );
      assert.equal(
        getInode(statLinkRes),
        getInode(statTargetRes),
        'stat(link) must follow symlink and match target inode'
      );
      assert.equal(statLinkRes.size, statTargetRes.size);

      assert.equal(
        await vfs.readFile(link, { encoding: 'utf8' }),
        body,
        'Reading through symlink must return target file contents'
      );

      // Unlinking the symlink leaves the target untouched
      await vfs.unlink(link);
      await assert.rejects(async () => vfs.lstat(link), (err) => err?.code === 'ENOENT');
      assert.equal(
        await vfs.readFile(target, { encoding: 'utf8' }),
        body,
        'Unlinking symlink must preserve target file'
      );
      assert.ok(
        events.some((e) => JSON.stringify(e).includes(link)),
        'Symlink creation/unlinking must emit vfs:changed events'
      );
    } finally {
      if (typeof unsub === 'function') unsub();
      await os.shutdown();
    }
  });

  test('T5 [F-020]: Dynamic virtual mounts (/proc, /dev/null, /dev/zero, /dev/urandom, /tmp)', async () => {
    const os = await loadPublicOmniOS();
    try {
      const vfs = os.require('vfs');
      const pm = os.require('processManager');
      os.require('scheduler').stop?.();
      const nonce = makeNonce();

      // /proc/uptime
      const uptimeText = await vfs.readFile('/proc/uptime', { encoding: 'utf8' });
      assert.match(String(uptimeText), /\d+(\.\d+)?/, `/proc/uptime must contain numeric uptime, got "${uptimeText}"`);

      // /proc/1/status & /proc/<livePid>/status
      const initStatus = String(await vfs.readFile('/proc/1/status', { encoding: 'utf8' }));
      assert.ok(initStatus.includes('omnid') && initStatus.includes('1'), `/proc/1/status must describe PID 1 omnid: ${initStatus}`);

      const procName = `proc-vm-${nonce}`;
      const pcb = pm.spawn({ name: procName, platform: 'universal', arch: 'wasm', executionContext: makeDummyContext() });
      const liveStatus = String(await vfs.readFile(`/proc/${pcb.pid}/status`, { encoding: 'utf8' }));
      assert.ok(
        liveStatus.includes(procName) && liveStatus.includes(String(pcb.pid)),
        `/proc/${pcb.pid}/status must describe live process "${procName}": ${liveStatus}`
      );
      pm.kill(pcb.pid, 'SIGTERM');

      // /dev/null
      await vfs.writeFile('/dev/null', `discard-${nonce}`);
      const nullBytes = toByteArray(await vfs.readFile('/dev/null'));
      assert.equal(nullBytes.length, 0, '/dev/null reads must return 0 bytes');

      // /dev/zero
      const zeroBytes = toByteArray(await vfs.readFile('/dev/zero', { length: 32 }));
      assert.ok(zeroBytes.length > 0, '/dev/zero must return non-empty byte buffer');
      const zeroSlice = zeroBytes.subarray(0, Math.min(32, zeroBytes.length));
      assert.ok(zeroSlice.every((b) => b === 0), '/dev/zero must contain strictly 0x00 bytes');

      // /dev/urandom
      const rand1 = toByteArray(await vfs.readFile('/dev/urandom', { length: 32 })).subarray(0, 32);
      const rand2 = toByteArray(await vfs.readFile('/dev/urandom', { length: 32 })).subarray(0, 32);
      assert.ok(rand1.length >= 16 && rand2.length >= 16, '/dev/urandom must return random bytes');
      assert.ok(rand1.some((b) => b !== 0), '/dev/urandom must not be all zeros');
      assert.equal(
        Buffer.from(rand1).equals(Buffer.from(rand2)),
        false,
        'Two consecutive /dev/urandom reads must produce distinct random bytes'
      );

      // /tmp ephemeral mount
      const tmpFile = `/tmp/ephemeral-${nonce}.txt`;
      const tmpData = `tmp-val-${nonce}`;
      await vfs.writeFile(tmpFile, tmpData);
      assert.equal(await vfs.readFile(tmpFile, { encoding: 'utf8' }), tmpData);
      const tmpEntries = normalizeDirNames(await vfs.readdir('/tmp'));
      assert.ok(tmpEntries.includes(`ephemeral-${nonce}.txt`), 'File written in /tmp must appear in readdir("/tmp")');
      await vfs.unlink(tmpFile);
    } finally {
      await os.shutdown();
    }
  });

  test('T6 [F-016–F-020, Contracts 7 & 8]: Live REST /api/v1/vfs/* & Remote CLI vfs commands', async () => {
    const srv = await startOmniServer();
    try {
      const nonce = makeNonce();
      const restDir = `/home/user/Documents/rest-${nonce}`;
      const restFile = `${restDir}/file-${nonce}.txt`;
      const restLink = `${restDir}/link-${nonce}.txt`;
      const restRenamed = `${restDir}/moved-${nonce}.txt`;
      const restBody = `rest-body-${nonce}`;

      const mkRes = await srv.api.post('/api/v1/vfs/mkdir', { path: restDir, recursive: true });
      assert.ok(mkRes.ok, `POST /api/v1/vfs/mkdir failed (${mkRes.status}): ${mkRes.text}`);

      const wrRes = await restMutate(srv.api, '/api/v1/vfs/file', { path: restFile, content: restBody, data: restBody });
      assert.ok(wrRes.ok, `Write /api/v1/vfs/file failed (${wrRes.status}): ${wrRes.text}`);

      const rdRes = await srv.api.get('/api/v1/vfs/file', { query: { path: restFile } });
      assert.equal(rdRes.status, 200);
      assert.ok(extractTextField(rdRes).includes(restBody), `GET /api/v1/vfs/file must return written body, got: ${rdRes.text}`);

      const stRes = await srv.api.get('/api/v1/vfs/stat', { query: { path: restFile } });
      assert.equal(stRes.status, 200);
      const stObj = stRes.json?.stat ?? stRes.json?.data ?? stRes.json;
      assert.equal(stObj?.size, Buffer.byteLength(restBody, 'utf8'));

      const lsRes = await srv.api.get('/api/v1/vfs/ls', { query: { path: restDir } });
      assert.equal(lsRes.status, 200);
      assert.ok(
        JSON.stringify(lsRes.json).includes(`file-${nonce}.txt`),
        `GET /api/v1/vfs/ls must include created file: ${lsRes.text}`
      );

      const symRes = await srv.api.post('/api/v1/vfs/symlink', { target: restFile, path: restLink, linkPath: restLink });
      assert.ok(symRes.ok, `POST /api/v1/vfs/symlink failed (${symRes.status}): ${symRes.text}`);

      const symStat = await srv.api.get('/api/v1/vfs/stat', { query: { path: restLink } });
      assert.equal(symStat.status, 200, `GET /api/v1/vfs/stat on created symlink failed (${symStat.status}): ${symStat.text}`);
      const symRead = await srv.api.get('/api/v1/vfs/file', { query: { path: restLink } });
      assert.equal(symRead.status, 200, `GET /api/v1/vfs/file through symlink failed (${symRead.status}): ${symRead.text}`);
      assert.ok(
        extractTextField(symRead).includes(restBody),
        `Reading through REST symlink must return target body "${restBody}", got: ${symRead.text}`
      );

      const renRes = await srv.api.post('/api/v1/vfs/rename', { oldPath: restFile, newPath: restRenamed, from: restFile, to: restRenamed });
      assert.ok(renRes.ok, `POST /api/v1/vfs/rename failed (${renRes.status}): ${renRes.text}`);

      const rdMoved = await srv.api.get('/api/v1/vfs/file', { query: { path: restRenamed } });
      assert.equal(rdMoved.status, 200);
      assert.ok(extractTextField(rdMoved).includes(restBody));

      const winQuery = `C:\\Users\\user\\Documents\\rest-${nonce}`;
      let resolveRes = await srv.api.get('/api/v1/vfs/resolve', { query: { path: winQuery, platform: 'windows' } });
      if (resolveRes.status === 404 || resolveRes.status === 405) {
        resolveRes = await srv.api.post('/api/v1/vfs/resolve', { path: winQuery, platform: 'windows' });
      }
      assert.equal(resolveRes.status, 200);
      assert.ok(
        JSON.stringify(resolveRes.json).includes(restDir),
        `GET/POST /api/v1/vfs/resolve must map Windows path to "${restDir}", got: ${resolveRes.text}`
      );

      const mountsRes = await srv.api.get('/api/v1/vfs/mounts');
      assert.equal(mountsRes.status, 200);
      const mountsText = JSON.stringify(mountsRes.json ?? mountsRes.text);
      assert.ok(mountsText.includes('/proc'), 'GET /api/v1/vfs/mounts must include /proc');
      assert.ok(mountsText.includes('/dev'), 'GET /api/v1/vfs/mounts must include /dev');
      assert.ok(mountsText.includes('/tmp'), 'GET /api/v1/vfs/mounts must include /tmp');

      // Remote CLI vfs subcommands
      const cliFile = `/home/user/Documents/cli-${nonce}.txt`;
      const cliBody = `cli-body-${nonce}`;
      await srv.runCli(['vfs', 'write', cliFile, cliBody], { json: true, expectZero: true });

      const catRes = await srv.runCli(['vfs', 'cat', cliFile], { json: true, expectZero: true });
      assert.ok(catRes.stdout.includes(cliBody), `CLI "vfs cat" must return written body, got: ${catRes.stdout}`);

      const cliLs = await srv.runCli(['vfs', 'ls', '/home/user/Documents'], { json: true, expectZero: true });
      assert.ok(cliLs.stdout.includes(`cli-${nonce}.txt`), `CLI "vfs ls" must list created file`);

      const cliResolve = await srv.runCli(
        ['vfs', 'resolve', `C:\\Users\\user\\Documents\\cli-${nonce}.txt`, '--platform', 'windows'],
        { json: true, expectZero: true }
      );
      assert.ok(cliResolve.stdout.includes(cliFile), `CLI "vfs resolve" must resolve Windows path to ${cliFile}`);

      await srv.runCli(['vfs', 'rm', cliFile], { json: true, expectZero: true });
      const checkGone = await srv.api.get('/api/v1/vfs/stat', { query: { path: cliFile } });
      assert.ok(!checkGone.ok, 'File removed by CLI "vfs rm" must no longer exist');
    } finally {
      await srv.stop();
    }
  });
});
