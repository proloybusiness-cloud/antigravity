/**
 * Tier 2 Boundary, Corner & Negative E2E Suite — FA-04:
 * Unified Cross-Platform VFS, Path Translation, Symlinks (ELOOP), Traversal & Virtual Mounts
 * (F-016 – F-020, Edge Case #28).
 *
 * Strictly opaque-box: imports ONLY Node 24 built-ins, ../lib/env.mjs, and ../lib/fixtures-malformed.mjs.
 * Zero skips, zero stubs, zero private internal os imports.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { loadPublicOmniOS, startOmniServer } from '../lib/env.mjs';
import { getVfsEdgeCasePayloads } from '../lib/fixtures-malformed.mjs';

function makeNonce() {
  return crypto.randomBytes(4).toString('hex');
}

function getInode(statObj) {
  return statObj?.ino ?? statObj?.inode ?? statObj?.id;
}

function toBuffer(val) {
  if (Buffer.isBuffer(val)) return val;
  if (val instanceof Uint8Array) return Buffer.from(val.buffer, val.byteOffset, val.byteLength);
  if (typeof val === 'string') return Buffer.from(val, 'utf8');
  return Buffer.from([]);
}

async function assertVfsError(fn, allowedCodes, label) {
  const allowed = Array.isArray(allowedCodes) ? allowedCodes : [allowedCodes];
  let caught = null;
  try {
    await fn();
  } catch (err) {
    caught = err;
  }
  assert.ok(caught instanceof Error, `${label}: MUST reject with Error (${allowed.join('|')})`);
  assert.ok(
    allowed.includes(caught.code),
    `${label}: expected err.code in [${allowed.join(', ')}] (got code=${caught.code}, msg=${caught.message})`
  );
  return caught;
}

async function discoverWorkingMutateVerb(api, urlPath, body, methods = ['PUT', 'POST', 'PATCH'], opts = {}) {
  let lastRes = null;
  let chosenMethod = methods[0];
  for (const method of methods) {
    chosenMethod = method;
    const res = await api.request(method, urlPath, { ...opts, body });
    lastRes = res;
    if (res.ok) return { method, res };
    if (res.status !== 404 && res.status !== 405) return { method, res };
  }
  return { method: chosenMethod, res: lastRes };
}

test.describe('Tier 2 — FA-04: Unified Cross-Platform VFS, Path Translation & Virtual Mounts (Boundary & Negative)', () => {
  test('T1 [F-019, Edge Case #28]: Symlink cycles ELOOP (2-node A<->B, 18-node cycle) & exact 16-hop boundary (16 succeeds, 17 -> ELOOP)', async () => {
    const nonce = makeNonce();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const vfs = os.require('vfs');
      const rootCtx = { uid: 0, gid: 0 };
      const payloads = getVfsEdgeCasePayloads();

      // 1. 2-node direct cycle (A <-> B)
      for (const { linkPath, target } of payloads.symlinkCycles.twoNode) {
        await vfs.symlink(target, linkPath, rootCtx);
      }
      await assertVfsError(() => vfs.stat('/tmp/eloop_a', rootCtx), 'ELOOP', 'stat 2-node cycle');
      await assertVfsError(() => vfs.readFile('/tmp/eloop_a', rootCtx), 'ELOOP', 'readFile 2-node cycle');
      await assertVfsError(() => vfs.open('/tmp/eloop_a', 'r', rootCtx), 'ELOOP', 'open 2-node cycle');

      // lstat and readlink MUST succeed without following the cycle
      const lstatA = await vfs.lstat('/tmp/eloop_a', rootCtx);
      assert.ok(lstatA && (lstatA.isSymlink === true || lstatA.type === 'symlink' || lstatA.isSymbolicLink?.() === true), 'lstat on cyclic link must identify symlink');
      assert.equal(await vfs.readlink('/tmp/eloop_a', rootCtx), '/tmp/eloop_b', 'readlink must return exact link target');

      // 2. 18-node cycle
      for (const { linkPath, target } of payloads.symlinkCycles.deepChain18) {
        await vfs.symlink(target, linkPath, rootCtx);
      }
      await assertVfsError(() => vfs.stat('/tmp/eloop_chain_0', rootCtx), 'ELOOP', 'stat 18-node cycle');
      await assertVfsError(() => vfs.readFile('/tmp/eloop_chain_0', rootCtx), 'ELOOP', 'readFile 18-node cycle');

      // 3. Exact 16-hop acyclic chain boundary (depth <= 16 succeeds, depth 17 > 16 -> ELOOP)
      const targetPath = `/tmp/chain-target-${nonce}.txt`;
      const targetBody = `chain-ok-${nonce}`;
      await vfs.writeFile(targetPath, targetBody, rootCtx);

      let prev = targetPath;
      for (let hop = 1; hop <= 17; hop++) {
        const linkPath = `/tmp/chain-hop-${nonce}-${hop}`;
        await vfs.symlink(prev, linkPath, rootCtx);
        prev = linkPath;
      }

      assert.equal(
        await vfs.readFile(`/tmp/chain-hop-${nonce}-1`, { encoding: 'utf8', ...rootCtx }),
        targetBody,
        '1-hop symlink must read target cleanly'
      );
      assert.equal(
        await vfs.readFile(`/tmp/chain-hop-${nonce}-16`, { encoding: 'utf8', ...rootCtx }),
        targetBody,
        'Exact 16-hop symlink boundary MUST succeed'
      );
      await assertVfsError(
        () => vfs.readFile(`/tmp/chain-hop-${nonce}-17`, { encoding: 'utf8', ...rootCtx }),
        'ELOOP',
        '17-hop symlink readFile (> 16) MUST reject with ELOOP'
      );
      await assertVfsError(
        () => vfs.stat(`/tmp/chain-hop-${nonce}-17`, rootCtx),
        'ELOOP',
        '17-hop symlink stat (> 16) MUST reject with ELOOP'
      );

      // 4. Dangling symlink contrast -> ENOENT (NOT ELOOP!)
      const dangling = `/tmp/dangling-${nonce}`;
      const missingTarget = `/tmp/no-target-${nonce}`;
      await vfs.symlink(missingTarget, dangling, rootCtx);
      assert.equal(await vfs.readlink(dangling, rootCtx), missingTarget);
      assert.ok(await vfs.lstat(dangling, rootCtx));
      await assertVfsError(() => vfs.stat(dangling, rootCtx), 'ENOENT', 'dangling symlink stat -> ENOENT');
      await assertVfsError(() => vfs.readFile(dangling, rootCtx), 'ENOENT', 'dangling symlink readFile -> ENOENT');
    } finally {
      await os?.shutdown();
    }
  });

  test('T2 [F-017, F-019, Edge Case #28]: Path traversal jail escape, NUL byte injection & cross-container traversal defense', async () => {
    const nonce = makeNonce();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const vfs = os.require('vfs');
      const pt = os.require('pathTranslator');
      const { traversalEscapes } = getVfsEdgeCasePayloads();

      // 1. NUL byte injection (create /home/user/Documents/safe.txt owned by uid 1000 FIRST for non-vacuity!)
      const safeBody = `safe-secret-${nonce}`;
      await vfs.writeFile('/home/user/Documents/safe.txt', safeBody, { uid: 1000, gid: 1000, mode: 0o644 });
      const nulVector = traversalEscapes[3]; // '/home/user/Documents/safe.txt\0../../evil.txt'
      assert.ok(nulVector.includes('\0'), 'Expected NUL byte vector from fixtures-malformed');

      assert.throws(
        () => pt.toCanonical(nulVector, { platform: 'posix' }),
        (err) => err instanceof Error && err.message.length > 0,
        'pathTranslator.toCanonical MUST reject NUL-byte path injection'
      );
      await assertVfsError(() => vfs.stat(nulVector, { uid: 1000, gid: 1000 }), ['EINVAL', 'EACCES', 'E_PATH_TRAVERSAL'], 'stat NUL path');
      await assertVfsError(() => vfs.readFile(nulVector, { encoding: 'utf8', uid: 1000, gid: 1000 }), ['EINVAL', 'EACCES', 'E_PATH_TRAVERSAL'], 'readFile NUL path');
      await assertVfsError(() => vfs.writeFile(nulVector, 'pwn', { uid: 1000, gid: 1000 }), ['EINVAL', 'EACCES', 'E_PATH_TRAVERSAL'], 'writeFile NUL path');
      assert.equal(
        await vfs.readFile('/home/user/Documents/safe.txt', { encoding: 'utf8', uid: 1000, gid: 1000 }),
        safeBody,
        'Rejected NUL-byte writeFile must not modify /home/user/Documents/safe.txt'
      );

      // 2. Host jail escape vectors (../../../../etc/passwd, Windows ..\..\.., Android /sdcard/../../..)
      const vectors = [
        { raw: traversalEscapes[0], platform: 'posix' },
        { raw: traversalEscapes[1], platform: 'windows' },
        { raw: traversalEscapes[2], platform: 'android' },
      ];
      for (const { raw, platform } of vectors) {
        let translated = null;
        let transErr = null;
        try {
          translated = pt.toCanonical(raw, { platform, cwd: '/home/user' });
        } catch (err) {
          transErr = err;
        }
        if (transErr) {
          assert.ok(transErr instanceof Error && transErr.message.length > 0);
        }
        if (translated) {
          assert.ok(!String(translated.canonicalPath ?? '').includes('..'), `Normalized canonicalPath must never retain "..": ${translated.canonicalPath}`);
        }

        let leakedContent = null;
        let leakErr = null;
        try {
          leakedContent = await vfs.readFile(raw, { encoding: 'utf8', platform, uid: 1000, gid: 1000 });
        } catch (err) {
          leakErr = err;
        }
        if (leakErr) {
          assert.ok(leakErr instanceof Error && leakErr.message.length > 0);
        }
        if (typeof leakedContent === 'string') {
          assert.ok(!leakedContent.includes('root:x:0:0:'), `Traversal vector "${raw}" MUST NEVER leak host Linux /etc/passwd!`);
        }
      }

      // Attempt Windows traversal write to host /tmp -> MUST NOT touch real Linux /tmp
      const hostEscapeFile = `/tmp/omnios-host-escape-${nonce}.txt`;
      try {
        await vfs.writeFile(
          `C:\\Users\\user\\..\\..\\..\\..\\tmp\\omnios-host-escape-${nonce}.txt`,
          `host-escape-${nonce}`,
          { platform: 'windows', uid: 1000, gid: 1000 }
        );
      } catch {
        // Rejection is preferred; clamping inside virtual VFS is also safe if host /tmp is untouched
      }
      await assert.rejects(() => fs.access(hostEscapeFile), 'VFS traversal write MUST NEVER create files on the real host Linux filesystem');

      // Windows C:\Users\..\..\Windows normalization & unprivileged write protection
      let winEsc = null;
      let winEscErr = null;
      try {
        winEsc = pt.toCanonical('C:\\Users\\..\\..\\Windows', { platform: 'windows' });
      } catch (err) {
        winEscErr = err;
      }
      if (winEscErr) {
        assert.ok(winEscErr instanceof Error && winEscErr.message.length > 0);
      }
      if (winEsc) {
        assert.ok(!String(winEsc.canonicalPath ?? '').includes('..'), 'Windows traversal canonicalPath must contain zero ".." segments');
      }
      await assert.rejects(
        async () => vfs.writeFile(`C:\\Users\\..\\..\\Windows\\evil-${nonce}.dll`, 'evil', { platform: 'windows', uid: 1000, gid: 1000 }),
        (err) => err instanceof Error && ['EACCES', 'EINVAL', 'E_PATH_TRAVERSAL', 'ENOENT'].includes(err.code),
        'Unprivileged traversal write to C:\\Windows must be blocked'
      );

      // 3. Cross-app sandbox container traversal escape (Android /data/data/attacker/../victim/secret.txt)
      const victimDir = `/var/appdata/android/com.victim.${nonce}`;
      const victimFile = `${victimDir}/secret.txt`;
      await vfs.mkdir(victimDir, { recursive: true, mode: 0o700, uid: 0, gid: 0 });
      await vfs.chown(victimDir, 10002, 10002, { uid: 0, gid: 0 });
      await vfs.writeFile(victimFile, `victim-secret-${nonce}`, { mode: 0o600, uid: 0, gid: 0 });
      await vfs.chown(victimFile, 10002, 10002, { uid: 0, gid: 0 });
      await vfs.chmod(victimFile, 0o600, { uid: 0, gid: 0 });

      const attackerCtx = {
        platform: 'android',
        appId: `com.attacker.${nonce}`,
        uid: 10001,
        gid: 10001,
      };
      await assert.rejects(
        async () => vfs.readFile(`/data/data/com.attacker.${nonce}/../com.victim.${nonce}/secret.txt`, { encoding: 'utf8', ...attackerCtx }),
        (err) => err instanceof Error && ['EACCES', 'EINVAL', 'E_PATH_TRAVERSAL', 'ENOENT'].includes(err.code),
        'Cross-app container traversal escape via ".." MUST be rejected'
      );
    } finally {
      await os?.shutdown();
    }
  });

  test('T3 [F-017, Edge Case #28]: Windows case-insensitive lookup preserving creation case vs POSIX case sensitivity', async () => {
    const nonce = makeNonce();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const vfs = os.require('vfs');
      const { windowsMixedCase } = getVfsEdgeCasePayloads();

      const v1 = `case-v1-${nonce}`;
      await vfs.writeFile(windowsMixedCase.createPath, v1, { platform: 'windows', uid: 1000, gid: 1000 });

      const canonStat = await vfs.stat(windowsMixedCase.canonicalExpected, { platform: 'posix', uid: 1000, gid: 1000 });
      const canonIno = getInode(canonStat);
      assert.ok(canonIno !== undefined && canonIno !== null, 'Created canonical file must have an inode');

      // Lookup via all case variants on Windows platform -> identical content & inode
      const allVariants = [
        ...windowsMixedCase.lookupVariants,
        'c:\\users\\USER\\documents\\casetest_abc.txt',
      ];
      for (const variant of allVariants) {
        const text = await vfs.readFile(variant, { encoding: 'utf8', platform: 'windows', uid: 1000, gid: 1000 });
        assert.equal(text, v1, `Windows case-insensitive lookup "${variant}" must read exact content`);
        const st = await vfs.stat(variant, { platform: 'windows', uid: 1000, gid: 1000 });
        assert.equal(getInode(st), canonIno, `Windows lookup "${variant}" must resolve to identical canonical inode`);
      }

      // Directory listing preserves original creation case with zero case-variant duplicates
      const listEntries = async () => {
        const raw = await vfs.readdir('/home/user/Documents', { platform: 'posix', uid: 1000, gid: 1000 });
        return raw.map((e) => (typeof e === 'string' ? e : e?.name));
      };
      const names1 = await listEntries();
      assert.ok(names1.includes(windowsMixedCase.preservedBasename), `readdir must preserve "${windowsMixedCase.preservedBasename}"`);
      assert.ok(!names1.includes('casetest_abc.txt'), 'readdir must not contain lowercase duplicate');
      assert.ok(!names1.includes('CASETEST_ABC.TXT'), 'readdir must not contain uppercase duplicate');

      // Overwrite via lowercase Windows path updates the SAME inode and preserves creation case
      const v2 = `case-v2-${nonce}`;
      await vfs.writeFile('c:\\users\\USER\\documents\\casetest_abc.txt', v2, { platform: 'windows', uid: 1000, gid: 1000 });
      assert.equal(
        await vfs.readFile(windowsMixedCase.canonicalExpected, { encoding: 'utf8', platform: 'posix', uid: 1000, gid: 1000 }),
        v2,
        'Lowercase Windows overwrite must update the canonical mixed-case file'
      );
      const names2 = await listEntries();
      assert.equal(
        names2.filter((n) => n.toLowerCase() === windowsMixedCase.preservedBasename.toLowerCase()).length,
        1,
        'Overwrite via different case on Windows must NOT create duplicate dirents'
      );
      assert.ok(names2.includes(windowsMixedCase.preservedBasename), 'Original creation case must remain preserved after overwrite');

      // POSIX contrast: lowercase lookup MUST fail with ENOENT
      await assertVfsError(
        () => vfs.readFile('/home/user/Documents/casetest_abc.txt', { encoding: 'utf8', platform: 'posix', uid: 1000, gid: 1000 }),
        'ENOENT',
        'POSIX lookup with wrong case must fail with ENOENT'
      );

      // Unlink via uppercase Windows path removes the canonical inode
      await vfs.unlink('C:\\Users\\user\\Documents\\CASETEST_ABC.TXT', { platform: 'windows', uid: 1000, gid: 1000 });
      await assertVfsError(
        () => vfs.stat(windowsMixedCase.canonicalExpected, { platform: 'posix', uid: 1000, gid: 1000 }),
        'ENOENT',
        'Canonical file must be removed after Windows case-insensitive unlink'
      );
    } finally {
      await os?.shutdown();
    }
  });

  test('T4 [F-016, Contract 2]: Complete POSIX VFS error code matrix (ENOENT, EEXIST, EISDIR, ENOTDIR, EINVAL, EACCES)', async () => {
    const nonce = makeNonce();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const vfs = os.require('vfs');
      const rootCtx = { uid: 0, gid: 0 };

      const dir = `/tmp/errdir-${nonce}`;
      const file = `${dir}/f.txt`;
      const missing = `/tmp/missing-${nonce}`;
      await vfs.mkdir(dir, { recursive: false, uid: 0, gid: 0 });
      await vfs.writeFile(file, 'hello', rootCtx);

      // ENOENT
      await assertVfsError(() => vfs.stat(missing, rootCtx), 'ENOENT', 'stat missing');
      await assertVfsError(() => vfs.lstat(missing, rootCtx), 'ENOENT', 'lstat missing');
      await assertVfsError(() => vfs.readFile(missing, rootCtx), 'ENOENT', 'readFile missing');
      await assertVfsError(() => vfs.unlink(missing, rootCtx), 'ENOENT', 'unlink missing');
      await assertVfsError(() => vfs.rmdir(missing, rootCtx), 'ENOENT', 'rmdir missing');
      await assertVfsError(() => vfs.readlink(missing, rootCtx), 'ENOENT', 'readlink missing');
      await assertVfsError(() => vfs.rename(missing, `${missing}-dst`, rootCtx), 'ENOENT', 'rename missing');
      await assertVfsError(() => vfs.mkdir(`/tmp/nope-${nonce}/sub`, { recursive: false, ...rootCtx }), 'ENOENT', 'mkdir non-recursive missing parent');

      // EEXIST
      await assertVfsError(() => vfs.mkdir(dir, { recursive: false, ...rootCtx }), 'EEXIST', 'mkdir existing dir');
      await assertVfsError(() => vfs.mkdir(file, { recursive: false, ...rootCtx }), 'EEXIST', 'mkdir existing file');
      await assertVfsError(() => vfs.symlink(file, file, rootCtx), 'EEXIST', 'symlink over existing path');

      // EISDIR
      await assertVfsError(() => vfs.readFile(dir, rootCtx), 'EISDIR', 'readFile on directory');
      await assertVfsError(() => vfs.writeFile(dir, 'x', rootCtx), 'EISDIR', 'writeFile on directory');
      await assertVfsError(() => vfs.unlink(dir, rootCtx), 'EISDIR', 'unlink on directory');

      // ENOTDIR
      await assertVfsError(() => vfs.readdir(file, rootCtx), 'ENOTDIR', 'readdir on file');
      await assertVfsError(() => vfs.stat(`${file}/child`, rootCtx), 'ENOTDIR', 'stat through file as dir');
      await assertVfsError(() => vfs.mkdir(`${file}/child`, { recursive: false, ...rootCtx }), 'ENOTDIR', 'mkdir under file');
      await assertVfsError(() => vfs.rmdir(file, rootCtx), 'ENOTDIR', 'rmdir on file');

      // EINVAL
      await assertVfsError(() => vfs.readlink(file, rootCtx), 'EINVAL', 'readlink on non-symlink');
      await assertVfsError(() => vfs.stat('', rootCtx), ['EINVAL', 'ENOENT'], 'stat empty path');
      await assertVfsError(() => vfs.stat('/tmp/bad\0name', rootCtx), 'EINVAL', 'stat NUL-byte path');

      // Non-empty rmdir
      await assertVfsError(() => vfs.rmdir(dir, rootCtx), ['ENOTEMPTY', 'EEXIST', 'EINVAL'], 'rmdir non-empty directory');

      // EACCES
      await vfs.chown(file, 10042, 10042, rootCtx);
      await vfs.chmod(file, 0o600, rootCtx);
      await assertVfsError(() => vfs.readFile(file, { uid: 10099, gid: 10099 }), 'EACCES', 'readFile 0o600 by non-owner');
      await assertVfsError(() => vfs.writeFile(file, 'x', { uid: 10099, gid: 10099 }), 'EACCES', 'writeFile 0o600 by non-owner');
    } finally {
      await os?.shutdown();
    }
  });

  test('T5 [F-020]: Virtual mount boundaries — /dev/null discard, /dev/zero exact byte count, /dev/urandom length & read-only /proc write rejection', async () => {
    const nonce = makeNonce();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const vfs = os.require('vfs');
      const rootCtx = { uid: 0, gid: 0 };

      // /dev/null discards arbitrary writes and always reads 0 bytes
      await vfs.writeFile('/dev/null', crypto.randomBytes(64 * 1024), rootCtx);
      await vfs.writeFile('/dev/null', 'append-discard', { append: true, ...rootCtx });
      assert.equal(toBuffer(await vfs.readFile('/dev/null', rootCtx)).length, 0, '/dev/null must read 0 bytes');
      assert.equal(toBuffer(await vfs.readFile('/dev/null', { length: 1024, ...rootCtx })).length, 0, '/dev/null with length=1024 must still read 0 bytes');

      // /dev/zero returns exact requested byte count, all 0x00
      for (const len of [0, 1, 64, 4097]) {
        const buf = toBuffer(await vfs.readFile('/dev/zero', { length: len, ...rootCtx }));
        assert.equal(buf.length, len, `/dev/zero length=${len} must return exact byte count`);
        assert.ok(buf.every((b) => b === 0), `/dev/zero length=${len} must contain only 0x00 bytes`);
      }

      // /dev/urandom returns exact requested length with distinct non-zero entropy
      const randA = toBuffer(await vfs.readFile('/dev/urandom', { length: 32, ...rootCtx }));
      const randB = toBuffer(await vfs.readFile('/dev/urandom', { length: 32, ...rootCtx }));
      const rand64 = toBuffer(await vfs.readFile('/dev/urandom', { length: 64, ...rootCtx }));
      assert.equal(randA.length, 32, '/dev/urandom length=32 must return 32 bytes');
      assert.equal(randB.length, 32);
      assert.equal(rand64.length, 64, '/dev/urandom length=64 must return 64 bytes');
      assert.ok(randA.some((b) => b !== 0), '/dev/urandom must not return all zeros');
      assert.notEqual(Buffer.compare(randA, randB), 0, 'Two consecutive 32B reads from /dev/urandom must differ');

      // Read-only /proc write/mutate rejections
      const roCodes = ['EACCES', 'EROFS', 'EINVAL'];
      await assertVfsError(() => vfs.writeFile('/proc/uptime', '0', rootCtx), roCodes, 'write /proc/uptime');
      await assertVfsError(() => vfs.writeFile('/proc/1/status', 'x', rootCtx), roCodes, 'write /proc/1/status');
      await assertVfsError(() => vfs.writeFile(`/proc/new-${nonce}`, 'x', rootCtx), roCodes, 'create /proc/new');
      await assertVfsError(() => vfs.unlink('/proc/uptime', rootCtx), roCodes, 'unlink /proc/uptime');
      await assertVfsError(() => vfs.mkdir(`/proc/d-${nonce}`, rootCtx), roCodes, 'mkdir under /proc');

      // Non-existent /proc/<pid>/status -> ENOENT
      await assertVfsError(() => vfs.readFile('/proc/999999/status', { encoding: 'utf8', ...rootCtx }), 'ENOENT', 'read /proc/999999/status');

      // Verify /proc remains healthy and readable
      const uptimeText = await vfs.readFile('/proc/uptime', { encoding: 'utf8', ...rootCtx });
      assert.ok(typeof uptimeText === 'string' && uptimeText.trim().length > 0, '/proc/uptime must remain readable');
      const pid1Status = await vfs.readFile('/proc/1/status', { encoding: 'utf8', ...rootCtx });
      assert.ok(typeof pid1Status === 'string' && pid1Status.length > 0, '/proc/1/status must remain readable');
    } finally {
      await os?.shutdown();
    }
  });

  test('T6 [F-016 - F-020, Contracts 7 & 8]: REST /api/v1/vfs/* & CLI negative boundaries (404, 400, ELOOP, /proc write, NUL/traversal)', async () => {
    const nonce = makeNonce();
    let srv = null;
    try {
      srv = await startOmniServer();

      // 404 on missing paths
      const resStat404 = await srv.api.get('/api/v1/vfs/stat', { query: { path: `/missing-${nonce}` } });
      assert.equal(resStat404.status, 404, `GET vfs/stat missing must return 404 (got ${resStat404.status})`);

      const resFile404 = await srv.api.get('/api/v1/vfs/file', { query: { path: `/missing-${nonce}` } });
      assert.equal(resFile404.status, 404, `GET vfs/file missing must return 404 (got ${resFile404.status})`);

      const resLs404 = await srv.api.get('/api/v1/vfs/ls', { query: { path: `/missing-${nonce}` } });
      assert.equal(resLs404.status, 404, `GET vfs/ls missing must return 404 (got ${resLs404.status})`);

      // Reading a directory as a file -> 4xx
      const resDirAsFile = await srv.api.get('/api/v1/vfs/file', { query: { path: '/home/user/Documents' } });
      assert.ok(
        resDirAsFile.status >= 400 && resDirAsFile.status < 500,
        `GET vfs/file on directory must return 4xx (got ${resDirAsFile.status})`
      );

      // Missing required path on mkdir -> 400
      const resMkdir400 = await srv.api.post('/api/v1/vfs/mkdir', {});
      assert.equal(resMkdir400.status, 400, `POST vfs/mkdir {} must return 400 (got ${resMkdir400.status})`);

      // Symlink cycle over REST -> 4xx mentioning ELOOP/loop (no hang)
      const linkA = `/tmp/ra_${nonce}`;
      const linkB = `/tmp/rb_${nonce}`;
      const resSym1 = await srv.api.post('/api/v1/vfs/symlink', { target: linkB, linkPath: linkA });
      assert.ok(resSym1.ok, `Creating symlink A->B via REST must succeed (got ${resSym1.status}: ${resSym1.text})`);
      const resSym2 = await srv.api.post('/api/v1/vfs/symlink', { target: linkA, linkPath: linkB });
      assert.ok(resSym2.ok, `Creating symlink B->A via REST must succeed (got ${resSym2.status}: ${resSym2.text})`);

      const resLoop = await srv.api.get('/api/v1/vfs/file', { query: { path: linkA } });
      assert.ok(
        resLoop.status >= 400 && resLoop.status < 500,
        `GET vfs/file on symlink cycle must return 4xx (got ${resLoop.status}: ${resLoop.text})`
      );
      assert.match(resLoop.text, /ELOOP|loop|symlink/i, `Symlink cycle HTTP error should identify ELOOP/loop (got ${resLoop.text})`);

      // Pre-condition: prove /api/v1/vfs/file write route actually works & create safe file BEFORE negative checks
      const safePath = `/home/user/Documents/safe-${nonce}.txt`;
      const safeBody = `safe-rest-body-${nonce}`;
      const { method: writeMethod, res: resCreateSafe } = await discoverWorkingMutateVerb(
        srv.api,
        '/api/v1/vfs/file',
        { path: safePath, content: safeBody, data: safeBody }
      );
      assert.ok(
        resCreateSafe.ok,
        `Pre-condition: creating ${safePath} via /api/v1/vfs/file must succeed (got ${resCreateSafe.status}: ${resCreateSafe.text})`
      );
      const resSafeRead = await srv.api.get('/api/v1/vfs/file', { query: { path: safePath } });
      assert.equal(resSafeRead.status, 200, `Pre-condition: reading back ${safePath} must return 200 (got ${resSafeRead.status})`);
      assert.ok(resSafeRead.text.includes(safeBody), `Pre-condition: ${safePath} must read back written body`);

      // Write to read-only /proc/uptime via exact proven writeMethod (ZERO fallback!) -> 4xx excluding 404/405
      const resProcWrite = await srv.api.request(writeMethod, '/api/v1/vfs/file', {
        body: { path: '/proc/uptime', content: 'hacked', data: 'hacked' },
      });
      assert.ok(
        resProcWrite.status >= 400 && resProcWrite.status < 500 &&
        resProcWrite.status !== 404 && resProcWrite.status !== 405,
        `Writing to /proc/uptime via ${writeMethod} /api/v1/vfs/file must return 400/403/409 (not 404/405, got ${resProcWrite.status}: ${resProcWrite.text})`
      );
      const resProcRead = await srv.api.get('/api/v1/vfs/file', { query: { path: '/proc/uptime' } });
      assert.equal(resProcRead.status, 200, '/proc/uptime must remain readable after rejected REST write');
      assert.ok(!resProcRead.text.includes('hacked'), 'Rejected write must not modify /proc/uptime');

      // NUL-byte URL injection against EXISTING safePath (defeats naive %00-truncating handlers!)
      const resNul = await srv.api.get(`/api/v1/vfs/file?path=${encodeURIComponent(safePath)}%00evil`);
      assert.ok(
        !resNul.ok && resNul.status >= 400 && resNul.status < 500,
        `NUL-byte VFS REST path must return 4xx (got ${resNul.status}: ${resNul.text})`
      );
      assert.ok(!resNul.text.includes(safeBody), 'NUL-byte path truncation MUST NOT leak contents of existing safe file');

      const resTrav = await srv.api.get('/api/v1/vfs/file', { query: { path: '../../../../etc/passwd' } });
      assert.ok(!resTrav.ok, `Traversal ../../../../etc/passwd must not succeed (got ${resTrav.status})`);
      assert.ok(!resTrav.text.includes('root:x:0:0:'), 'REST VFS traversal MUST NEVER leak host /etc/passwd');

      // Remote CLI negative VFS checks
      const cliMissing = await srv.runCli(['vfs', 'cat', `/missing-${nonce}`], { json: true });
      assert.notEqual(cliMissing.code, 0, 'CLI vfs cat on missing file must exit non-zero');

      const cliProcWrite = await srv.runCli(['vfs', 'write', '/proc/uptime', 'x'], { json: true });
      assert.notEqual(cliProcWrite.code, 0, 'CLI vfs write to /proc/uptime must exit non-zero');

      // Final server liveness check
      const health = await srv.api.get('/api/health');
      assert.equal(health.status, 200);
      assert.equal(health.json?.ok, true);
      assert.equal(health.json?.os, 'OmniOS');
    } finally {
      await srv?.stop();
    }
  });
});
