/**
 * Tier 1 E2E Tests — FA-03: Virtual Memory R/W/X Protection, Heap & Sandbox Quotas
 * Features covered: F-011, F-012, F-013, F-014, F-035
 * Contracts: Contract 1 (IAddressSpace, ProcessManager quotas), Contract 2 (IVFS errors), Contract 7 (REST)
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

const PROT_NONE = 0;
const PROT_READ = 1;
const PROT_WRITE = 2;
const PROT_EXEC = 4;

const REQUIRED_AS_METHODS = [
  'mmap',
  'reserveGuard',
  'munmap',
  'mprotect',
  'read',
  'write',
  'fetch',
  'alloc',
  'free',
  'realloc',
  'getStats',
];

function makeNonce() {
  return `${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`;
}

function makeIdleContext(maxSteps = 10, exitCode = 0) {
  let steps = 0;
  return {
    get steps() {
      return steps;
    },
    step(budget = 1) {
      steps += 1;
      const insns = Math.max(1, Math.min(budget, 5));
      if (steps >= maxSteps) {
        return { status: 'EXITED', instructionsExecuted: insns, exitCode };
      }
      return { status: 'YIELD', instructionsExecuted: insns };
    },
    deliverEvent() {},
    getDebugState() {
      return { arch: 'test', pc: steps * 4, sp: 0x1000, registers: {}, instructionsExecuted: steps, lastSyscall: null, stackTop: 0x1000 };
    },
    dispose() {},
  };
}

function getAddressSpace(pcb) {
  const as = pcb?.addressSpace ?? pcb?.addrSpace ?? pcb?.memory ?? pcb?.vmm;
  assert.ok(as && typeof as === 'object', `Spawned PCB (pid=${pcb?.pid}) must expose a per-PID AddressSpace`);
  for (const fn of REQUIRED_AS_METHODS) {
    assert.equal(typeof as[fn], 'function', `AddressSpace must implement Contract 1 method "${fn}"`);
  }
  return as;
}

function unwrapObject(payload, keys = ['diagnostics', 'kernel', 'process', 'data']) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return payload;
  for (const key of keys) {
    if (payload[key] && typeof payload[key] === 'object' && !Array.isArray(payload[key])) {
      return payload[key];
    }
  }
  return payload;
}

function assertMemoryFault(fn, label) {
  let caught = null;
  try {
    fn();
  } catch (err) {
    caught = err;
  }
  assert.ok(caught instanceof Error, `Expected MemoryFaultError/SIGSEGV on ${label}, but operation succeeded`);
  const isMemFault =
    caught.signal === 'SIGSEGV' ||
    /MemoryFault|SIGSEGV|EFAULT|EACCES|PROT|PERM/i.test(`${caught.name ?? ''} ${caught.code ?? ''} ${caught.message ?? ''}`);
  assert.ok(
    isMemFault,
    `Expected MemoryFaultError/SIGSEGV on ${label}, got name=${caught.name} code=${caught.code} signal=${caught.signal} msg=${caught.message}`
  );
}

describe('Tier 1 — FA-03: Virtual Memory R/W/X Protection, Heap & Sandbox Quotas', () => {
  test('T1 [F-012]: Sparse 4KB AddressSpace mmap/munmap, cross-page R/W & per-PID isolation', async () => {
    const os = await loadPublicOmniOS();
    try {
      const pm = os.require('processManager');
      os.require('scheduler').stop?.();
      const nonce = makeNonce();

      const pcbA = pm.spawn({ name: `vmm-a-${nonce}`, platform: 'universal', arch: 'wasm', executionContext: makeIdleContext() });
      const pcbB = pm.spawn({ name: `vmm-b-${nonce}`, platform: 'universal', arch: 'wasm', executionContext: makeIdleContext() });
      const asA = getAddressSpace(pcbA);
      const asB = getAddressSpace(pcbB);

      const baseA = asA.mmap(0x100000, 8192, PROT_READ | PROT_WRITE, `bufA-${nonce}`);
      const baseB = asB.mmap(0x100000, 8192, PROT_READ | PROT_WRITE, `bufB-${nonce}`);
      assert.equal(typeof baseA, 'number');
      assert.equal(typeof baseB, 'number');

      // Cross the 4KB page boundary (offset 4090..4122 spans page 0 and page 1)
      const bytesA = crypto.randomBytes(32);
      const bytesB = crypto.randomBytes(32);
      assert.equal(bytesA.equals(bytesB), false, 'Random test payloads must differ');

      asA.write(baseA + 4090, bytesA);
      asB.write(baseB + 4090, bytesB);

      const readA = Buffer.from(asA.read(baseA + 4090, 32));
      const readB = Buffer.from(asB.read(baseB + 4090, 32));
      assert.ok(readA.equals(bytesA), 'Process A cross-page readback must match written bytes');
      assert.ok(readB.equals(bytesB), 'Process B cross-page readback must match written bytes');
      assert.equal(readA.equals(readB), false, 'Per-PID AddressSpaces must be strictly isolated at identical virtual addresses');

      // Sparse high-address mapping must allocate real pages without allocating intermediate pages
      const statsBeforeHigh = asA.getStats();
      assert.ok(
        statsBeforeHigh.mappedPages >= 2,
        `Expected >= 2 mapped pages after 8KB cross-page write, got ${statsBeforeHigh.mappedPages}`
      );
      assert.ok(
        statsBeforeHigh.usedBytes > 0,
        `Expected usedBytes > 0 after mmap+write, got ${statsBeforeHigh.usedBytes}`
      );
      assert.ok(
        statsBeforeHigh.peakBytes >= statsBeforeHigh.usedBytes && statsBeforeHigh.peakBytes > 0,
        `Expected peakBytes >= usedBytes > 0, got peak=${statsBeforeHigh.peakBytes}, used=${statsBeforeHigh.usedBytes}`
      );

      const pagesBefore = statsBeforeHigh.mappedPages;
      const highBase = asA.mmap(0x40000000, 4096, PROT_READ | PROT_WRITE, `sparse-${nonce}`);
      const highPayload = crypto.randomBytes(16);
      asA.write(highBase, highPayload);
      assert.ok(Buffer.from(asA.read(highBase, 16)).equals(highPayload));

      const pagesAfterMap = asA.getStats().mappedPages;
      assert.ok(
        pagesAfterMap > pagesBefore && pagesAfterMap <= pagesBefore + 2,
        `Sparse high-VA mapping must allocate 1..2 pages (before=${pagesBefore}, after=${pagesAfterMap})`
      );

      asA.munmap(highBase, 4096);
      assert.equal(
        asA.getStats().mappedPages,
        pagesBefore,
        'munmap() must release mapped pages back to prior count'
      );
    } finally {
      await os.shutdown();
    }
  });

  test('T2 [F-012]: Non-allocating 4 GiB __PAGEZERO virtual guard region', async () => {
    const os = await loadPublicOmniOS();
    try {
      const pm = os.require('processManager');
      os.require('scheduler').stop?.();
      const nonce = makeNonce();

      const pcb = pm.spawn({
        name: `pagezero-${nonce}`,
        platform: 'macos',
        arch: 'arm64',
        quotas: { maxMemoryBytes: 4 * 1024 * 1024 },
        executionContext: makeIdleContext(),
      });
      const as = getAddressSpace(pcb);

      const before = as.getStats();
      as.reserveGuard(0, 0x100000000, '__PAGEZERO');
      const after = as.getStats();

      assert.equal(
        after.mappedPages,
        before.mappedPages,
        `4 GiB __PAGEZERO guard must allocate 0 physical pages (before=${before.mappedPages}, after=${after.mappedPages})`
      );
      assert.equal(
        after.usedBytes,
        before.usedBytes,
        `4 GiB __PAGEZERO guard must consume 0 RAM bytes (before=${before.usedBytes}, after=${after.usedBytes})`
      );
      assert.ok(
        Array.isArray(after.regions) && after.regions.some((r) => r?.label === '__PAGEZERO'),
        'AddressSpace regions telemetry must record __PAGEZERO guard region'
      );

      // Reading inside __PAGEZERO virtual guard must fault with MemoryFaultError / SIGSEGV
      assertMemoryFault(() => as.read(0x1000, 4), 'read inside __PAGEZERO guard region');

      // Mapping & accessing normal memory above 4 GiB must work cleanly and increase telemetry
      const aboveBase = as.mmap(0x100004000, 4096, PROT_READ | PROT_WRITE, `above-pz-${nonce}`);
      const payload = Buffer.from(`above-pagezero-${nonce}`, 'utf8');
      as.write(aboveBase, payload);
      assert.ok(Buffer.from(as.read(aboveBase, payload.length)).equals(payload));
      const afterNormal = as.getStats();
      assert.ok(
        afterNormal.mappedPages > after.mappedPages,
        `Normal mmap+write above __PAGEZERO must increase mappedPages (afterGuard=${after.mappedPages}, afterNormal=${afterNormal.mappedPages})`
      );
      assert.ok(
        afterNormal.usedBytes > after.usedBytes,
        `Normal mmap+write above __PAGEZERO must increase usedBytes (afterGuard=${after.usedBytes}, afterNormal=${afterNormal.usedBytes})`
      );
      assert.ok(afterNormal.peakBytes > 0, `peakBytes must be > 0 after allocation, got ${afterNormal.peakBytes}`);
    } finally {
      await os.shutdown();
    }
  });

  test('T3 [F-013]: R/W/X page permissions on granted pages & W^X mprotect transitions', async () => {
    const os = await loadPublicOmniOS();
    try {
      const pm = os.require('processManager');
      os.require('scheduler').stop?.();
      const nonce = makeNonce();

      const pcb = pm.spawn({ name: `wx-${nonce}`, platform: 'windows', arch: 'x86_64', executionContext: makeIdleContext() });
      const as = getAddressSpace(pcb);

      const base = as.mmap(0x200000, 4096, PROT_READ | PROT_WRITE, `wx-${nonce}`);
      const nonceBytes = crypto.randomBytes(10);
      const code1 = Buffer.concat([Buffer.from([0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3]), nonceBytes]);

      // Write & read succeed while RW; NX fetch MUST fault
      as.write(base, code1);
      assert.ok(Buffer.from(as.read(base, code1.length)).equals(code1));
      assertMemoryFault(() => as.fetch(base, 4), 'NX fetch on PROT_READ|PROT_WRITE page');

      // W^X transition: RW -> RX -> fetch & read succeed; write MUST fault
      as.mprotect(base, 4096, PROT_READ | PROT_EXEC);
      const fetched = Buffer.from(as.fetch(base, code1.length));
      assert.ok(fetched.equals(code1), 'fetch() on PROT_READ|PROT_EXEC page must return exact code bytes');
      assert.ok(Buffer.from(as.read(base, code1.length)).equals(code1), 'read() on PROT_READ|PROT_EXEC page must succeed');
      assertMemoryFault(() => as.write(base, Buffer.from([0x90])), 'write on PROT_READ|PROT_EXEC page after mprotect');

      // Transition to RO -> read succeeds; write & NX fetch MUST fault
      as.mprotect(base, 4096, PROT_READ);
      assert.ok(Buffer.from(as.read(base, code1.length)).equals(code1));
      assertMemoryFault(() => as.write(base, Buffer.from([0x90])), 'write on PROT_READ (RO) page after mprotect');
      assertMemoryFault(() => as.fetch(base, 4), 'NX fetch on PROT_READ (RO) page after mprotect');

      // Transition back to RW -> write new bytes & read back
      as.mprotect(base, 4096, PROT_READ | PROT_WRITE);
      const code2 = crypto.randomBytes(code1.length);
      as.write(base, code2);
      assert.ok(Buffer.from(as.read(base, code2.length)).equals(code2));

      // RWX mapping supports write, read, and fetch simultaneously
      const rwxBase = as.mmap(0x210000, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, `rwx-${nonce}`);
      const rwxBytes = crypto.randomBytes(16);
      as.write(rwxBase, rwxBytes);
      assert.ok(Buffer.from(as.read(rwxBase, 16)).equals(rwxBytes));
      assert.ok(Buffer.from(as.fetch(rwxBase, 16)).equals(rwxBytes));

      // Transition to PROT_NONE -> read, write, and fetch MUST all fault; restoring PROT_READ allows readback
      as.mprotect(rwxBase, 4096, PROT_NONE);
      assertMemoryFault(() => as.read(rwxBase, 4), 'read on PROT_NONE page after mprotect');
      assertMemoryFault(() => as.write(rwxBase, Buffer.from([0x01])), 'write on PROT_NONE page after mprotect');
      assertMemoryFault(() => as.fetch(rwxBase, 4), 'fetch on PROT_NONE page after mprotect');
      as.mprotect(rwxBase, 4096, PROT_READ);
      assert.ok(Buffer.from(as.read(rwxBase, 16)).equals(rwxBytes));
    } finally {
      await os.shutdown();
    }
  });

  test('T4 [F-014]: Per-PID free-list heap alloc/realloc/free, block coalescing & getStats() telemetry', async () => {
    const os = await loadPublicOmniOS();
    try {
      const pm = os.require('processManager');
      os.require('scheduler').stop?.();
      const nonce = makeNonce();

      const pcb = pm.spawn({ name: `heap-${nonce}`, platform: 'universal', arch: 'wasm', executionContext: makeIdleContext() });
      const as = getAddressSpace(pcb);

      const initStats = as.getStats();
      assert.equal(typeof initStats.mappedPages, 'number');
      assert.equal(typeof initStats.usedBytes, 'number');
      assert.equal(typeof initStats.peakBytes, 'number');
      assert.equal(typeof initStats.maxBytes, 'number');
      assert.ok(Array.isArray(initStats.regions), 'getStats().regions must be an Array');

      const p1 = as.alloc(256);
      const p2 = as.alloc(256);
      const p3 = as.alloc(256);
      assert.ok(p1 > 0 && p2 > 0 && p3 > 0, 'alloc() must return non-zero heap pointers');
      assert.ok(p1 !== p2 && p2 !== p3 && p1 !== p3, 'Distinct allocations must return distinct pointers');

      const d1 = crypto.randomBytes(256);
      const d2 = crypto.randomBytes(256);
      const d3 = crypto.randomBytes(256);
      as.write(p1, d1);
      as.write(p2, d2);
      as.write(p3, d3);
      assert.ok(Buffer.from(as.read(p1, 256)).equals(d1), 'Heap block p1 must not be clobbered by p2/p3');
      assert.ok(Buffer.from(as.read(p2, 256)).equals(d2), 'Heap block p2 must not be clobbered by p1/p3');
      assert.ok(Buffer.from(as.read(p3, 256)).equals(d3), 'Heap block p3 must not be clobbered by p1/p2');

      // realloc() preserves existing prefix and expands capacity
      const p1Grown = as.realloc(p1, 1024);
      assert.ok(p1Grown > 0, 'realloc() must return a valid pointer');
      assert.ok(Buffer.from(as.read(p1Grown, 256)).equals(d1), 'realloc() must preserve original 256-byte prefix');
      const tail = crypto.randomBytes(768);
      as.write(p1Grown + 256, tail);
      assert.ok(Buffer.from(as.read(p1Grown + 256, 768)).equals(tail));

      const afterInitialAllocs = as.getStats();
      assert.ok(afterInitialAllocs.mappedPages > 0, `Expected mappedPages > 0 after alloc, got ${afterInitialAllocs.mappedPages}`);
      assert.ok(afterInitialAllocs.usedBytes > 0, `Expected usedBytes > 0 after alloc, got ${afterInitialAllocs.usedBytes}`);
      assert.ok(
        afterInitialAllocs.peakBytes >= afterInitialAllocs.usedBytes && afterInitialAllocs.peakBytes > 0,
        `Expected peakBytes >= usedBytes > 0, got peak=${afterInitialAllocs.peakBytes}, used=${afterInitialAllocs.usedBytes}`
      );

      // Adjacent free block coalescing on a clean AddressSpace (zero prior holes from realloc)
      const pcbCoal = pm.spawn({ name: `heap-coal-${nonce}`, platform: 'universal', arch: 'wasm', executionContext: makeIdleContext() });
      try {
        const asCoal = getAddressSpace(pcbCoal);
        const a = asCoal.alloc(512);
        const b = asCoal.alloc(512);
        const fence = asCoal.alloc(512);
        assert.ok(a > 0 && b > 0 && fence > 0, 'Coalescing test allocations must return non-zero heap pointers');
        assert.ok(a !== b && b !== fence && a !== fence, 'Coalescing test allocations must return distinct pointers');
        const fenceData = crypto.randomBytes(512);
        asCoal.write(fence, fenceData);
        asCoal.free(a);
        asCoal.free(b);

        const merged = asCoal.alloc(900);
        assert.ok(merged > 0, 'Coalesced free blocks must satisfy a 900-byte allocation');
        const rangeLo = Math.min(a, b);
        const rangeHi = Math.max(a, b) + 512;
        assert.ok(
          merged >= rangeLo && merged + 900 <= rangeHi + 64 && merged !== fence,
          `Coalesced 900B allocation must reuse freed [a, b] address range without overlapping fence ` +
            `(a=${a}, b=${b}, fence=${fence}, merged=${merged})`
        );
        const mergedData = crypto.randomBytes(900);
        asCoal.write(merged, mergedData);
        assert.ok(Buffer.from(asCoal.read(merged, 900)).equals(mergedData));
        assert.ok(Buffer.from(asCoal.read(fence, 512)).equals(fenceData), 'Live fence block must not be clobbered by coalesced allocation');

        asCoal.free(merged);
        asCoal.free(fence);
      } finally {
        pm.kill(pcbCoal.pid, 'SIGKILL');
      }

      const beforeLoop = as.getStats();
      assert.ok(beforeLoop.usedBytes > 0 && beforeLoop.mappedPages > 0, 'Heap stats must remain positive before reuse loop');
      const seenLoopPtrs = new Set();
      for (let i = 0; i < 20; i += 1) {
        const tmp = as.alloc(512);
        assert.ok(tmp > 0);
        seenLoopPtrs.add(tmp);
        as.free(tmp);
      }
      assert.ok(
        seenLoopPtrs.size < 20,
        `Free-list must reuse freed addresses across repeated alloc/free cycles (got ${seenLoopPtrs.size} unique pointers for 20 iterations)`
      );
      const afterLoop = as.getStats();
      assert.ok(afterLoop.usedBytes > 0, 'usedBytes must stay positive while earlier heap blocks remain live');
      assert.ok(
        afterLoop.usedBytes <= beforeLoop.usedBytes + 4096,
        `Free-list must reuse freed blocks without leaking (before=${beforeLoop.usedBytes}, after=${afterLoop.usedBytes})`
      );
      assert.ok(afterLoop.peakBytes >= afterLoop.usedBytes && afterLoop.peakBytes > 0, 'peakBytes must always be >= usedBytes > 0');

      as.free(p1Grown);
      as.free(p2);
      as.free(p3);
    } finally {
      await os.shutdown();
    }
  });

  test('T5 [F-011]: Process sandbox quotas configured, reported & respected within limits', async () => {
    const os = await loadPublicOmniOS();
    try {
      const pm = os.require('processManager');
      const sched = os.require('scheduler');
      const vfs = os.require('vfs');
      sched.stop?.();
      const nonce = makeNonce();

      const quotas = {
        maxMemoryBytes: 2 * 1024 * 1024,
        maxInstructionsPerTick: 50,
        maxTotalInstructions: 500,
        maxOpenFds: 16,
        maxWindows: 4,
      };

      const workerCtx = makeIdleContext(8, 0);
      const pcb = pm.spawn({
        name: `quota-ok-${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        uid: 1000,
        gid: 1000,
        quotas,
        executionContext: workerCtx,
      });

      const sibling = pm.spawn({
        name: `quota-sib-${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        uid: 1000,
        gid: 1000,
        executionContext: makeIdleContext(100, 0),
      });

      assert.ok(pcb.quotas && typeof pcb.quotas === 'object', 'PCB must record configured sandbox quotas');
      const as = getAddressSpace(pcb);
      const stats = as.getStats();
      assert.ok(stats.maxBytes > 0, 'AddressSpace stats must report positive maxBytes memory quota');

      // Perform within-quota allocation, VFS open, and execution
      const ptr = as.alloc(4096);
      assert.ok(ptr > 0);
      const marker = Buffer.from(`within-quota-${nonce}`, 'utf8');
      as.write(ptr, marker);
      assert.ok(Buffer.from(as.read(ptr, marker.length)).equals(marker));

      const fd = await vfs.open(`/tmp/quota-${nonce}.txt`, 'w', { pid: pcb.pid, uid: 1000, gid: 1000 });
      assert.ok(fd !== null && fd !== undefined);

      await sched.runUntilIdle(pcb.pid, 100);
      assert.equal(pm.get(pcb.pid).exitCode, 0, 'Within-quota process must exit cleanly with exitCode 0');
      assert.ok(
        !['ZOMBIE', 'TERMINATED'].includes(pm.get(sibling.pid).state),
        'Healthy sibling process must remain alive'
      );

      pm.kill(sibling.pid, 'SIGTERM');
    } finally {
      await os.shutdown();
    }

    const srv = await startOmniServer();
    try {
      const kStatus = await srv.api.get('/api/v1/kernel/status');
      assert.equal(kStatus.status, 200);
      const diag = unwrapObject(kStatus.json);
      assert.ok(diag?.memoryStats && typeof diag.memoryStats === 'object', 'REST /api/v1/kernel/status must report memoryStats');

      const p1 = await srv.api.get('/api/v1/processes/1');
      assert.equal(p1.status, 200);
      assert.equal(unwrapObject(p1.json)?.pid, 1);
    } finally {
      await srv.stop();
    }
  });

  test('T6 [F-035]: Structured typed OS error hierarchy & non-crashing kernel isolation', async () => {
    const os = await loadPublicOmniOS();
    try {
      const kernel = os.require('kernel');
      const pm = os.require('processManager');
      const vfs = os.require('vfs');
      os.require('scheduler').stop?.();
      const nonce = makeNonce();

      const pcb = pm.spawn({ name: `err-iso-${nonce}`, platform: 'universal', arch: 'wasm', executionContext: makeIdleContext() });
      const as = getAddressSpace(pcb);

      // 1. VMM unmapped read raises structured Error with code or SIGSEGV signal
      let vmmErr = null;
      try {
        as.read(0xdead0000, 4);
      } catch (err) {
        vmmErr = err;
      }
      assert.ok(vmmErr instanceof Error, 'Unmapped VMM read must throw an Error');
      assert.ok(
        (typeof vmmErr.code === 'string' && vmmErr.code.length > 0) || vmmErr.signal === 'SIGSEGV',
        `Expected structured VMM error with .code or .signal==='SIGSEGV', got code=${vmmErr.code}, signal=${vmmErr.signal}`
      );
      assert.ok(typeof vmmErr.message === 'string' && vmmErr.message.length > 0);

      // 2. VFS missing path raises ENOENT
      let enoentErr = null;
      try {
        await vfs.stat(`/does-not-exist-${nonce}`);
      } catch (err) {
        enoentErr = err;
      }
      assert.ok(enoentErr instanceof Error, 'vfs.stat() on missing path must throw an Error');
      assert.equal(enoentErr.code, 'ENOENT', `Expected err.code === 'ENOENT', got ${enoentErr.code}`);

      // 3. VFS duplicate mkdir raises EEXIST
      const dupDir = `/tmp/dup-dir-${nonce}`;
      await vfs.mkdir(dupDir, { recursive: false, mode: 0o755 });
      let eexistErr = null;
      try {
        await vfs.mkdir(dupDir, { recursive: false, mode: 0o755 });
      } catch (err) {
        eexistErr = err;
      }
      assert.ok(eexistErr instanceof Error, 'Duplicate non-recursive mkdir must throw an Error');
      assert.equal(eexistErr.code, 'EEXIST', `Expected err.code === 'EEXIST', got ${eexistErr.code}`);

      // 4. Kernel remains healthy and subsequent VMM + VFS ops succeed cleanly
      assert.equal(kernel.getDiagnostics().state, 'RUNNING', 'Structured user/VFS/VMM errors must never crash the kernel');
      const ptr = as.alloc(64);
      assert.ok(ptr > 0);
      as.free(ptr);

      const okFile = `/tmp/after-err-${nonce}.txt`;
      await vfs.writeFile(okFile, `ok-${nonce}`);
      assert.equal(await vfs.readFile(okFile, { encoding: 'utf8' }), `ok-${nonce}`);
    } finally {
      await os.shutdown();
    }
  });
});
