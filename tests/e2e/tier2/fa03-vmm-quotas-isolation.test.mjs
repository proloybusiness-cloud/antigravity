/**
 * Tier 2 Boundary, Corner & Negative E2E Suite — FA-03:
 * Virtual Memory R/W/X Protection, __PAGEZERO Guard, Heap Allocator & Sandbox Quotas
 * (F-011 – F-014, F-035, Edge Case #21).
 *
 * Strictly opaque-box: imports ONLY Node 24 built-ins and ../lib/env.mjs.
 * Zero skips, zero stubs, zero private internal os imports.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { loadPublicOmniOS } from '../lib/env.mjs';

const PROT_NONE = 0;
const PROT_READ = 1;
const PROT_WRITE = 2;
const PROT_EXEC = 4;

function makeNonce() {
  return crypto.randomBytes(4).toString('hex');
}

function makeScriptedContext({ stepFn = null } = {}) {
  const ctx = {
    steps: 0,
    totalInsns: 0,
    disposed: false,
    step(budget) {
      ctx.steps += 1;
      if (typeof stepFn === 'function') {
        const res = stepFn(ctx, budget);
        ctx.totalInsns += Number(res?.instructionsExecuted) || 0;
        return res;
      }
      const insns = Math.max(1, Number(budget) || 1);
      ctx.totalInsns += insns;
      return { status: 'YIELD', instructionsExecuted: insns };
    },
    deliverEvent() {},
    getDebugState() {
      return { arch: 'wasm', pc: ctx.steps, sp: 0, registers: {}, instructionsExecuted: ctx.totalInsns, lastSyscall: null, stackTop: 0 };
    },
    dispose() {
      ctx.disposed = true;
    },
  };
  return ctx;
}

function getAddressSpace(pcb) {
  const as = pcb?.addressSpace ?? pcb?.addrSpace ?? pcb?.memory ?? pcb?.vmm;
  assert.ok(as && typeof as === 'object', 'PCB must expose an IAddressSpace instance');
  for (const method of ['mmap', 'reserveGuard', 'munmap', 'mprotect', 'read', 'write', 'fetch', 'alloc', 'free', 'realloc', 'getStats']) {
    assert.equal(typeof as[method], 'function', `IAddressSpace missing required Contract 1 method "${method}"`);
  }
  return as;
}

function assertSegfault(fn, label) {
  let caught = null;
  try {
    fn();
  } catch (err) {
    caught = err;
  }
  assert.ok(caught instanceof Error, `${label}: MUST throw MemoryFaultError(SIGSEGV)`);
  assert.ok(
    !(caught instanceof TypeError) && !(caught instanceof ReferenceError),
    `${label}: threw JS ${caught.name} instead of structured MemoryFaultError: ${caught.message}`
  );
  const hasFaultMeta =
    caught.name === 'MemoryFaultError' ||
    typeof caught.signal === 'string' ||
    typeof caught.code === 'string';
  assert.ok(hasFaultMeta, `${label}: fault error must carry MemoryFaultError name, signal, or code (got ${caught.name}: ${caught.message})`);
  const matchesSegv =
    caught.signal === 'SIGSEGV' ||
    /SIGSEGV|SEGV|FAULT|PROT|UNMAPPED|GUARD|PAGEZERO/i.test(`${caught.code ?? ''} ${caught.name} ${caught.message}`);
  assert.ok(matchesSegv, `${label}: expected SIGSEGV/MemoryFaultError (got name=${caught.name}, code=${caught.code}, signal=${caught.signal}, msg=${caught.message})`);
}

function assertEnomem(fn, label) {
  let caught = null;
  try {
    fn();
  } catch (err) {
    caught = err;
  }
  assert.ok(caught instanceof Error, `${label}: MUST throw ENOMEM error`);
  assert.ok(
    !(caught instanceof TypeError) && !(caught instanceof ReferenceError),
    `${label}: threw JS ${caught.name} instead of ENOMEM: ${caught.message}`
  );
  const matchesEnomem =
    caught.code === 'ENOMEM' ||
    /ENOMEM|OUT_OF_MEMORY|MEMORY_QUOTA|OOM/i.test(String(caught.code ?? '')) ||
    (caught.name === 'MemoryFaultError' && /ENOMEM|quota|memory|oom/i.test(caught.message));
  assert.ok(matchesEnomem, `${label}: expected ENOMEM error (got name=${caught.name}, code=${caught.code}, msg=${caught.message})`);
}

test.describe('Tier 2 — FA-03: Virtual Memory R/W/X Protection, Heap & Sandbox Quotas (Boundary & Negative)', () => {
  test('T1 [F-013, F-012]: Hardware-style R/W/X MemoryFaultError(SIGSEGV) matrix (unmapped, PROT_NONE, RO/RX write, RW/NX fetch, WO read/fetch, post-munmap)', async () => {
    const nonce = makeNonce();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const kernel = os.require('kernel');
      const pm = os.require('processManager');
      os.require('scheduler').stop();

      const pcb = pm.spawn({
        name: `vmm-rwx-${nonce}`,
        appId: `com.vmm.rwx.${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        executionContext: makeScriptedContext(),
      });

      try {
        const as = getAddressSpace(pcb);

        // 1. Unmapped VA 0x00500000 -> R, W, X all SIGSEGV
        assertSegfault(() => as.read(0x00500000, 4), 'read unmapped VA');
        assertSegfault(() => as.write(0x00500000, Uint8Array.from([1, 2, 3, 4])), 'write unmapped VA');
        assertSegfault(() => as.fetch(0x00500000, 4), 'fetch unmapped VA');

        // 2. PROT_NONE at 0x00600000 (prove RW works BEFORE mprotect PROT_NONE!)
        const pNone = as.mmap(0x00600000, 4096, PROT_READ | PROT_WRITE, 't-none');
        const sentinel = crypto.randomBytes(16);
        as.write(pNone, sentinel);
        assert.equal(Buffer.compare(Buffer.from(as.read(pNone, 16)), sentinel), 0, 'Pre-condition: RW page must read back sentinel');

        as.mprotect(pNone, 4096, PROT_NONE);
        assertSegfault(() => as.read(pNone, 16), 'read PROT_NONE');
        assertSegfault(() => as.write(pNone, Uint8Array.from([0xee])), 'write PROT_NONE');
        assertSegfault(() => as.fetch(pNone, 4), 'fetch PROT_NONE');

        as.mprotect(pNone, 4096, PROT_READ);
        assert.equal(Buffer.compare(Buffer.from(as.read(pNone, 16)), sentinel), 0, 'PROT_NONE must preserve underlying page bytes');

        // 3. RO+X (PROT_READ | PROT_EXEC) at 0x00700000
        const pRx = as.mmap(0x00700000, 4096, PROT_READ | PROT_WRITE, 't-rx');
        const origCode = crypto.randomBytes(16);
        as.write(pRx, origCode);
        as.mprotect(pRx, 4096, PROT_READ | PROT_EXEC);

        assert.equal(Buffer.compare(Buffer.from(as.read(pRx, 16)), origCode), 0, 'RX page must allow read');
        assert.equal(Buffer.compare(Buffer.from(as.fetch(pRx, 16)), origCode), 0, 'RX page must allow fetch');
        assertSegfault(() => as.write(pRx, Uint8Array.from([0xff, 0xff, 0xff, 0xff])), 'write RX page');
        assert.equal(Buffer.compare(Buffer.from(as.read(pRx, 16)), origCode), 0, 'Rejected write to RX page must not corrupt bytes');

        // 4. Pure RO (PROT_READ)
        as.mprotect(pRx, 4096, PROT_READ);
        assert.equal(Buffer.compare(Buffer.from(as.read(pRx, 16)), origCode), 0, 'RO page must allow read');
        assertSegfault(() => as.write(pRx, Uint8Array.from([0xaa])), 'write RO page');
        assertSegfault(() => as.fetch(pRx, 4), 'fetch RO page');

        // 5. NX (PROT_READ | PROT_WRITE) at 0x00800000
        const pNx = as.mmap(0x00800000, 4096, PROT_READ | PROT_WRITE, 't-nx');
        const rwBytes = Uint8Array.from([0x90, 0x90, 0xc3, 0x00]);
        as.write(pNx, rwBytes);
        assert.equal(Buffer.compare(Buffer.from(as.read(pNx, 4)), Buffer.from(rwBytes)), 0);
        assertSegfault(() => as.fetch(pNx, 4), 'fetch NX (RW) page');

        // 6. Write-only (PROT_WRITE) at 0x00900000
        const pWo = as.mmap(0x00900000, 4096, PROT_WRITE, 't-wo');
        as.write(pWo, Uint8Array.from([1, 2, 3, 4]));
        assertSegfault(() => as.read(pWo, 4), 'read write-only page');
        assertSegfault(() => as.fetch(pWo, 4), 'fetch write-only page');

        // 7. Post-munmap access -> R, W, X all SIGSEGV
        as.munmap(pNx, 4096);
        assertSegfault(() => as.read(pNx, 4), 'read after munmap');
        assertSegfault(() => as.write(pNx, Uint8Array.from([1])), 'write after munmap');
        assertSegfault(() => as.fetch(pNx, 4), 'fetch after munmap');

        assert.equal(kernel.getDiagnostics()?.state, 'RUNNING');
      } finally {
        try { pm.kill(pcb.pid, 'SIGKILL'); } catch { /* ignore */ }
      }
    } finally {
      await os?.shutdown();
    }
  });

  test('T2 [F-012, F-013, Edge Case #21]: 4 GiB __PAGEZERO virtual guard (0, 0x100, 0xFFFFFFFF & upper-edge straddle faults with zero RAM alloc)', async () => {
    const nonce = makeNonce();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const pm = os.require('processManager');
      os.require('scheduler').stop();

      const pcb = pm.spawn({
        name: `vmm-pz-${nonce}`,
        appId: `com.vmm.pz.${nonce}`,
        platform: 'macos',
        arch: 'arm64',
        quotas: { maxMemoryBytes: 2 * 1024 * 1024, maxBytes: 2 * 1024 * 1024 },
        executionContext: makeScriptedContext(),
      });

      try {
        const as = getAddressSpace(pcb);
        const before = as.getStats();
        const rssBefore = process.memoryUsage().rss;

        as.reserveGuard(0, 0x100000000, '__PAGEZERO');

        const after = as.getStats();
        const rssDelta = process.memoryUsage().rss - rssBefore;
        assert.equal(after.mappedPages, before.mappedPages, '__PAGEZERO must NOT allocate physical/mapped pages');
        assert.equal(after.usedBytes, before.usedBytes, '__PAGEZERO must NOT charge usedBytes against RAM quota');
        assert.ok(
          Array.isArray(after.regions) && after.regions.some((r) => r?.label === '__PAGEZERO'),
          `getStats().regions must list __PAGEZERO guard (got ${JSON.stringify(after.regions)})`
        );
        assert.ok(rssDelta < 64 * 1024 * 1024, `__PAGEZERO must not allocate host RAM (rssDelta=${rssDelta})`);

        // Exact lower, offset, and upper-inclusive guard boundaries
        for (const addr of [0x0, 0x100, 0xffffffff]) {
          const len = addr === 0xffffffff ? 1 : 4;
          assertSegfault(() => as.read(addr, len), `read __PAGEZERO @ 0x${addr.toString(16)}`);
          assertSegfault(() => as.write(addr, new Uint8Array(len)), `write __PAGEZERO @ 0x${addr.toString(16)}`);
          assertSegfault(() => as.fetch(addr, len), `fetch __PAGEZERO @ 0x${addr.toString(16)}`);
        }

        // Map valid page right above 4 GiB boundary at 0x100000000
        const aboveAddr = as.mmap(0x100000000, 4096, PROT_READ | PROT_WRITE, 'above-pz');
        assert.equal(aboveAddr, 0x100000000, 'Mapping at exact 0x100000000 right above __PAGEZERO must succeed');
        const sentinel = Uint8Array.from([0xde, 0xad, 0xbe, 0xef]);
        as.write(0x100000000, sentinel);
        assert.equal(Buffer.compare(Buffer.from(as.read(0x100000000, 4)), Buffer.from(sentinel)), 0);

        // Straddling upper __PAGEZERO boundary (0xFFFFFFFE..0x100000001) MUST SIGSEGV without corrupting 0x100000000
        assertSegfault(() => as.read(0xfffffffe, 4), 'read straddling __PAGEZERO upper edge');
        assertSegfault(() => as.write(0xfffffffe, Uint8Array.from([1, 2, 3, 4])), 'write straddling __PAGEZERO upper edge');
        assert.equal(
          Buffer.compare(Buffer.from(as.read(0x100000000, 4)), Buffer.from(sentinel)),
          0,
          'Straddling write into __PAGEZERO must not corrupt valid page at 0x100000000'
        );

        // Guard overlap defense: mmap inside __PAGEZERO must throw Error OR relocate >= 0x100000000
        let overlapAddr = null;
        let overlapErr = null;
        try {
          overlapAddr = as.mmap(0x1000, 4096, PROT_READ | PROT_WRITE, 'pz-overlap');
        } catch (err) {
          overlapErr = err;
        }
        if (overlapErr) {
          assert.ok(overlapErr instanceof Error && overlapErr.message.length > 0);
        } else {
          assert.ok(
            overlapAddr >= 0x100000000,
            `mmap(0x1000) overlapping __PAGEZERO must reject or relocate >= 0x100000000 (got 0x${overlapAddr.toString(16)})`
          );
        }
        assertSegfault(() => as.read(0x1000, 4), '0x1000 inside __PAGEZERO must remain inaccessible');
      } finally {
        try { pm.kill(pcb.pid, 'SIGKILL'); } catch { /* ignore */ }
      }
    } finally {
      await os?.shutdown();
    }
  });

  test('T3 [F-012, F-013]: Page-boundary straddling R/W/X (0x0FFE mapped->unmapped, RW->RO, RX->NX)', async () => {
    const nonce = makeNonce();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const pm = os.require('processManager');
      os.require('scheduler').stop();

      const pcb = pm.spawn({
        name: `vmm-straddle-${nonce}`,
        appId: `com.vmm.straddle.${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        executionContext: makeScriptedContext(),
      });

      try {
        const as = getAddressSpace(pcb);

        // 1. Mapped RW page -> Unmapped next page
        const base1 = as.mmap(0x00a00000, 4096, PROT_READ | PROT_WRITE, 'straddle-unmapped');
        as.write(base1 + 0x0ffe, Uint8Array.from([0xaa, 0xbb]));
        assert.deepEqual(Array.from(as.read(base1 + 0x0ffe, 2)), [0xaa, 0xbb], 'Exact end-of-page 2B access must succeed');

        assertSegfault(() => as.read(base1 + 0x0ffe, 4), 'read straddling mapped->unmapped (+2B)');
        assertSegfault(() => as.write(base1 + 0x0ffe, Uint8Array.from([1, 2, 3, 4])), 'write straddling mapped->unmapped (+2B)');
        assertSegfault(() => as.read(base1 + 0x0fff, 2), 'read straddling mapped->unmapped (+1B)');
        assertSegfault(() => as.write(base1 + 0x0fff, Uint8Array.from([5, 6])), 'write straddling mapped->unmapped (+1B)');
        assertSegfault(() => as.read(base1 + 0x1000, 1), 'Adjacent page after straddle must remain unmapped');

        // 2. RW page 0 -> RO page 1
        const base2 = as.mmap(0x00b00000, 8192, PROT_READ | PROT_WRITE, 'straddle-rw-ro');
        as.write(base2 + 0x0ffe, Uint8Array.from([0xde, 0xad, 0xbe, 0xef]));
        as.mprotect(base2 + 0x1000, 4096, PROT_READ);

        assert.deepEqual(Array.from(as.read(base2 + 0x0ffe, 4)), [0xde, 0xad, 0xbe, 0xef], 'Read across RW->RO boundary must succeed');
        assertSegfault(() => as.write(base2 + 0x0ffe, Uint8Array.from([1, 2, 3, 4])), 'write straddling RW->RO boundary');
        assert.deepEqual(
          Array.from(as.read(base2 + 0x1000, 2)),
          [0xbe, 0xef],
          'RO page bytes MUST NOT be mutated by straddling write from RW page'
        );

        // 3. RX page 0 -> NX (RW) page 1
        as.mprotect(base2, 4096, PROT_READ | PROT_EXEC);
        as.mprotect(base2 + 0x1000, 4096, PROT_READ | PROT_WRITE);
        assert.equal(as.fetch(base2 + 0x0ffe, 2).length, 2, 'Fetch strictly within RX page must succeed');
        assertSegfault(() => as.fetch(base2 + 0x0ffe, 4), 'fetch straddling RX->NX boundary');
      } finally {
        try { pm.kill(pcb.pid, 'SIGKILL'); } catch { /* ignore */ }
      }
    } finally {
      await os?.shutdown();
    }
  });

  test('T4 [F-011, F-014]: Memory quota exhaustion (alloc/realloc/mmap exceeding maxBytes -> ENOMEM), reclamation & sibling isolation', async () => {
    const nonce = makeNonce();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const pm = os.require('processManager');
      os.require('scheduler').stop();

      const pcb = pm.spawn({
        name: `vmm-quota-${nonce}`,
        appId: `com.vmm.quota.${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        quotas: { maxMemoryBytes: 64 * 1024, maxBytes: 64 * 1024 },
        executionContext: makeScriptedContext(),
      });
      const sibPcb = pm.spawn({
        name: `vmm-sib-${nonce}`,
        appId: `com.vmm.sib.${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        quotas: { maxMemoryBytes: 256 * 1024, maxBytes: 256 * 1024 },
        executionContext: makeScriptedContext(),
      });

      try {
        const as = getAddressSpace(pcb);
        const sibAs = getAddressSpace(sibPcb);

        const initStats = as.getStats();
        assert.ok(
          initStats.maxBytes > 0 && initStats.maxBytes <= 64 * 1024,
          `maxBytes must honor 64 KiB quota (got ${initStats.maxBytes})`
        );
        const maxBytes = initStats.maxBytes;

        // Baseline allocation + sentinel write
        const p1 = as.alloc(8192);
        assert.ok(p1 > 0, 'Initial 8 KiB alloc must return non-zero pointer');
        const d1 = crypto.randomBytes(8192);
        as.write(p1, d1);
        const s1 = as.getStats();
        assert.ok(s1.usedBytes > 0 && s1.peakBytes >= s1.usedBytes, 'VMM stats must track usedBytes and peakBytes');

        // Single oversized alloc -> ENOMEM
        assertEnomem(() => as.alloc(maxBytes + 4096), 'single oversized alloc');

        // Cumulative 8 KiB allocations MUST hit ENOMEM within bounded iterations
        const held = [];
        let hitOom = false;
        let oomErr = null;
        let oomIter = -1;
        const maxIters = Math.ceil(maxBytes / 8192) + 4;
        for (let i = 0; i < maxIters; i++) {
          try {
            held.push(as.alloc(8192));
          } catch (err) {
            oomErr = err;
            oomIter = i;
            hitOom = true;
            break;
          }
        }
        if (oomErr) {
          assertEnomem(() => { throw oomErr; }, `cumulative alloc #${oomIter}`);
        }
        assert.equal(hitOom, true, `Cumulative 8 KiB allocs must hit ENOMEM within ${maxIters} iterations`);
        assert.ok(as.getStats().usedBytes <= maxBytes, `usedBytes (${as.getStats().usedBytes}) must stay <= maxBytes (${maxBytes})`);
        assert.equal(Buffer.compare(Buffer.from(as.read(p1, 8192)), d1), 0, 'Existing p1 data must stay intact after ENOMEM');

        // Free loop-allocated blocks -> quota reclamation allows fresh allocation
        for (const ptr of held) {
          as.free(ptr);
        }
        const reclaimed = as.alloc(8192);
        assert.ok(reclaimed > 0, 'Freeing blocks must reclaim heap space for subsequent alloc');
        as.free(reclaimed);

        // Oversized realloc -> ENOMEM and preserves p1 bytes
        assertEnomem(() => as.realloc(p1, maxBytes + 4096), 'oversized realloc');
        assert.equal(Buffer.compare(Buffer.from(as.read(p1, 8192)), d1), 0, 'Failed realloc must preserve original p1 data');

        // Oversized mmap -> ENOMEM / quota error
        assertEnomem(() => as.mmap(0x00c00000, maxBytes + 16384, PROT_READ | PROT_WRITE, 'oom-map'), 'oversized mmap');

        // Sibling process isolation: unaffected by pcb quota exhaustion
        const sibPtr = sibAs.alloc(8192);
        assert.ok(sibPtr > 0, 'Sibling process must allocate cleanly while peer hits quota');
        sibAs.free(sibPtr);
        as.free(p1);
      } finally {
        try { pm.kill(pcb.pid, 'SIGKILL'); } catch { /* ignore */ }
        try { pm.kill(sibPcb.pid, 'SIGKILL'); } catch { /* ignore */ }
      }
    } finally {
      await os?.shutdown();
    }
  });

  test('T5 [F-014, F-035]: Heap allocator negative boundaries — double-free, invalid/interior/negative free(), negative/NaN alloc() & invalid realloc()', async () => {
    const nonce = makeNonce();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const kernel = os.require('kernel');
      const pm = os.require('processManager');
      os.require('scheduler').stop();

      const pcb = pm.spawn({
        name: `vmm-heap-neg-${nonce}`,
        appId: `com.vmm.heapneg.${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        executionContext: makeScriptedContext(),
      });

      try {
        const as = getAddressSpace(pcb);

        // Double-free MUST throw structured Error
        const p = as.alloc(256);
        assert.ok(p > 0);
        as.free(p);
        assert.throws(() => as.free(p), (err) => err instanceof Error && err.message.length > 0, 'Double-free must throw structured Error');

        // Invalid / negative pointers MUST throw structured Error
        assert.throws(() => as.free(0xdeadbeef), (err) => err instanceof Error && err.message.length > 0, 'free(0xDEADBEEF) must throw');
        assert.throws(() => as.free(-1), (err) => err instanceof Error && err.message.length > 0, 'free(-1) must throw');

        // Interior pointer free MUST throw and leave live allocation intact
        const live = as.alloc(256);
        const sentinel = crypto.randomBytes(256);
        as.write(live, sentinel);
        assert.throws(() => as.free(live + 16), (err) => err instanceof Error && err.message.length > 0, 'free(interior ptr) must throw');
        assert.equal(Buffer.compare(Buffer.from(as.read(live, 256)), sentinel), 0, 'Rejected interior free must not corrupt live allocation');
        as.free(live);

        // Negative & NaN alloc sizes MUST throw
        assert.throws(() => as.alloc(-64), (err) => err instanceof Error && err.message.length > 0, 'alloc(-64) must throw');
        assert.throws(() => as.alloc(Number.NaN), (err) => err instanceof Error && err.message.length > 0, 'alloc(NaN) must throw');

        // alloc(0): may throw Error or return 0 / valid freeable ptr without corrupting heap
        let zeroPtr = null;
        let zeroErr = null;
        try {
          zeroPtr = as.alloc(0);
        } catch (err) {
          zeroErr = err;
        }
        if (zeroErr) {
          assert.ok(zeroErr instanceof Error && zeroErr.message.length > 0);
        }
        if (typeof zeroPtr === 'number' && zeroPtr > 0) {
          as.free(zeroPtr);
        }

        // Invalid realloc pointer MUST throw
        assert.throws(() => as.realloc(0xdeadbeef, 128), (err) => err instanceof Error && err.message.length > 0, 'realloc(0xDEADBEEF) must throw');

        // Post-error heap health check
        const okPtr = as.alloc(128);
        const okBytes = crypto.randomBytes(128);
        as.write(okPtr, okBytes);
        assert.equal(Buffer.compare(Buffer.from(as.read(okPtr, 128)), okBytes), 0);
        as.free(okPtr);
        assert.equal(kernel.getDiagnostics()?.state, 'RUNNING');
      } finally {
        try { pm.kill(pcb.pid, 'SIGKILL'); } catch { /* ignore */ }
      }
    } finally {
      await os?.shutdown();
    }
  });

  test('T6 [F-011, F-009, F-035]: Runaway process exceeding maxTotalInstructions (SIGXCPU/E_CPU_QUOTA) kills ONLY offending PID while sibling stays healthy', async () => {
    const nonce = makeNonce();
    let os = null;
    try {
      os = await loadPublicOmniOS();
      const kernel = os.require('kernel');
      const pm = os.require('processManager');
      const sched = os.require('scheduler');
      sched.stop();

      const sibCtx = makeScriptedContext();
      const sibPcb = pm.spawn({
        name: `quota-sib-${nonce}`,
        appId: `com.quota.sib.${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        quotas: { maxTotalInstructions: 1_000_000 },
        executionContext: sibCtx,
      });
      const sibAs = getAddressSpace(sibPcb);
      const sibPage = sibAs.mmap(0x00d00000, 4096, PROT_READ | PROT_WRITE, 'sib-data');
      const sibData = crypto.randomBytes(64);
      sibAs.write(sibPage, sibData);

      const runawayCtx = makeScriptedContext({
        stepFn: (_ctx, budget) => ({ status: 'YIELD', instructionsExecuted: Math.max(1, Number(budget) || 1) }),
      });
      const runawayPcb = pm.spawn({
        name: `quota-runaway-${nonce}`,
        appId: `com.quota.runaway.${nonce}`,
        platform: 'universal',
        arch: 'wasm',
        quotas: { maxInstructionsPerTick: 25, maxTotalInstructions: 100 },
        executionContext: runawayCtx,
      });

      try {
        const isTerminated = (pid) => {
          const p = pm.get(pid);
          return !p || ['ZOMBIE', 'TERMINATED'].includes(String(p.state ?? '').toUpperCase());
        };

        let killedAtTick = -1;
        for (let tick = 1; tick <= 500; tick++) {
          sched.step(1);
          if (isTerminated(runawayPcb.pid)) {
            killedAtTick = tick;
            break;
          }
        }

        assert.ok(killedAtTick > 0, 'Runaway process exceeding maxTotalInstructions=100 MUST be terminated before 500 ticks');
        assert.equal(runawayCtx.disposed, true, 'Terminated runaway executionContext must be disposed');
        assert.ok(
          runawayCtx.totalInsns <= 250,
          `Runaway process must terminate near 100-instruction quota (executed ${runawayCtx.totalInsns})`
        );

        const deadRecord = pm.get(runawayPcb.pid);
        if (deadRecord) {
          const meta = JSON.stringify({
            signal: deadRecord.signal ?? deadRecord.terminationSignal ?? deadRecord.fault?.signal,
            code: deadRecord.fault?.code ?? deadRecord.errorCode,
            exitCode: deadRecord.exitCode,
            reason: deadRecord.exitReason ?? deadRecord.fault?.message,
          });
          assert.ok(
            /SIGXCPU|CPU_QUOTA|QUOTA|XCPU/i.test(meta) || (typeof deadRecord.exitCode === 'number' && deadRecord.exitCode !== 0),
            `Runaway termination metadata must reflect CPU quota fault or non-zero exit (got ${meta})`
          );
        }

        // Healthy sibling MUST remain alive, continue stepping, and retain intact VMM memory
        assert.equal(isTerminated(sibPcb.pid), false, 'Healthy sibling must NOT be affected by runaway PID kill');
        assert.equal(sibCtx.disposed, false, 'Healthy sibling context must not be disposed');

        const sibStepsBefore = sibCtx.steps;
        const runawayStepsAfterKill = runawayCtx.steps;
        const probeTicks = Math.max(8, pm.list().length + 4);
        for (let i = 0; i < probeTicks && sibCtx.steps === sibStepsBefore; i++) {
          sched.step(1);
        }
        assert.ok(sibCtx.steps > sibStepsBefore, 'Healthy sibling must continue executing after runaway kill');
        assert.equal(runawayCtx.steps, runawayStepsAfterKill, 'Killed runaway process must not execute further steps');
        assert.equal(Buffer.compare(Buffer.from(sibAs.read(sibPage, 64)), sibData), 0, 'Sibling VMM page must remain intact');
        assert.equal(kernel.getDiagnostics()?.state, 'RUNNING');
      } finally {
        try { pm.kill(sibPcb.pid, 'SIGKILL'); } catch { /* ignore */ }
        try { pm.kill(runawayPcb.pid, 'SIGKILL'); } catch { /* ignore */ }
      }
    } finally {
      await os?.shutdown();
    }
  });
});
