/**
 * OmniOS Per-PID Sparse 4KB Virtual Memory Manager (`AddressSpace`)
 * Features:
 *  - Safe 53-bit & BigInt virtual addressing (supports Mach-O 0x100000000, PE32+ 0x140000000, 0x7FFF00000000)
 *  - Zero 32-bit bitwise truncation on addresses or sizes
 *  - Non-allocating virtual guard regions (e.g. 4 GiB __PAGEZERO with 0 allocated pages)
 *  - Hardware-style atomic R/W/X page protection enforcement (PROT_NONE/READ/WRITE/EXEC)
 *  - Guard-aware 16-byte aligned coalescing free-list heap allocator (alloc/realloc/free)
 */

import { MemoryFaultError, ERROR_CODES } from '../common/errors.mjs';

export const PAGE_SIZE = 0x1000; // 4096 bytes
export const PROT_NONE = 0;
export const PROT_READ = 1;
export const PROT_WRITE = 2;
export const PROT_EXEC = 4;
export const PROT_ALL = PROT_READ | PROT_WRITE | PROT_EXEC; // 7

export const HEAP_ALIGNMENT = 16;
export const DEFAULT_MAX_MEMORY_BYTES = 64 * 1024 * 1024; // 64 MiB
export const DEFAULT_HEAP_BASE = 0x10000000; // 256 MiB
export const DEFAULT_MMAP_BASE = 0x20000000; // 512 MiB
export const HIGH_VA_HEAP_BASE = 0x200000000; // 8 GiB (above 4GiB __PAGEZERO & Mach-O/PE32+ images)
export const HIGH_VA_MMAP_BASE = 0x300000000; // 12 GiB
export const MAX_VA = Number.MAX_SAFE_INTEGER; // 0x1FFFFFFFFFFFFF

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder('utf-8');

export function alignUp(value, alignment = PAGE_SIZE) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new MemoryFaultError(`Invalid value for alignUp: ${value}`, {
      code: ERROR_CODES.EINVAL,
      faultType: 'INVALID_ADDRESS',
      address: value,
    });
  }
  if (typeof alignment !== 'number' || !Number.isSafeInteger(alignment) || alignment <= 0) {
    throw new MemoryFaultError(`Invalid alignment: ${alignment}`, {
      code: ERROR_CODES.EINVAL,
      faultType: 'INVALID_SIZE',
    });
  }
  if (value === 0) return 0;
  const rem = value % alignment;
  const aligned = rem === 0 ? value : value + (alignment - rem);
  if (!Number.isSafeInteger(aligned)) {
    throw new MemoryFaultError('Address/size alignment overflow', {
      code: ERROR_CODES.EINVAL,
      faultType: 'INVALID_ADDRESS',
      address: value,
    });
  }
  return aligned;
}

export function alignDown(value, alignment = PAGE_SIZE) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new MemoryFaultError(`Invalid value for alignDown: ${value}`, {
      code: ERROR_CODES.EINVAL,
      faultType: 'INVALID_ADDRESS',
      address: value,
    });
  }
  if (typeof alignment !== 'number' || !Number.isSafeInteger(alignment) || alignment <= 0) {
    throw new MemoryFaultError(`Invalid alignment: ${alignment}`, {
      code: ERROR_CODES.EINVAL,
      faultType: 'INVALID_SIZE',
    });
  }
  return value - (value % alignment);
}

export function formatPerms(perms) {
  const r = (perms & PROT_READ) !== 0 ? 'r' : '-';
  const w = (perms & PROT_WRITE) !== 0 ? 'w' : '-';
  const x = (perms & PROT_EXEC) !== 0 ? 'x' : '-';
  return `${r}${w}${x}`;
}

function intervalsOverlap(aStart, aEnd, bStart, bEnd) {
  return aStart < bEnd && bStart < aEnd;
}

function rangeFitsVA(base, len) {
  if (typeof base !== 'number' || !Number.isSafeInteger(base) || base < 0) return false;
  if (typeof len !== 'number' || !Number.isSafeInteger(len) || len < 0) return false;
  if (len === 0) return base <= MAX_VA;
  return base <= MAX_VA && len - 1 <= MAX_VA - base;
}

function toBytesView(input, pid) {
  if (input instanceof Uint8Array) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  if (input instanceof ArrayBuffer) {
    return new Uint8Array(input);
  }
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  throw new MemoryFaultError('Expected Uint8Array, ArrayBuffer, or ArrayBufferView', {
    code: ERROR_CODES.EINVAL,
    signal: 'SIGSEGV',
    faultType: 'INVALID_ARGUMENT',
    pid,
  });
}

export class AddressSpace {
  constructor({
    pid = 0,
    maxMemoryBytes = undefined,
    maxBytes = undefined,
    mmapBase = DEFAULT_MMAP_BASE,
    heapBase = null,
  } = {}) {
    const limit = maxMemoryBytes !== undefined ? maxMemoryBytes : (maxBytes !== undefined ? maxBytes : DEFAULT_MAX_MEMORY_BYTES);
    if (typeof limit !== 'number' || !Number.isSafeInteger(limit) || limit < 0) {
      throw new MemoryFaultError(`Invalid maxMemoryBytes: ${limit}`, {
        code: ERROR_CODES.EINVAL,
        faultType: 'INVALID_SIZE',
        pid,
      });
    }
    this.pid = pid;
    this.maxMemoryBytes = limit;
    this._pages = new Map();
    this._regions = [];
    this._guardRegions = [];
    this._mmapCursor = mmapBase;
    this._requestedHeapBase = heapBase;
    this._heapInitialized = false;
    this._heapBase = null;
    this._heapEnd = 0;
    this._heapBlocks = [];
    this._freedPtrs = new Set();
    this._peakBytes = 0;
    this._destroyed = false;
  }

  _assertAlive() {
    if (this._destroyed) {
      throw new MemoryFaultError('AddressSpace has been destroyed', {
        code: ERROR_CODES.EFAULT,
        signal: 'SIGSEGV',
        faultType: 'ADDRESS_SPACE_DESTROYED',
        pid: this.pid,
      });
    }
  }

  _normalizeAddr(raw, { faultOnError = true } = {}) {
    if (typeof raw === 'bigint') {
      if (raw < 0n || raw > BigInt(MAX_VA)) {
        throw new MemoryFaultError(`Invalid 64-bit virtual address: 0x${raw.toString(16)}`, {
          code: faultOnError ? ERROR_CODES.EFAULT : ERROR_CODES.EINVAL,
          signal: 'SIGSEGV',
          faultType: 'INVALID_ADDRESS',
          address: raw,
          pid: this.pid,
        });
      }
      return Number(raw);
    }
    if (typeof raw !== 'number' || !Number.isSafeInteger(raw) || raw < 0) {
      throw new MemoryFaultError(`Invalid virtual address: ${raw}`, {
        code: faultOnError ? ERROR_CODES.EFAULT : ERROR_CODES.EINVAL,
        signal: 'SIGSEGV',
        faultType: 'INVALID_ADDRESS',
        address: raw,
        pid: this.pid,
      });
    }
    return raw;
  }

  _normalizePositiveSize(rawSize) {
    let val = rawSize;
    if (typeof rawSize === 'bigint') {
      if (rawSize <= 0n || rawSize > BigInt(MAX_VA)) {
        throw new MemoryFaultError(`Invalid size: ${rawSize}`, {
          code: ERROR_CODES.EINVAL,
          faultType: 'INVALID_SIZE',
          pid: this.pid,
        });
      }
      val = Number(rawSize);
    }
    if (typeof val !== 'number' || !Number.isSafeInteger(val) || val <= 0) {
      throw new MemoryFaultError(`Size must be a positive safe integer: ${rawSize}`, {
        code: ERROR_CODES.EINVAL,
        faultType: 'INVALID_SIZE',
        pid: this.pid,
      });
    }
    return val;
  }

  _normalizeNonNegativeSize(rawSize) {
    let val = rawSize;
    if (typeof rawSize === 'bigint') {
      if (rawSize < 0n || rawSize > BigInt(MAX_VA)) {
        throw new MemoryFaultError(`Invalid size: ${rawSize}`, {
          code: ERROR_CODES.EINVAL,
          faultType: 'INVALID_SIZE',
          pid: this.pid,
        });
      }
      val = Number(rawSize);
    }
    if (typeof val !== 'number' || !Number.isSafeInteger(val) || val < 0) {
      throw new MemoryFaultError(`Size must be a non-negative safe integer: ${rawSize}`, {
        code: ERROR_CODES.EINVAL,
        faultType: 'INVALID_SIZE',
        pid: this.pid,
      });
    }
    return val;
  }

  _validatePerms(perms) {
    if (typeof perms !== 'number' || !Number.isInteger(perms) || perms < 0 || perms > PROT_ALL) {
      throw new MemoryFaultError(`Invalid page permissions: ${perms}`, {
        code: ERROR_CODES.EINVAL,
        faultType: 'INVALID_PERMISSIONS',
        pid: this.pid,
      });
    }
  }

  _findGuardContaining(addr) {
    for (let i = 0; i < this._guardRegions.length; i++) {
      const g = this._guardRegions[i];
      if (addr >= g.base && addr < g.end) return g;
      if (g.base > addr) break;
    }
    return null;
  }

  _findGuardOverlapping(start, end) {
    for (let i = 0; i < this._guardRegions.length; i++) {
      const g = this._guardRegions[i];
      if (intervalsOverlap(start, end, g.base, g.end)) return g;
      if (g.base >= end) break;
    }
    return null;
  }

  _findRegionOverlapping(start, end) {
    for (let i = 0; i < this._regions.length; i++) {
      const r = this._regions[i];
      if (intervalsOverlap(start, end, r.base, r.end)) return r;
      if (r.base >= end) break;
    }
    return null;
  }

  _getOccupiedIntervals({ includeHeapHeadroom = false } = {}) {
    const intervals = [];
    for (const g of this._guardRegions) {
      intervals.push({ base: g.base, end: g.end });
    }
    for (const r of this._regions) {
      intervals.push({ base: r.base, end: r.end });
    }
    if (includeHeapHeadroom && this._heapInitialized && this._heapBase !== null) {
      const headroom = Math.max(
        this._heapEnd - this._heapBase,
        Math.min(Math.max(this.maxMemoryBytes, 0x1000000), 0x10000000)
      );
      const reserveEnd = rangeFitsVA(this._heapBase, headroom)
        ? this._heapBase + headroom
        : MAX_VA + 1;
      intervals.push({ base: this._heapBase, end: reserveEnd });
    }
    intervals.sort((a, b) => a.base - b.base);
    return intervals;
  }

  _findFreeRange(startCandidate, alignedSize, { includeHeapHeadroom = false } = {}) {
    if (!rangeFitsVA(PAGE_SIZE, alignedSize)) return null;
    const occupied = this._getOccupiedIntervals({ includeHeapHeadroom });
    const clampedStart =
      typeof startCandidate === 'number' && Number.isSafeInteger(startCandidate) && startCandidate >= PAGE_SIZE
        ? startCandidate
        : PAGE_SIZE;
    const maxAlignedPageBase = MAX_VA - (PAGE_SIZE - 1);
    const candidate = clampedStart > maxAlignedPageBase ? PAGE_SIZE : alignUp(clampedStart, PAGE_SIZE);

    const scanFrom = (initCandidate) => {
      let cur = initCandidate;
      if (!rangeFitsVA(cur, alignedSize)) return null;
      for (let i = 0; i < occupied.length; i++) {
        const iv = occupied[i];
        if (iv.end <= cur) continue;
        if (cur + alignedSize <= iv.base) break;
        // Overlaps [iv.base, iv.end): jump past iv.end
        if (iv.end > maxAlignedPageBase) {
          return null;
        }
        cur = alignUp(iv.end, PAGE_SIZE);
        if (!rangeFitsVA(cur, alignedSize)) {
          return null;
        }
      }
      if (!rangeFitsVA(cur, alignedSize)) {
        return null;
      }
      return cur;
    };

    const first = scanFrom(candidate);
    if (first !== null) return first;
    if (candidate === PAGE_SIZE) return null;
    return scanFrom(PAGE_SIZE);
  }

  _insertRegionSorted(region) {
    let idx = this._regions.length;
    for (let i = 0; i < this._regions.length; i++) {
      if (this._regions[i].base > region.base) {
        idx = i;
        break;
      }
    }
    this._regions.splice(idx, 0, region);
    this._coalesceRegions();
  }

  _coalesceRegions() {
    if (this._regions.length < 2) return;
    const merged = [this._regions[0]];
    for (let i = 1; i < this._regions.length; i++) {
      const prev = merged[merged.length - 1];
      const cur = this._regions[i];
      if (
        prev.end === cur.base &&
        prev.perms === cur.perms &&
        prev.label === cur.label &&
        prev.kind === cur.kind
      ) {
        prev.size += cur.size;
        prev.end = cur.end;
      } else {
        merged.push(cur);
      }
    }
    this._regions = merged;
  }

  /**
   * Reserve a virtual guard region without allocating ANY pages in `_pages`.
   * Example: Mach-O `__PAGEZERO` (`0 .. 0x100000000`) uses O(1) RAM.
   */
  reserveGuard(baseAddr, size, label = '__PAGEZERO') {
    this._assertAlive();
    const base = this._normalizeAddr(baseAddr, { faultOnError: false });
    if (base % PAGE_SIZE !== 0) {
      throw new MemoryFaultError(`Guard base address not page-aligned: 0x${base.toString(16)}`, {
        code: ERROR_CODES.EINVAL,
        faultType: 'UNALIGNED_ADDRESS',
        address: base,
        pid: this.pid,
      });
    }
    const rawSize = this._normalizePositiveSize(size);
    const alignedSize = alignUp(rawSize, PAGE_SIZE);
    if (!rangeFitsVA(base, alignedSize)) {
      throw new MemoryFaultError('Guard region end address overflow', {
        code: ERROR_CODES.EINVAL,
        faultType: 'INVALID_ADDRESS',
        address: base,
        pid: this.pid,
      });
    }
    const end = base + alignedSize;

    if (this._findRegionOverlapping(base, end)) {
      throw new MemoryFaultError(`Guard region overlaps existing mapped region at 0x${base.toString(16)}`, {
        code: ERROR_CODES.EEXIST,
        faultType: 'REGION_OVERLAP',
        address: base,
        pid: this.pid,
      });
    }
    if (this._findGuardOverlapping(base, end)) {
      throw new MemoryFaultError(`Guard region overlaps existing guard at 0x${base.toString(16)}`, {
        code: ERROR_CODES.EEXIST,
        faultType: 'GUARD_OVERLAP',
        address: base,
        pid: this.pid,
      });
    }

    const guard = { base, size: alignedSize, end, label: String(label ?? '__PAGEZERO') };
    let idx = this._guardRegions.length;
    for (let i = 0; i < this._guardRegions.length; i++) {
      if (this._guardRegions[i].base > base) {
        idx = i;
        break;
      }
    }
    this._guardRegions.splice(idx, 0, guard);
    return { ...guard };
  }

  /**
   * Map sparse 4KB pages with given permissions and label.
   */
  mmap(addrHint, size, perms = PROT_READ | PROT_WRITE, label = 'anon') {
    this._assertAlive();
    const rawSize = this._normalizePositiveSize(size);
    const alignedSize = alignUp(rawSize, PAGE_SIZE);
    this._validatePerms(perms);

    // Atomic quota check BEFORE any allocation or cursor update
    const currentBytes = this._pages.size * PAGE_SIZE;
    if (currentBytes + alignedSize > this.maxMemoryBytes) {
      throw new MemoryFaultError(
        `Out of virtual memory quota: requested ${alignedSize}B, used ${currentBytes}B, max ${this.maxMemoryBytes}B`,
        {
          code: ERROR_CODES.ENOMEM,
          faultType: 'ENOMEM',
          pid: this.pid,
          details: { requestedBytes: alignedSize, currentBytes, maxBytes: this.maxMemoryBytes },
        }
      );
    }

    let baseAddr;
    const isAuto = addrHint === 0 || addrHint === 0n || addrHint === null || addrHint === undefined;
    if (isAuto) {
      let startCursor = this._mmapCursor;
      const blockingGuard = this._findGuardContaining(startCursor);
      if (blockingGuard && blockingGuard.end >= 0x100000000) {
        startCursor = Math.max(HIGH_VA_MMAP_BASE, blockingGuard.end);
      }
      const found = this._findFreeRange(startCursor, alignedSize, { includeHeapHeadroom: true });
      if (found === null) {
        throw new MemoryFaultError('No free virtual address range available for mmap', {
          code: ERROR_CODES.ENOMEM,
          faultType: 'ENOMEM',
          pid: this.pid,
        });
      }
      baseAddr = found;
      const nextCursor = baseAddr + alignedSize;
      this._mmapCursor = nextCursor <= MAX_VA ? nextCursor : PAGE_SIZE;
    } else {
      baseAddr = this._normalizeAddr(addrHint, { faultOnError: false });
      if (baseAddr % PAGE_SIZE !== 0) {
        throw new MemoryFaultError(`mmap address not page-aligned: 0x${baseAddr.toString(16)}`, {
          code: ERROR_CODES.EINVAL,
          faultType: 'UNALIGNED_ADDRESS',
          address: baseAddr,
          pid: this.pid,
        });
      }
      if (!rangeFitsVA(baseAddr, alignedSize)) {
        throw new MemoryFaultError('mmap region end address overflow', {
          code: ERROR_CODES.EINVAL,
          faultType: 'INVALID_ADDRESS',
          address: baseAddr,
          pid: this.pid,
        });
      }
      const end = baseAddr + alignedSize;
      const guard = this._findGuardOverlapping(baseAddr, end);
      if (guard) {
        throw new MemoryFaultError(
          `SIGSEGV: Cannot mmap over guard region '${guard.label}' at 0x${baseAddr.toString(16)}`,
          {
            code: ERROR_CODES.EACCES,
            signal: 'SIGSEGV',
            faultType: 'GUARD_PAGE',
            address: baseAddr,
            pid: this.pid,
            details: { guardLabel: guard.label },
          }
        );
      }
      if (this._findRegionOverlapping(baseAddr, end)) {
        throw new MemoryFaultError(`mmap overlaps existing region at 0x${baseAddr.toString(16)}`, {
          code: ERROR_CODES.EEXIST,
          faultType: 'REGION_OVERLAP',
          address: baseAddr,
          pid: this.pid,
        });
      }
    }

    const startPage = Math.floor(baseAddr / PAGE_SIZE);
    const pageCount = alignedSize / PAGE_SIZE;
    for (let i = 0; i < pageCount; i++) {
      this._pages.set(startPage + i, {
        data: new Uint8Array(PAGE_SIZE),
        perms,
      });
    }

    this._insertRegionSorted({
      base: baseAddr,
      size: alignedSize,
      end: baseAddr + alignedSize,
      perms,
      label: String(label ?? 'anon'),
      kind: 'mmap',
    });

    const newBytes = this._pages.size * PAGE_SIZE;
    if (newBytes > this._peakBytes) {
      this._peakBytes = newBytes;
    }

    return baseAddr;
  }

  /**
   * Atomically update page permissions over [baseAddr, baseAddr + alignedSize).
   */
  mprotect(baseAddr, size, perms) {
    this._assertAlive();
    const base = this._normalizeAddr(baseAddr, { faultOnError: false });
    if (base % PAGE_SIZE !== 0) {
      throw new MemoryFaultError(`mprotect base address not page-aligned: 0x${base.toString(16)}`, {
        code: ERROR_CODES.EINVAL,
        faultType: 'UNALIGNED_ADDRESS',
        address: base,
        pid: this.pid,
      });
    }
    const alignedSize = alignUp(this._normalizePositiveSize(size), PAGE_SIZE);
    this._validatePerms(perms);
    if (!rangeFitsVA(base, alignedSize)) {
      throw new MemoryFaultError('mprotect end address overflow', {
        code: ERROR_CODES.EINVAL,
        faultType: 'INVALID_ADDRESS',
        address: base,
        pid: this.pid,
      });
    }
    const end = base + alignedSize;

    const startPage = Math.floor(base / PAGE_SIZE);
    const endPage = Math.floor((end - 1) / PAGE_SIZE);

    // Atomic pre-validation of EVERY page in range
    for (let p = startPage; p <= endPage; p++) {
      if (!this._pages.has(p)) {
        const faultAddr = p * PAGE_SIZE;
        const guard = this._findGuardContaining(faultAddr);
        throw new MemoryFaultError(
          guard
            ? `SIGSEGV: mprotect on guard region '${guard.label}' at 0x${faultAddr.toString(16)}`
            : `SIGSEGV: mprotect on unmapped page at 0x${faultAddr.toString(16)}`,
          {
            code: ERROR_CODES.EFAULT,
            signal: 'SIGSEGV',
            faultType: guard ? 'GUARD_PAGE' : 'UNMAPPED_PAGE',
            address: faultAddr,
            pid: this.pid,
            details: guard ? { guardLabel: guard.label } : null,
          }
        );
      }
    }

    for (let p = startPage; p <= endPage; p++) {
      this._pages.get(p).perms = perms;
    }

    // Split/update region metadata cleanly
    const nextRegions = [];
    for (const r of this._regions) {
      if (!intervalsOverlap(r.base, r.end, base, end)) {
        nextRegions.push(r);
        continue;
      }
      // Left untouched prefix
      if (r.base < base) {
        nextRegions.push({
          base: r.base,
          size: base - r.base,
          end: base,
          perms: r.perms,
          label: r.label,
          kind: r.kind,
        });
      }
      // Protected intersection
      const midStart = Math.max(r.base, base);
      const midEnd = Math.min(r.end, end);
      nextRegions.push({
        base: midStart,
        size: midEnd - midStart,
        end: midEnd,
        perms,
        label: r.label,
        kind: r.kind,
      });
      // Right untouched suffix
      if (r.end > end) {
        nextRegions.push({
          base: end,
          size: r.end - end,
          end: r.end,
          perms: r.perms,
          label: r.label,
          kind: r.kind,
        });
      }
    }
    this._regions = nextRegions;
    this._coalesceRegions();
  }

  /**
   * Unmap pages in [baseAddr, baseAddr + alignedSize).
   */
  munmap(baseAddr, size) {
    this._assertAlive();
    const base = this._normalizeAddr(baseAddr, { faultOnError: false });
    if (base % PAGE_SIZE !== 0) {
      throw new MemoryFaultError(`munmap base address not page-aligned: 0x${base.toString(16)}`, {
        code: ERROR_CODES.EINVAL,
        faultType: 'UNALIGNED_ADDRESS',
        address: base,
        pid: this.pid,
      });
    }
    const alignedSize = alignUp(this._normalizePositiveSize(size), PAGE_SIZE);
    if (!rangeFitsVA(base, alignedSize)) {
      throw new MemoryFaultError('munmap end address overflow', {
        code: ERROR_CODES.EINVAL,
        faultType: 'INVALID_ADDRESS',
        address: base,
        pid: this.pid,
      });
    }
    const end = base + alignedSize;

    const guard = this._findGuardOverlapping(base, end);
    if (guard) {
      throw new MemoryFaultError(
        `SIGSEGV: Cannot munmap guard region '${guard.label}' at 0x${base.toString(16)}`,
        {
          code: ERROR_CODES.EACCES,
          signal: 'SIGSEGV',
          faultType: 'GUARD_PAGE',
          address: base,
          pid: this.pid,
          details: { guardLabel: guard.label },
        }
      );
    }

    for (const r of this._regions) {
      if (r.kind === 'heap' && intervalsOverlap(r.base, r.end, base, end)) {
        throw new MemoryFaultError('Cannot munmap active heap region directly; use free()', {
          code: ERROR_CODES.EINVAL,
          faultType: 'HEAP_REGION_PROTECTED',
          address: base,
          pid: this.pid,
        });
      }
    }

    const startPage = Math.floor(base / PAGE_SIZE);
    const endPage = Math.floor((end - 1) / PAGE_SIZE);
    if (endPage - startPage + 1 <= this._pages.size) {
      for (let p = startPage; p <= endPage; p++) {
        this._pages.delete(p);
      }
    } else {
      for (const p of this._pages.keys()) {
        if (p >= startPage && p <= endPage) {
          this._pages.delete(p);
        }
      }
    }

    const nextRegions = [];
    for (const r of this._regions) {
      if (!intervalsOverlap(r.base, r.end, base, end)) {
        nextRegions.push(r);
        continue;
      }
      if (r.base < base) {
        nextRegions.push({
          base: r.base,
          size: base - r.base,
          end: base,
          perms: r.perms,
          label: r.label,
          kind: r.kind,
        });
      }
      if (r.end > end) {
        nextRegions.push({
          base: end,
          size: r.end - end,
          end: r.end,
          perms: r.perms,
          label: r.label,
          kind: r.kind,
        });
      }
    }
    this._regions = nextRegions;
  }

  /**
   * Full atomic pre-validation of all pages spanned by [addr, addr + length).
   */
  _validateAccess(addr, length, requiredPerm, accessKind) {
    this._assertAlive();
    const startAddr = this._normalizeAddr(addr, { faultOnError: true });
    if (typeof length !== 'number' || !Number.isSafeInteger(length) || length < 0) {
      throw new MemoryFaultError(`Invalid ${accessKind} length: ${length}`, {
        code: ERROR_CODES.EINVAL,
        signal: 'SIGSEGV',
        faultType: 'INVALID_SIZE',
        address: startAddr,
        access: accessKind,
        pid: this.pid,
      });
    }
    if (length === 0) {
      return { startAddr, length: 0 };
    }
    if (!rangeFitsVA(startAddr, length)) {
      throw new MemoryFaultError(`SIGSEGV: ${accessKind} address range overflow at 0x${startAddr.toString(16)}`, {
        code: ERROR_CODES.EFAULT,
        signal: 'SIGSEGV',
        faultType: 'INVALID_ADDRESS',
        address: startAddr,
        access: accessKind,
        pid: this.pid,
      });
    }
    const endAddr = startAddr + length;

    const startPage = Math.floor(startAddr / PAGE_SIZE);
    const endPage = Math.floor((endAddr - 1) / PAGE_SIZE);

    for (let p = startPage; p <= endPage; p++) {
      const page = this._pages.get(p);
      const faultAddr = p === startPage ? startAddr : p * PAGE_SIZE;
      if (!page) {
        const guard = this._findGuardContaining(faultAddr);
        throw new MemoryFaultError(
          guard
            ? `SIGSEGV: Access to guard region '${guard.label}' at 0x${faultAddr.toString(16)}`
            : `SIGSEGV: Unmapped page access at 0x${faultAddr.toString(16)}`,
          {
            code: ERROR_CODES.EFAULT,
            signal: 'SIGSEGV',
            faultType: guard ? 'GUARD_PAGE' : 'UNMAPPED_PAGE',
            address: faultAddr,
            pid: this.pid,
            access: accessKind,
            details: guard ? { guardLabel: guard.label } : null,
          }
        );
      }
      if ((page.perms & requiredPerm) === 0) {
        const faultType =
          accessKind === 'read'
            ? 'READ_VIOLATION'
            : accessKind === 'write'
              ? 'WRITE_VIOLATION'
              : 'NX_EXEC_VIOLATION';
        throw new MemoryFaultError(
          `SIGSEGV: ${faultType} at 0x${faultAddr.toString(16)} (perms=${formatPerms(page.perms)})`,
          {
            code: ERROR_CODES.EFAULT,
            signal: 'SIGSEGV',
            faultType,
            address: faultAddr,
            pid: this.pid,
            access: accessKind,
            pagePerms: page.perms,
          }
        );
      }
    }

    return { startAddr, length };
  }

  _readChecked(startAddr, length) {
    const out = new Uint8Array(length);
    let remaining = length;
    let curAddr = startAddr;
    let dstOff = 0;

    while (remaining > 0) {
      const pageNum = Math.floor(curAddr / PAGE_SIZE);
      const pageOff = curAddr - pageNum * PAGE_SIZE;
      const chunkLen = Math.min(remaining, PAGE_SIZE - pageOff);
      const page = this._pages.get(pageNum);
      out.set(page.data.subarray(pageOff, pageOff + chunkLen), dstOff);
      curAddr += chunkLen;
      dstOff += chunkLen;
      remaining -= chunkLen;
    }

    return out;
  }

  read(addr, length) {
    const { startAddr, length: len } = this._validateAccess(addr, length, PROT_READ, 'read');
    if (len === 0) return new Uint8Array(0);
    return this._readChecked(startAddr, len);
  }

  write(addr, bytes) {
    const view = toBytesView(bytes, this.pid);
    const { startAddr, length: len } = this._validateAccess(addr, view.byteLength, PROT_WRITE, 'write');
    if (len === 0) return;

    let remaining = len;
    let curAddr = startAddr;
    let srcOff = 0;

    while (remaining > 0) {
      const pageNum = Math.floor(curAddr / PAGE_SIZE);
      const pageOff = curAddr - pageNum * PAGE_SIZE;
      const chunkLen = Math.min(remaining, PAGE_SIZE - pageOff);
      const page = this._pages.get(pageNum);
      page.data.set(view.subarray(srcOff, srcOff + chunkLen), pageOff);
      curAddr += chunkLen;
      srcOff += chunkLen;
      remaining -= chunkLen;
    }
  }

  fetch(addr, length) {
    const { startAddr, length: len } = this._validateAccess(addr, length, PROT_EXEC, 'exec');
    if (len === 0) return new Uint8Array(0);
    return this._readChecked(startAddr, len);
  }

  // Typed helpers strictly delegating to read/write
  readU8(addr) {
    return this.read(addr, 1)[0];
  }

  readU16(addr, littleEndian = true) {
    const b = this.read(addr, 2);
    return new DataView(b.buffer, b.byteOffset, 2).getUint16(0, littleEndian);
  }

  readU32(addr, littleEndian = true) {
    const b = this.read(addr, 4);
    return new DataView(b.buffer, b.byteOffset, 4).getUint32(0, littleEndian);
  }

  readU64(addr, littleEndian = true) {
    const b = this.read(addr, 8);
    return new DataView(b.buffer, b.byteOffset, 8).getBigUint64(0, littleEndian);
  }

  writeU8(addr, value) {
    this.write(addr, new Uint8Array([value & 0xff]));
  }

  writeU16(addr, value, littleEndian = true) {
    const buf = new Uint8Array(2);
    new DataView(buf.buffer).setUint16(0, value & 0xffff, littleEndian);
    this.write(addr, buf);
  }

  writeU32(addr, value, littleEndian = true) {
    const buf = new Uint8Array(4);
    new DataView(buf.buffer).setUint32(0, value >>> 0, littleEndian);
    this.write(addr, buf);
  }

  writeU64(addr, value, littleEndian = true) {
    const buf = new Uint8Array(8);
    const big = BigInt.asUintN(64, typeof value === 'bigint' ? value : BigInt(value));
    new DataView(buf.buffer).setBigUint64(0, big, littleEndian);
    this.write(addr, buf);
  }

  readCString(addr, maxLen = 4096) {
    this._assertAlive();
    let cur = this._normalizeAddr(addr, { faultOnError: true });
    if (!Number.isInteger(maxLen) || maxLen < 0) {
      throw new MemoryFaultError(`Invalid maxLen: ${maxLen}`, {
        code: ERROR_CODES.EINVAL,
        faultType: 'INVALID_SIZE',
        pid: this.pid,
      });
    }
    const collected = [];
    let remaining = maxLen;
    while (remaining > 0) {
      const pageNum = Math.floor(cur / PAGE_SIZE);
      const pageOff = cur - pageNum * PAGE_SIZE;
      const step = Math.min(remaining, PAGE_SIZE - pageOff);
      const chunk = this.read(cur, step);
      for (let i = 0; i < chunk.length; i++) {
        if (chunk[i] === 0x00) {
          return TEXT_DECODER.decode(Uint8Array.from(collected));
        }
        collected.push(chunk[i]);
      }
      cur += step;
      remaining -= step;
    }
    return TEXT_DECODER.decode(Uint8Array.from(collected));
  }

  writeCString(addr, str) {
    const encoded = TEXT_ENCODER.encode(String(str));
    const buf = new Uint8Array(encoded.length + 1);
    buf.set(encoded, 0);
    buf[encoded.length] = 0x00;
    this.write(addr, buf);
    return buf.length;
  }

  // ---- Guard-Aware Coalescing Free-List Heap Allocator ----

  _ensureHeapInitialized(minBytes) {
    if (this._heapInitialized) return;
    const desiredWindow = alignUp(Math.max(minBytes, PAGE_SIZE), PAGE_SIZE);

    let chosenBase = null;
    if (this._requestedHeapBase !== null && this._requestedHeapBase !== undefined) {
      const req = this._normalizeAddr(this._requestedHeapBase, { faultOnError: false });
      if (req % PAGE_SIZE !== 0) {
        throw new MemoryFaultError('Requested heapBase must be page-aligned', {
          code: ERROR_CODES.EINVAL,
          faultType: 'UNALIGNED_ADDRESS',
          address: req,
          pid: this.pid,
        });
      }
      if (!rangeFitsVA(req, desiredWindow)) {
        throw new MemoryFaultError('Requested heapBase range overflow', {
          code: ERROR_CODES.EINVAL,
          faultType: 'INVALID_ADDRESS',
          address: req,
          pid: this.pid,
        });
      }
      if (
        this._findGuardOverlapping(req, req + desiredWindow) ||
        this._findRegionOverlapping(req, req + desiredWindow)
      ) {
        throw new MemoryFaultError('Requested heapBase overlaps guard or mapped region', {
          code: ERROR_CODES.EEXIST,
          faultType: 'REGION_OVERLAP',
          address: req,
          pid: this.pid,
        });
      }
      chosenBase = req;
    } else {
      const preferWindow = alignUp(
        Math.max(desiredWindow, Math.min(Math.max(this.maxMemoryBytes, PAGE_SIZE), 0x1000000)),
        PAGE_SIZE
      );
      if (
        !this._findGuardOverlapping(DEFAULT_HEAP_BASE, DEFAULT_HEAP_BASE + preferWindow) &&
        !this._findRegionOverlapping(DEFAULT_HEAP_BASE, DEFAULT_HEAP_BASE + preferWindow)
      ) {
        chosenBase = DEFAULT_HEAP_BASE;
      } else if (
        !this._findGuardOverlapping(HIGH_VA_HEAP_BASE, HIGH_VA_HEAP_BASE + preferWindow) &&
        !this._findRegionOverlapping(HIGH_VA_HEAP_BASE, HIGH_VA_HEAP_BASE + preferWindow)
      ) {
        chosenBase = HIGH_VA_HEAP_BASE;
      } else {
        chosenBase =
          this._findFreeRange(HIGH_VA_HEAP_BASE, preferWindow) ??
          this._findFreeRange(HIGH_VA_HEAP_BASE, desiredWindow);
      }
    }

    if (chosenBase === null) {
      throw new MemoryFaultError('Unable to place process heap in virtual address space', {
        code: ERROR_CODES.ENOMEM,
        faultType: 'ENOMEM',
        pid: this.pid,
      });
    }

    this._heapBase = chosenBase;
    this._heapEnd = chosenBase;
    this._heapInitialized = true;
  }

  _mapHeapPages(baseAddr, alignedSize) {
    const startPage = Math.floor(baseAddr / PAGE_SIZE);
    const pageCount = alignedSize / PAGE_SIZE;
    for (let i = 0; i < pageCount; i++) {
      this._pages.set(startPage + i, {
        data: new Uint8Array(PAGE_SIZE),
        perms: PROT_READ | PROT_WRITE,
      });
    }
    this._insertRegionSorted({
      base: baseAddr,
      size: alignedSize,
      end: baseAddr + alignedSize,
      perms: PROT_READ | PROT_WRITE,
      label: 'heap',
      kind: 'heap',
    });
    const newBytes = this._pages.size * PAGE_SIZE;
    if (newBytes > this._peakBytes) {
      this._peakBytes = newBytes;
    }
  }

  _canGrowContiguously(growBytes) {
    if (!rangeFitsVA(this._heapEnd, growBytes)) return false;
    const end = this._heapEnd + growBytes;
    return (
      !this._findGuardOverlapping(this._heapEnd, end) &&
      !this._findRegionOverlapping(this._heapEnd, end)
    );
  }

  _growHeap(neededBytes) {
    const growBytes = alignUp(neededBytes, PAGE_SIZE);
    const currentBytes = this._pages.size * PAGE_SIZE;
    if (currentBytes + growBytes > this.maxMemoryBytes) {
      throw new MemoryFaultError(
        `Heap out of memory: requested ${growBytes}B, used ${currentBytes}B, max ${this.maxMemoryBytes}B`,
        {
          code: ERROR_CODES.ENOMEM,
          faultType: 'ENOMEM',
          pid: this.pid,
          details: { requestedBytes: growBytes, currentBytes, maxBytes: this.maxMemoryBytes },
        }
      );
    }

    let chunkBase;
    if (this._canGrowContiguously(growBytes)) {
      chunkBase = this._heapEnd;
      this._heapEnd += growBytes;
    } else {
      chunkBase = this._findFreeRange(this._heapEnd, growBytes);
      if (chunkBase === null) {
        throw new MemoryFaultError('No free virtual range for heap growth', {
          code: ERROR_CODES.ENOMEM,
          faultType: 'ENOMEM',
          pid: this.pid,
        });
      }
      if (chunkBase + growBytes > this._heapEnd) {
        this._heapEnd = chunkBase + growBytes;
      }
    }

    this._mapHeapPages(chunkBase, growBytes);

    const newBlock = { addr: chunkBase, size: growBytes, free: true };
    let insertIdx = this._heapBlocks.length;
    for (let i = 0; i < this._heapBlocks.length; i++) {
      if (this._heapBlocks[i].addr > chunkBase) {
        insertIdx = i;
        break;
      }
    }
    this._heapBlocks.splice(insertIdx, 0, newBlock);
    this._coalesceHeapAt(insertIdx);
  }

  _coalesceHeapAt(idx) {
    let curIdx = idx;
    // Merge forward
    while (curIdx + 1 < this._heapBlocks.length) {
      const cur = this._heapBlocks[curIdx];
      const next = this._heapBlocks[curIdx + 1];
      if (cur.free && next.free && cur.addr + cur.size === next.addr) {
        cur.size += next.size;
        this._heapBlocks.splice(curIdx + 1, 1);
      } else {
        break;
      }
    }
    // Merge backward
    while (curIdx > 0) {
      const prev = this._heapBlocks[curIdx - 1];
      const cur = this._heapBlocks[curIdx];
      if (prev.free && cur.free && prev.addr + prev.size === cur.addr) {
        prev.size += cur.size;
        this._heapBlocks.splice(curIdx, 1);
        curIdx -= 1;
      } else {
        break;
      }
    }
    return curIdx;
  }

  _findHeapBlockIndex(addr) {
    let lo = 0;
    let hi = this._heapBlocks.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const b = this._heapBlocks[mid];
      if (b.addr === addr) return mid;
      if (b.addr < addr) lo = mid + 1;
      else hi = mid - 1;
    }
    return -1;
  }

  _clearFreedPtrsInRange(start, end) {
    if (this._freedPtrs.size === 0) return;
    for (const p of this._freedPtrs) {
      if (p >= start && p < end) {
        this._freedPtrs.delete(p);
      }
    }
  }

  alloc(size) {
    this._assertAlive();
    const rawSize = this._normalizeNonNegativeSize(size);
    const alignedSize = rawSize === 0 ? HEAP_ALIGNMENT : alignUp(rawSize, HEAP_ALIGNMENT);
    const freshInit = !this._heapInitialized;
    this._ensureHeapInitialized(alignedSize);

    let idx = this._heapBlocks.findIndex((b) => b.free && b.size >= alignedSize);
    if (idx === -1) {
      const last = this._heapBlocks.length > 0 ? this._heapBlocks[this._heapBlocks.length - 1] : null;
      let growNeeded = alignedSize;
      if (last && last.free && last.addr + last.size === this._heapEnd) {
        const delta = alignedSize - last.size;
        if (delta > 0 && this._canGrowContiguously(alignUp(delta, PAGE_SIZE))) {
          growNeeded = delta;
        }
      }
      try {
        this._growHeap(growNeeded);
      } catch (err) {
        if (freshInit && this._heapBlocks.length === 0) {
          this._heapInitialized = false;
          this._heapBase = null;
          this._heapEnd = 0;
        }
        throw err;
      }
      idx = this._heapBlocks.findIndex((b) => b.free && b.size >= alignedSize);
      if (idx === -1) {
        if (freshInit && this._heapBlocks.length === 0) {
          this._heapInitialized = false;
          this._heapBase = null;
          this._heapEnd = 0;
        }
        throw new MemoryFaultError('Heap allocation failed after growth', {
          code: ERROR_CODES.ENOMEM,
          faultType: 'ENOMEM',
          pid: this.pid,
        });
      }
    }

    const block = this._heapBlocks[idx];
    if (block.size - alignedSize >= HEAP_ALIGNMENT) {
      const remainder = {
        addr: block.addr + alignedSize,
        size: block.size - alignedSize,
        free: true,
      };
      block.size = alignedSize;
      block.free = false;
      this._heapBlocks.splice(idx + 1, 0, remainder);
    } else {
      block.free = false;
    }

    this._clearFreedPtrsInRange(block.addr, block.addr + block.size);
    return block.addr;
  }

  free(ptr) {
    this._assertAlive();
    const addr = this._normalizeAddr(ptr, { faultOnError: false });
    const idx = this._findHeapBlockIndex(addr);

    if (idx !== -1) {
      const block = this._heapBlocks[idx];
      if (!block.free) {
        block.free = true;
        this._freedPtrs.add(addr);
        this._coalesceHeapAt(idx);
        return;
      }
      if (this._freedPtrs.has(addr)) {
        throw new MemoryFaultError(`Double free detected at 0x${addr.toString(16)}`, {
          code: ERROR_CODES.EINVAL,
          signal: 'SIGSEGV',
          faultType: 'DOUBLE_FREE',
          address: addr,
          pid: this.pid,
        });
      }
      throw new MemoryFaultError(`Invalid pointer passed to free(): 0x${addr.toString(16)}`, {
        code: ERROR_CODES.EINVAL,
        signal: 'SIGSEGV',
        faultType: 'INVALID_FREE',
        address: addr,
        pid: this.pid,
      });
    }

    if (this._freedPtrs.has(addr)) {
      throw new MemoryFaultError(`Double free detected at 0x${addr.toString(16)}`, {
        code: ERROR_CODES.EINVAL,
        signal: 'SIGSEGV',
        faultType: 'DOUBLE_FREE',
        address: addr,
        pid: this.pid,
      });
    }

    throw new MemoryFaultError(`Invalid pointer passed to free(): 0x${addr.toString(16)}`, {
      code: ERROR_CODES.EINVAL,
      signal: 'SIGSEGV',
      faultType: 'INVALID_FREE',
      address: addr,
      pid: this.pid,
    });
  }

  realloc(ptr, newSize) {
    this._assertAlive();
    const isNull = ptr === 0 || ptr === 0n || ptr === null || ptr === undefined;
    const oldAddr = isNull ? 0 : this._normalizeAddr(ptr, { faultOnError: false });
    const rawNewSize = this._normalizeNonNegativeSize(newSize);

    if (oldAddr === 0 && rawNewSize === 0) return 0;
    if (oldAddr === 0 && rawNewSize > 0) return this.alloc(rawNewSize);
    if (oldAddr !== 0 && rawNewSize === 0) {
      this.free(oldAddr);
      return 0;
    }

    const idx = this._findHeapBlockIndex(oldAddr);
    if (idx === -1 || this._heapBlocks[idx].free) {
      const isDouble = this._freedPtrs.has(oldAddr);
      throw new MemoryFaultError(
        isDouble
          ? `realloc() on freed pointer 0x${oldAddr.toString(16)}`
          : `Invalid pointer passed to realloc(): 0x${oldAddr.toString(16)}`,
        {
          code: ERROR_CODES.EINVAL,
          signal: 'SIGSEGV',
          faultType: isDouble ? 'DOUBLE_FREE' : 'INVALID_FREE',
          address: oldAddr,
          pid: this.pid,
        }
      );
    }

    const block = this._heapBlocks[idx];
    const alignedNew = alignUp(rawNewSize, HEAP_ALIGNMENT);

    // 1. Shrink or equal
    if (alignedNew <= block.size) {
      const leftover = block.size - alignedNew;
      if (leftover >= HEAP_ALIGNMENT) {
        block.size = alignedNew;
        this._heapBlocks.splice(idx + 1, 0, {
          addr: block.addr + alignedNew,
          size: leftover,
          free: true,
        });
        this._coalesceHeapAt(idx + 1);
      }
      return block.addr;
    }

    // 2. In-place grow into contiguous next free block
    const next = idx + 1 < this._heapBlocks.length ? this._heapBlocks[idx + 1] : null;
    if (next && next.free && block.addr + block.size === next.addr && block.size + next.size >= alignedNew) {
      const extra = alignedNew - block.size;
      const rem = next.size - extra;
      if (rem >= HEAP_ALIGNMENT) {
        next.addr += extra;
        next.size = rem;
        block.size = alignedNew;
      } else {
        block.size += next.size;
        this._heapBlocks.splice(idx + 1, 1);
      }
      this._clearFreedPtrsInRange(block.addr, block.addr + block.size);
      return block.addr;
    }

    // 3. In-place grow at end of heap (avoids doubling memory near quota)
    const blockEnd = block.addr + block.size;
    const trailingFree =
      next && next.free && blockEnd === next.addr && next.addr + next.size === this._heapEnd
        ? next
        : null;
    const contiguousEnd = trailingFree ? trailingFree.addr + trailingFree.size : blockEnd;
    if (contiguousEnd === this._heapEnd) {
      const deltaNeeded = alignedNew - (contiguousEnd - block.addr);
      const growBytes = alignUp(deltaNeeded, PAGE_SIZE);
      if (
        this._canGrowContiguously(growBytes) &&
        this._pages.size * PAGE_SIZE + growBytes <= this.maxMemoryBytes
      ) {
        this._growHeap(growBytes);
        // Re-fetch next block (which now contains the newly grown contiguous free space)
        const grownNext = this._heapBlocks[idx + 1];
        if (grownNext && grownNext.free && block.addr + block.size === grownNext.addr && block.size + grownNext.size >= alignedNew) {
          const extra = alignedNew - block.size;
          const rem = grownNext.size - extra;
          if (rem >= HEAP_ALIGNMENT) {
            grownNext.addr += extra;
            grownNext.size = rem;
            block.size = alignedNew;
          } else {
            block.size += grownNext.size;
            this._heapBlocks.splice(idx + 1, 1);
          }
          this._clearFreedPtrsInRange(block.addr, block.addr + block.size);
          return block.addr;
        }
      }
    }

    // 4. Atomic relocate (preserves original block untouched on ENOMEM)
    const oldSize = block.size;
    const newPtr = this.alloc(rawNewSize);
    try {
      const copyLen = Math.min(oldSize, alignedNew);
      const payload = this.read(oldAddr, copyLen);
      this.write(newPtr, payload);
    } catch (err) {
      this.free(newPtr);
      throw err;
    }
    this.free(oldAddr);
    return newPtr;
  }

  getStats() {
    let allocatedBytes = 0;
    let freeBytes = 0;
    let freeBlockCount = 0;
    for (const b of this._heapBlocks) {
      if (b.free) {
        freeBytes += b.size;
        freeBlockCount += 1;
      } else {
        allocatedBytes += b.size;
      }
    }

    return {
      mappedPages: this._pages.size,
      usedBytes: this._pages.size * PAGE_SIZE,
      peakBytes: this._peakBytes,
      maxBytes: this.maxMemoryBytes,
      regions: [
        ...this._guardRegions.map((g) => ({
          base: g.base,
          size: g.size,
          end: g.end,
          perms: 0,
          permsString: '---',
          label: g.label,
          kind: 'guard',
        })),
        ...this._regions.map((r) => ({
          base: r.base,
          size: r.size,
          end: r.end,
          perms: r.perms,
          permsString: formatPerms(r.perms),
          label: r.label,
          kind: r.kind,
        })),
      ].sort((a, b) => a.base - b.base),
      guardRegions: this._guardRegions.map((g) => ({
        base: g.base,
        size: g.size,
        end: g.end,
        label: g.label,
      })),
      heap: {
        base: this._heapBase,
        allocatedBytes,
        freeBytes,
        totalBytes: allocatedBytes + freeBytes,
        blockCount: this._heapBlocks.length,
        freeBlockCount,
      },
    };
  }

  destroy() {
    if (this._destroyed) return;
    this._pages.clear();
    this._regions = [];
    this._guardRegions = [];
    this._heapBlocks = [];
    this._freedPtrs.clear();
    this._heapInitialized = false;
    this._heapBase = null;
    this._heapEnd = 0;
    this._destroyed = true;
  }
}

export function createAddressSpace(options = {}) {
  return new AddressSpace(options);
}
