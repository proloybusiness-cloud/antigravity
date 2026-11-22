/**
 * OmniOS CpuRegistry — maps CPU/VM architecture identifiers to CPU/VM factories.
 * Contract 5 (`os/cpu/registry.mjs`).
 */

import { OmniOSError, ERROR_CODES } from '../common/errors.mjs';

export const SUPPORTED_ARCHS = Object.freeze(['dalvik', 'x86_64', 'x86', 'arm64', 'wasm']);

export const ARCH_ALIASES = Object.freeze(
  Object.assign(Object.create(null), {
    amd64: 'x86_64',
    'x86-64': 'x86_64',
    x64: 'x86_64',
    aarch64: 'arm64',
    arm64e: 'arm64',
    i386: 'x86',
    i686: 'x86',
    ia32: 'x86',
    dex: 'dalvik',
    wasm32: 'wasm',
  })
);

export class CpuRegistry {
  constructor() {
    this._factories = new Map();
  }

  _normalizeArch(arch) {
    if (typeof arch !== 'string') return null;
    const clean = arch.trim().toLowerCase();
    if (clean.length === 0) return null;
    return Object.prototype.hasOwnProperty.call(ARCH_ALIASES, clean) ? ARCH_ALIASES[clean] : clean;
  }

  register(arch, CpuFactory, { overwrite = true } = {}) {
    const key = this._normalizeArch(arch);
    if (!key) {
      throw new OmniOSError('Architecture name must be a non-empty string', {
        code: ERROR_CODES.EINVAL,
        details: { arch },
      });
    }

    const isCallable = typeof CpuFactory === 'function';
    const isFactoryObj =
      CpuFactory !== null && typeof CpuFactory === 'object' && typeof CpuFactory.create === 'function';
    if (!isCallable && !isFactoryObj) {
      throw new OmniOSError(`Invalid CpuFactory for architecture: ${key}`, {
        code: ERROR_CODES.EINVAL,
        details: { arch: key },
      });
    }

    if (!overwrite && this._factories.has(key)) {
      throw new OmniOSError(`CPU architecture already registered: ${key}`, {
        code: ERROR_CODES.EEXIST,
        details: { arch: key },
      });
    }

    this._factories.set(key, CpuFactory);
    return this;
  }

  get(arch) {
    const key = this._normalizeArch(arch);
    if (!key) return null;
    return this._factories.get(key) ?? null;
  }

  has(arch) {
    return this.get(arch) !== null;
  }

  unregister(arch) {
    const key = this._normalizeArch(arch);
    if (!key) return false;
    return this._factories.delete(key);
  }

  list() {
    return Array.from(this._factories.keys());
  }

  create(arch, opts = {}) {
    const factory = this.get(arch);
    if (!factory) {
      throw new OmniOSError(`No CPU/VM engine registered for architecture: ${arch}`, {
        code: ERROR_CODES.ENOENT,
        details: { arch, registered: this.list() },
      });
    }

    if (typeof factory === 'object' && typeof factory.create === 'function') {
      return factory.create(opts);
    }

    const src = Function.prototype.toString.call(factory);
    if (/^\s*class[\s{]/.test(src)) {
      return new factory(opts);
    }

    try {
      return factory(opts);
    } catch (err) {
      if (err instanceof TypeError && /cannot be invoked without 'new'/i.test(err.message)) {
        return new factory(opts);
      }
      throw err;
    }
  }

  clear() {
    this._factories.clear();
  }
}
