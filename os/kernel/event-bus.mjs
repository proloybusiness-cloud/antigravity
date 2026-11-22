/**
 * OmniOS KernelEventBus — synchronous, wildcard & prefix-capable, fault-isolated pub/sub bus.
 */

export class KernelEventBus {
  constructor({ onError = null } = {}) {
    this._exact = new Map();
    this._prefix = new Map();
    this._wildcard = new Set();
    this._subSeq = 0;
    this._emitSeq = 0;
    this._errorCount = 0;
    this._onError = typeof onError === 'function' ? onError : null;
  }

  _classifyPattern(pattern) {
    if (typeof pattern !== 'string' || pattern.length === 0) {
      throw new TypeError('Event pattern must be a non-empty string');
    }
    if (pattern === '*') {
      return { bucketType: 'wildcard', prefix: '' };
    }
    if (pattern.endsWith('*')) {
      return { bucketType: 'prefix', prefix: pattern.slice(0, -1) };
    }
    return { bucketType: 'exact', prefix: '' };
  }

  _subscribe(pattern, listener, once) {
    const { bucketType, prefix } = this._classifyPattern(pattern);
    if (typeof listener !== 'function') {
      throw new TypeError('Event listener must be a function');
    }

    const sub = {
      seq: ++this._subSeq,
      pattern,
      bucketType,
      prefix,
      listener,
      once: Boolean(once),
      active: true,
    };

    if (bucketType === 'wildcard') {
      this._wildcard.add(sub);
    } else if (bucketType === 'prefix') {
      let bucket = this._prefix.get(prefix);
      if (!bucket) {
        bucket = new Set();
        this._prefix.set(prefix, bucket);
      }
      bucket.add(sub);
    } else {
      let bucket = this._exact.get(pattern);
      if (!bucket) {
        bucket = new Set();
        this._exact.set(pattern, bucket);
      }
      bucket.add(sub);
    }

    return () => this._removeSub(sub);
  }

  _removeSub(sub) {
    if (!sub.active) return false;
    sub.active = false;
    if (sub.bucketType === 'wildcard') {
      return this._wildcard.delete(sub);
    }
    if (sub.bucketType === 'prefix') {
      const bucket = this._prefix.get(sub.prefix);
      if (!bucket) return false;
      const deleted = bucket.delete(sub);
      if (bucket.size === 0) this._prefix.delete(sub.prefix);
      return deleted;
    }
    const bucket = this._exact.get(sub.pattern);
    if (!bucket) return false;
    const deleted = bucket.delete(sub);
    if (bucket.size === 0) this._exact.delete(sub.pattern);
    return deleted;
  }

  _notifyError(error, event, pattern, listener) {
    if (!this._onError) return;
    try {
      this._onError({ event, pattern, error, listener });
    } catch {
      // Isolate onError handler failures so emit() never crashes.
    }
  }

  on(pattern, listener) {
    return this._subscribe(pattern, listener, false);
  }

  once(pattern, listener) {
    return this._subscribe(pattern, listener, true);
  }

  off(pattern, listener = undefined) {
    const { bucketType, prefix } = this._classifyPattern(pattern);
    if (listener !== undefined && typeof listener !== 'function') {
      throw new TypeError('Event listener must be a function');
    }

    let bucket;
    let mapRef = null;
    let mapKey = null;
    if (bucketType === 'wildcard') {
      bucket = this._wildcard;
    } else if (bucketType === 'prefix') {
      bucket = this._prefix.get(prefix);
      mapRef = this._prefix;
      mapKey = prefix;
    } else {
      bucket = this._exact.get(pattern);
      mapRef = this._exact;
      mapKey = pattern;
    }

    if (!bucket || bucket.size === 0) return false;

    let removed = false;
    for (const sub of Array.from(bucket)) {
      if (listener === undefined || sub.listener === listener) {
        sub.active = false;
        bucket.delete(sub);
        removed = true;
      }
    }
    if (mapRef && bucket.size === 0) {
      mapRef.delete(mapKey);
    }
    return removed;
  }

  emit(event, payload = undefined) {
    if (typeof event !== 'string' || event.length === 0) {
      throw new TypeError('Event name must be a non-empty string');
    }

    const emitSeq = ++this._emitSeq;
    const ts = new Date().toISOString();
    const matched = [];
    let bucketCount = 0;

    const exactBucket = this._exact.get(event);
    if (exactBucket && exactBucket.size > 0) {
      bucketCount += 1;
      for (const sub of exactBucket) {
        if (sub.active) matched.push(sub);
      }
    }

    for (const [prefix, bucket] of this._prefix.entries()) {
      if (event.startsWith(prefix) && bucket.size > 0) {
        bucketCount += 1;
        for (const sub of bucket) {
          if (sub.active) matched.push(sub);
        }
      }
    }

    if (this._wildcard.size > 0) {
      bucketCount += 1;
      for (const sub of this._wildcard) {
        if (sub.active) matched.push(sub);
      }
    }

    if (bucketCount > 1 && matched.length > 1) {
      matched.sort((a, b) => a.seq - b.seq);
    }

    let delivered = 0;
    const errors = [];

    for (const sub of matched) {
      if (!sub.active) continue;
      if (sub.once) {
        this._removeSub(sub);
      }

      const meta = { event, pattern: sub.pattern, ts, seq: emitSeq };
      try {
        const ret = sub.listener(payload, event, meta);
        delivered += 1;
        if (
          ret !== null &&
          ret !== undefined &&
          (typeof ret === 'object' || typeof ret === 'function') &&
          typeof ret.then === 'function'
        ) {
          ret.then(undefined, (asyncErr) => {
            this._errorCount += 1;
            this._notifyError(asyncErr, event, sub.pattern, sub.listener);
          });
        }
      } catch (err) {
        this._errorCount += 1;
        errors.push({ event, pattern: sub.pattern, error: err });
        this._notifyError(err, event, sub.pattern, sub.listener);
      }
    }

    return { event, delivered, errors };
  }

  removeAllListeners(pattern = undefined) {
    if (pattern === undefined) {
      this.clear();
      return;
    }
    this.off(pattern);
  }

  clear() {
    for (const bucket of this._exact.values()) {
      for (const sub of bucket) sub.active = false;
    }
    for (const bucket of this._prefix.values()) {
      for (const sub of bucket) sub.active = false;
    }
    for (const sub of this._wildcard) {
      sub.active = false;
    }
    this._exact.clear();
    this._prefix.clear();
    this._wildcard.clear();
  }

  listenerCount(pattern = undefined) {
    if (pattern !== undefined) {
      const { bucketType, prefix } = this._classifyPattern(pattern);
      if (bucketType === 'wildcard') return this._wildcard.size;
      if (bucketType === 'prefix') return this._prefix.get(prefix)?.size ?? 0;
      return this._exact.get(pattern)?.size ?? 0;
    }

    let total = this._wildcard.size;
    for (const bucket of this._exact.values()) total += bucket.size;
    for (const bucket of this._prefix.values()) total += bucket.size;
    return total;
  }

  getStats() {
    return {
      emittedCount: this._emitSeq,
      errorCount: this._errorCount,
      activeListeners: this.listenerCount(),
    };
  }
}
