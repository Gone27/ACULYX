/**
 * BroadcastCoalescer
 * Coalesces rapid tab-state broadcasts to at most one per `intervalMs` (default 100ms).
 * The LAST value received in the window is always flushed (never drops final state).
 * A trailing flush always fires after the last call even if the interval has not elapsed.
 */
export class BroadcastCoalescer<T> {
  private pending = new Map<number, T>(); // tabId → last value
  private timers = new Map<number, ReturnType<typeof setTimeout>>();
  
  constructor(
    private readonly flush: (tabId: number, value: T) => void,
    private readonly intervalMs: number = 100,
  ) {}

  push(tabId: number, value: T): void {
    // Always store latest value
    this.pending.set(tabId, value);
    // Schedule a trailing flush if not already scheduled
    if (!this.timers.has(tabId)) {
      const timer = setTimeout(() => {
        this.timers.delete(tabId);
        const v = this.pending.get(tabId);
        if (v !== undefined) {
          this.pending.delete(tabId);
          this.flush(tabId, v);
        }
      }, this.intervalMs);
      this.timers.set(tabId, timer);
    }
  }

  /** Immediately flush a specific tab (e.g. on tab close). */
  flushNow(tabId: number): void {
    const timer = this.timers.get(tabId);
    if (timer !== undefined) {
      clearTimeout(timer);
      this.timers.delete(tabId);
    }
    const v = this.pending.get(tabId);
    if (v !== undefined) {
      this.pending.delete(tabId);
      this.flush(tabId, v);
    }
  }

  /** Clear all pending state for a tab (e.g. navigation reset). */
  clear(tabId: number): void {
    const timer = this.timers.get(tabId);
    if (timer !== undefined) {
      clearTimeout(timer);
      this.timers.delete(tabId);
    }
    this.pending.delete(tabId);
  }
}

/**
 * WriteBatcher
 * Batches chrome.storage.session writes to at most `maxPerSec` writes per tab per second.
 * The LAST value is always committed (trailing write always fires).
 * Writes are serialized per tab to prevent lost updates.
 */
export class WriteBatcher {
  private timers = new Map<number, ReturnType<typeof setTimeout>>();
  private pending = new Map<number, () => Promise<void>>();
  private readonly minIntervalMs: number;

  constructor(maxPerSec: number = 2) {
    this.minIntervalMs = Math.ceil(1000 / maxPerSec);
  }

  schedule(tabId: number, writeFn: () => Promise<void>): void {
    this.pending.set(tabId, writeFn);
    if (!this.timers.has(tabId)) {
      const timer = setTimeout(() => {
        this.timers.delete(tabId);
        const fn = this.pending.get(tabId);
        if (fn !== undefined) {
          this.pending.delete(tabId);
          void fn();
        }
      }, this.minIntervalMs);
      this.timers.set(tabId, timer);
    }
  }

  flushNow(tabId: number): void {
    const timer = this.timers.get(tabId);
    if (timer !== undefined) {
      clearTimeout(timer);
      this.timers.delete(tabId);
    }
    const fn = this.pending.get(tabId);
    if (fn !== undefined) {
      this.pending.delete(tabId);
      void fn();
    }
  }

  clear(tabId: number): void {
    const timer = this.timers.get(tabId);
    if (timer !== undefined) {
      clearTimeout(timer);
      this.timers.delete(tabId);
    }
    this.pending.delete(tabId);
  }
}
