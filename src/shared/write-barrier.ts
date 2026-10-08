/**
 * write-barrier.ts
 *
 * Provides shared synchronization, write barrier, and epoch tracking
 * for all storage and settings operations across the extension.
 * Eliminates race conditions during full data reset and guarantees
 * linearizability across async tasks without circular imports.
 */

// ─── Keyed Asynchronous Mutex ────────────────────────────────────────────────
// Serializes read-modify-write operations per tab, origin, or apex domain
// to eliminate lost history records, auth baselines, and graph updates.

export class KeyedAsyncMutex {
  private locks = new Map<string, Promise<void>>();

  async runExclusive<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const currentLock = this.locks.get(key) ?? Promise.resolve();
    let release!: () => void;
    const nextLock = new Promise<void>((resolve) => {
      release = resolve;
    });
    const tail = currentLock.then(() => nextLock, () => nextLock);
    this.locks.set(key, tail);

    try {
      await currentLock;
      return await fn();
    } finally {
      release();
      if (this.locks.get(key) === tail) {
        this.locks.delete(key);
      }
    }
  }

  isLocked(key: string): boolean {
    return this.locks.has(key);
  }
}

export const storageMutex = new KeyedAsyncMutex();

// ─── Storage Write Barrier & Reset Epoch ────────────────────────────────────
// Linearizes all in-flight and future storage mutations against full reset.
// Ensures that pre-reset writes cannot finish after storage clear and recreate data.

export class StorageWriteBarrier {
  private activeWrites = new Set<Promise<unknown>>();
  private barrierPromise: Promise<void> | null = null;
  private releaseBarrier: (() => void) | null = null;

  async enter(): Promise<void> {
    if (this.barrierPromise !== null) {
      await this.barrierPromise;
    }
  }

  track<T>(promise: Promise<T>): Promise<T> {
    this.activeWrites.add(promise);
    const cleanup = () => {
      this.activeWrites.delete(promise);
    };
    promise.then(cleanup, cleanup);
    return promise;
  }

  async closeBarrierAndDrain(): Promise<void> {
    if (this.barrierPromise === null) {
      let release!: () => void;
      this.barrierPromise = new Promise<void>((resolve) => {
        release = resolve;
      });
      this.releaseBarrier = release;
    }
    while (this.activeWrites.size > 0) {
      await Promise.allSettled(Array.from(this.activeWrites));
    }
  }

  openBarrier(): void {
    if (this.releaseBarrier !== null) {
      const release = this.releaseBarrier;
      this.releaseBarrier = null;
      this.barrierPromise = null;
      release();
    }
  }

  isClosed(): boolean {
    return this.barrierPromise !== null;
  }

  getActiveCount(): number {
    return this.activeWrites.size;
  }
}

export const storageWriteBarrier = new StorageWriteBarrier();

let storageResetEpoch = 0;
type EpochChangeListener = (newEpoch: number) => void;
const epochChangeListeners = new Set<EpochChangeListener>();

export function onEpochChange(listener: EpochChangeListener): () => void {
  epochChangeListeners.add(listener);
  return () => {
    epochChangeListeners.delete(listener);
  };
}

function notifyEpochChange(): void {
  for (const listener of epochChangeListeners) {
    try {
      listener(storageResetEpoch);
    } catch {
      // Ignore listener errors during notification
    }
  }
}

export function getStorageResetEpoch(): number {
  return storageResetEpoch;
}

export function setStorageResetEpoch(epoch: number): void {
  storageResetEpoch = epoch;
  notifyEpochChange();
}

export function incrementStorageResetEpoch(): number {
  storageResetEpoch++;
  notifyEpochChange();
  return storageResetEpoch;
}

export function isStorageEpochStale(epoch?: number): boolean {
  if (epoch === undefined) return false;
  return epoch !== storageResetEpoch;
}
