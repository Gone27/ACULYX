import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { BroadcastCoalescer, WriteBatcher } from '../../src/shared/coalescer';

describe('BroadcastCoalescer (WS3 Performance)', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('coalesces rapid pushes and flushes the latest value after interval', () => {
    const flushed: Array<{ tabId: number; val: string }> = [];
    const coalescer = new BroadcastCoalescer<string>((tabId, val) => {
      flushed.push({ tabId, val });
    }, 100);

    coalescer.push(1, 'state-1');
    coalescer.push(1, 'state-2');
    coalescer.push(1, 'state-final');

    expect(flushed).toHaveLength(0);

    vi.advanceTimersByTime(100);

    expect(flushed).toHaveLength(1);
    expect(flushed[0]).toEqual({ tabId: 1, val: 'state-final' });
  });

  it('flushNow immediately emits pending value and cancels timer', () => {
    const flushed: Array<{ tabId: number; val: string }> = [];
    const coalescer = new BroadcastCoalescer<string>((tabId, val) => {
      flushed.push({ tabId, val });
    }, 100);

    coalescer.push(2, 'immediate-state');
    expect(flushed).toHaveLength(0);

    coalescer.flushNow(2);
    expect(flushed).toHaveLength(1);
    expect(flushed[0]).toEqual({ tabId: 2, val: 'immediate-state' });

    // Ensure timer expiration does not double-fire
    vi.advanceTimersByTime(150);
    expect(flushed).toHaveLength(1);
  });

  it('clear cancels pending flush without emitting', () => {
    const flushed: Array<{ tabId: number; val: string }> = [];
    const coalescer = new BroadcastCoalescer<string>((tabId, val) => {
      flushed.push({ tabId, val });
    }, 100);

    coalescer.push(3, 'cancelled-state');
    coalescer.clear(3);

    vi.advanceTimersByTime(200);
    expect(flushed).toHaveLength(0);
  });

  it('handles multiple tabs independently', () => {
    const flushed: Array<{ tabId: number; val: string }> = [];
    const coalescer = new BroadcastCoalescer<string>((tabId, val) => {
      flushed.push({ tabId, val });
    }, 100);

    coalescer.push(10, 'tab10-v1');
    coalescer.push(20, 'tab20-v1');
    coalescer.push(10, 'tab10-v2');

    vi.advanceTimersByTime(50);
    coalescer.flushNow(20);

    expect(flushed).toEqual([{ tabId: 20, val: 'tab20-v1' }]);

    vi.advanceTimersByTime(50);
    expect(flushed).toEqual([
      { tabId: 20, val: 'tab20-v1' },
      { tabId: 10, val: 'tab10-v2' },
    ]);
  });
});

describe('WriteBatcher (WS3 Performance)', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('batches rapid writes and executes only the latest scheduled write', async () => {
    const writes: string[] = [];
    const batcher = new WriteBatcher(2); // minIntervalMs = 500

    batcher.schedule(1, async () => {
      await Promise.resolve();
      writes.push('write-1');
    });
    batcher.schedule(1, async () => {
      await Promise.resolve();
      writes.push('write-2');
    });
    batcher.schedule(1, async () => {
      await Promise.resolve();
      writes.push('write-final');
    });

    expect(writes).toHaveLength(0);

    await vi.advanceTimersByTimeAsync(500);

    expect(writes).toEqual(['write-final']);
  });

  it('flushNow executes the pending write immediately', async () => {
    const writes: string[] = [];
    const batcher = new WriteBatcher(2);

    batcher.schedule(2, async () => {
      await Promise.resolve();
      writes.push('flushed-write');
    });

    batcher.flushNow(2);
    await Promise.resolve();
    expect(writes).toEqual(['flushed-write']);

    await vi.advanceTimersByTimeAsync(600);
    expect(writes).toEqual(['flushed-write']);
  });

  it('clear cancels the pending write without executing', async () => {
    const writes: string[] = [];
    const batcher = new WriteBatcher(2);

    batcher.schedule(3, async () => {
      await Promise.resolve();
      writes.push('cancelled-write');
    });

    batcher.clear(3);
    await vi.advanceTimersByTimeAsync(600);
    expect(writes).toHaveLength(0);
  });
});
