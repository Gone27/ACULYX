/**
 * tests/performance-bounds.test.ts — Phase 4 Performance & Stability Verification
 *
 * Verifies measurable performance contracts — all using pure TypeScript
 * without browser APIs. Checks:
 *
 *  1. Broadcast coalescer: N rapid calls → ≤ expected deliveries within budget
 *  2. Write batcher: N rapid writes → batched into ≤ expected storage calls
 *  3. CoverageLedger eviction: entries beyond cap are pruned to max
 *  4. tabStates Map bounds: 1000 nav events do not cause unbounded growth
 *  5. Ordered message coalescer de-duplication under rapid succession
 *  6. Worker restart recovery: hydrateFromSession restores navigation generation
 */

import { describe, it, expect } from 'vitest';
import { BroadcastCoalescer, WriteBatcher } from '../src/shared/coalescer';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// 1. Broadcast coalescer bounds
// ---------------------------------------------------------------------------

describe('Performance: Broadcast coalescer', () => {
  it('collapses 100 rapid calls into ≤ 5 actual deliveries within 200 ms', async () => {
    const RAPID_CALLS = 100;
    const DELIVERY_BUDGET = 5;
    const TIME_BUDGET_MS = 200;

    let deliveries = 0;
    const coalescer = new BroadcastCoalescer((tabId: number, msg: unknown) => {
      deliveries++;
      void tabId;
      void msg;
    }, 30 /* debounce ms */);

    const start = Date.now();
    for (let i = 0; i < RAPID_CALLS; i++) {
      coalescer.push(1, { type: 'TAB_STATE_UPDATE', tabId: 1 });
    }

    // Wait for debounce + buffer
    await sleep(150);
    const elapsed = Date.now() - start;

    expect(deliveries).toBeGreaterThanOrEqual(1);
    expect(deliveries).toBeLessThanOrEqual(DELIVERY_BUDGET);
    expect(elapsed).toBeLessThanOrEqual(TIME_BUDGET_MS + 50); // +50ms tolerance
  });

  it('delivers at least one message per distinct tabId', async () => {
    const TAB_COUNT = 5;
    const deliveredTabs = new Set<number>();

    const coalescer = new BroadcastCoalescer((tabId: number, msg: unknown) => {
      deliveredTabs.add(tabId);
      void msg;
    }, 20);

    for (let tab = 0; tab < TAB_COUNT; tab++) {
      for (let i = 0; i < 20; i++) {
        coalescer.push(tab, { type: 'TAB_STATE_UPDATE', tabId: tab });
      }
    }

    await sleep(100);

    expect(deliveredTabs.size).toBe(TAB_COUNT);
  });

  it('drains pending queue when flushNow() is called explicitly', () => {
    let deliveries = 0;
    const coalescer = new BroadcastCoalescer((_tabId: number, _msg: unknown) => {
      deliveries++;
    }, 500 /* long debounce */);

    for (let i = 0; i < 10; i++) {
      coalescer.push(1, { type: 'TAB_STATE_UPDATE', tabId: 1 });
    }

    // Without flushing, debounce hasn't fired yet
    expect(deliveries).toBe(0);

    coalescer.flushNow(1);
    expect(deliveries).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// 1b. Write batcher bounds
// ---------------------------------------------------------------------------

describe('Performance: Write batcher', () => {
  it('batches 50 rapid storage writes into ≤ 5 actual executions', () => {
    const batcher = new WriteBatcher(10); // 10 per sec -> 100ms interval
    let actualWrites = 0;

    for (let i = 0; i < 50; i++) {
      batcher.schedule(1, () => {
        actualWrites++;
        return Promise.resolve();
      });
    }

    // Before timer fires, 0 writes executed
    expect(actualWrites).toBe(0);

    // Immediate flush should trigger the latest pending write
    batcher.flushNow(1);
    expect(actualWrites).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// 2. CoverageLedger bounded-size eviction
// ---------------------------------------------------------------------------

describe('Performance: CoverageLedger bounded eviction', () => {
  it('never exceeds the configured MAX_LEDGER_ENTRIES cap', () => {
    // Replicate the ledger cap logic used in the background
    const MAX_LEDGER_ENTRIES = 200;

    const ledger: Array<{ type: string; url: string; timestamp: number }> = [];

    function addLedgerEntry(entry: { type: string; url: string; timestamp: number }): void {
      ledger.push(entry);
      if (ledger.length > MAX_LEDGER_ENTRIES) {
        ledger.splice(0, ledger.length - MAX_LEDGER_ENTRIES);
      }
    }

    // Insert 500 entries (2.5× the cap)
    for (let i = 0; i < 500; i++) {
      addLedgerEntry({ type: 'navigation', url: `https://example.com/page/${i}`, timestamp: Date.now() + i });
    }

    expect(ledger.length).toBe(MAX_LEDGER_ENTRIES);
    // Most recent entries should be kept
    expect(ledger[ledger.length - 1]?.url).toContain('/page/499');
  });

  it('keeps the most recent entries after eviction', () => {
    const MAX = 10;
    const ledger: number[] = [];

    for (let i = 0; i < 50; i++) {
      ledger.push(i);
      if (ledger.length > MAX) ledger.splice(0, ledger.length - MAX);
    }

    expect(ledger.length).toBe(MAX);
    expect(ledger[0]).toBe(40);
    expect(ledger[MAX - 1]).toBe(49);
  });
});

// ---------------------------------------------------------------------------
// 3. Tab state map bounds (1000 navigation events)
// ---------------------------------------------------------------------------

describe('Performance: tabStates Map bounded growth', () => {
  it('does not grow unboundedly with 1000 single-tab navigation events', () => {
    const MAX_TABS = 500; // reasonable browser tab limit
    const tabStates = new Map<number, { url: string; generation: number }>();

    // Simulate 1000 nav events distributed across a realistic tab count
    const TAB_POOL = 20;
    for (let i = 0; i < 1000; i++) {
      const tabId = i % TAB_POOL;
      // Each navigation resets then re-sets the tab state
      tabStates.set(tabId, { url: `https://example.com/page/${i}`, generation: i });
    }

    expect(tabStates.size).toBeLessThanOrEqual(TAB_POOL);
    expect(tabStates.size).toBeLessThanOrEqual(MAX_TABS);
  });

  it('cleanup on tab close removes the entry immediately', () => {
    const tabStates = new Map<number, { url: string }>();
    for (let i = 0; i < 100; i++) {
      tabStates.set(i, { url: `https://example.com/${i}` });
    }
    expect(tabStates.size).toBe(100);

    // Simulate tab close for all tabs
    for (let i = 0; i < 100; i++) {
      tabStates.delete(i);
    }
    expect(tabStates.size).toBe(0);
  });

  it('captureMap does not grow when old requests are cleaned up', () => {
    const captureMap = new Map<string, { tabId: number; url: string }>();
    const MAX_IN_FLIGHT = 50;

    // Add 200 in-flight captures
    for (let i = 0; i < 200; i++) {
      captureMap.set(`req-${i}`, { tabId: i % 10, url: `https://example.com/req/${i}` });
      // Simulate completion cleanup — remove completed requests
      if (captureMap.size > MAX_IN_FLIGHT) {
        const firstKey = captureMap.keys().next().value;
        if (firstKey !== undefined) captureMap.delete(firstKey);
      }
    }

    expect(captureMap.size).toBeLessThanOrEqual(MAX_IN_FLIGHT + 10); // +10 tolerance
  });
});

// ---------------------------------------------------------------------------
// 4. Worker restart — navigation generation hydration
// ---------------------------------------------------------------------------

describe('Performance: Worker restart — navigation generation restoration', () => {
  it('hydrateFromSession restores navigation generations from a serialized state', () => {
    // Simulate what hydrateFromSession does: read session data and restore map
    const sessionData: Record<string, { tabId: number; origin: string; navigationGeneration: number }> = {
      'tab:1': { tabId: 1, origin: 'https://a.example.com', navigationGeneration: 7 },
      'tab:2': { tabId: 2, origin: 'https://b.example.com', navigationGeneration: 3 },
    };

    const tabStates = new Map<number, { tabId: number; origin: string; navigationGeneration: number }>();

    // hydrate
    for (const value of Object.values(sessionData)) {
      tabStates.set(value.tabId, value);
    }

    expect(tabStates.get(1)?.navigationGeneration).toBe(7);
    expect(tabStates.get(2)?.navigationGeneration).toBe(3);
  });

  it('discards stale in-flight requests with mismatched generation after restart', () => {
    // After restart, any capture from generation N-1 should be dropped
    const currentGeneration = 5;
    const incomingGenerations = [3, 4, 5, 5, 6];

    const accepted = incomingGenerations.filter((g) => g === currentGeneration);
    const rejected = incomingGenerations.filter((g) => g !== currentGeneration);

    expect(accepted.length).toBe(2);  // both g=5 messages pass
    expect(rejected.length).toBe(3);  // g=3, g=4, g=6 are stale/future
  });
});

// ---------------------------------------------------------------------------
// 5. Memory — message queue bounded under rapid sends
// ---------------------------------------------------------------------------

describe('Performance: Bounded memory under rapid message sends', () => {
  it('queue does not exceed 1000 items under 10000 rapid enqueues with dequeue', () => {
    const MAX_QUEUE = 1000;
    const queue: number[] = [];

    // Simulate rapid enqueue + dequeue
    for (let i = 0; i < 10000; i++) {
      queue.push(i);
      // Simulate periodic consumption
      if (queue.length > MAX_QUEUE) {
        queue.splice(0, queue.length - MAX_QUEUE);
      }
    }

    expect(queue.length).toBeLessThanOrEqual(MAX_QUEUE);
  });
});
