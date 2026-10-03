import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';

vi.hoisted(() => {
  const dummyEvent = () => ({
    addListener: vi.fn(),
    removeListener: vi.fn(),
    hasListener: vi.fn(),
  });
  (globalThis as unknown as { chrome: unknown }).chrome = {
    webNavigation: {
      onBeforeNavigate: dummyEvent(),
      onCommitted: dummyEvent(),
      onHistoryStateUpdated: dummyEvent(),
    },
    webRequest: {
      onBeforeSendHeaders: dummyEvent(),
      onHeadersReceived: dummyEvent(),
      onResponseStarted: dummyEvent(),
      onBeforeRedirect: dummyEvent(),
      onErrorOccurred: dummyEvent(),
      onCompleted: dummyEvent(),
    },
    cookies: {
      onChanged: dummyEvent(),
      getAll: vi.fn().mockResolvedValue([]),
    },
    tabs: {
      onRemoved: dummyEvent(),
      query: vi.fn((_q: unknown, cb: (tabs: unknown[]) => void) => cb([])),
      get: vi.fn(),
      create: vi.fn().mockResolvedValue({}),
    },
    runtime: {
      onConnect: dummyEvent(),
      onMessage: dummyEvent(),
      getURL: vi.fn((path: string) => `chrome-extension://mock/${path}`),
    },
    action: {
      setBadgeText: vi.fn().mockResolvedValue(undefined),
      setBadgeBackgroundColor: vi.fn().mockResolvedValue(undefined),
    },
    alarms: {
      get: vi.fn((_name: string, cb?: (a: unknown) => void) => { if (cb) cb(null); }),
      create: vi.fn(),
      onAlarm: dummyEvent(),
    },
    sidePanel: {
      setPanelBehavior: vi.fn().mockResolvedValue(undefined),
    },
    permissions: {
      onRemoved: dummyEvent(),
      getAll: vi.fn().mockResolvedValue({ origins: [] }),
    },
    storage: {
      local: {
        get: vi.fn().mockResolvedValue({}),
        set: vi.fn().mockResolvedValue(undefined),
        remove: vi.fn().mockResolvedValue(undefined),
      },
      session: {
        get: vi.fn().mockResolvedValue({}),
        set: vi.fn().mockResolvedValue(undefined),
        remove: vi.fn().mockResolvedValue(undefined),
      },
    },
  };
});

import {
  TabActionQueue,
  getTabGeneration,
  incrementTabGeneration,
  tabGenerations,
  isDuplicateEvent,
  pruneTransientStructures,
} from '../../src/background/index';
import { captureMap, inFlightRequests } from '../../src/background/capture';
import {
  correlateCookies,
  resetInFlightCorrelationsForTesting,
  MAX_COOKIE_RECORDS,
  MAX_UNOBSERVED_FINDINGS,
} from '../../src/background/correlate';

describe('Tab Navigation Generation Tracking', () => {
  beforeEach(() => {
    tabGenerations.clear();
  });

  it('defaults to generation 0 for an unknown tab', () => {
    expect(getTabGeneration(99)).toBe(0);
  });

  it('monotonically increments generation on navigation', () => {
    expect(incrementTabGeneration(1)).toBe(1);
    expect(getTabGeneration(1)).toBe(1);
    expect(incrementTabGeneration(1)).toBe(2);
    expect(getTabGeneration(1)).toBe(2);
  });

  it('maintains independent generation counts per tab', () => {
    incrementTabGeneration(1);
    incrementTabGeneration(1);
    incrementTabGeneration(2);

    expect(getTabGeneration(1)).toBe(2);
    expect(getTabGeneration(2)).toBe(1);
    expect(getTabGeneration(3)).toBe(0);
  });
});

describe('TabActionQueue (Ordered per-tab pipeline)', () => {
  beforeEach(() => {
    tabGenerations.clear();
  });

  it('processes actions for the same tab in strict sequential order', async () => {
    const queue = new TabActionQueue();
    const tabId = 10;
    const executionOrder: number[] = [];

    const p1 = queue.enqueue(tabId, 0, async () => {
      await new Promise((r) => setTimeout(r, 20));
      executionOrder.push(1);
      return 1;
    });

    const p2 = queue.enqueue(tabId, 0, async () => {
      await Promise.resolve();
      executionOrder.push(2);
      return 2;
    });

    const p3 = queue.enqueue(tabId, 0, async () => {
      await Promise.resolve();
      executionOrder.push(3);
      return 3;
    });

    const [r1, r2, r3] = await Promise.all([p1, p2, p3]);
    expect(executionOrder).toEqual([1, 2, 3]);
    expect(r1).toBe(1);
    expect(r2).toBe(2);
    expect(r3).toBe(3);
  });

  it('discards late arrivals whose generation does not match current tab generation', async () => {
    const queue = new TabActionQueue();
    const tabId = 20;
    incrementTabGeneration(tabId); // Gen is now 1

    let executedOld = false;
    // Enqueue an action tagged with older generation 0
    const resultOld = await queue.enqueue(tabId, 0, async () => {
      await Promise.resolve();
      executedOld = true;
      return 'old';
    });

    expect(executedOld).toBe(false);
    expect(resultOld).toBeUndefined();

    // Enqueue an action tagged with current generation 1
    let executedCurrent = false;
    const resultCurrent = await queue.enqueue(tabId, 1, async () => {
      await Promise.resolve();
      executedCurrent = true;
      return 'current';
    });

    expect(executedCurrent).toBe(true);
    expect(resultCurrent).toBe('current');
  });

  it('allows actions for different tabs to proceed concurrently', async () => {
    const queue = new TabActionQueue();
    let tab2FinishedFirst = false;

    const pTab1 = queue.enqueue(1, 0, async () => {
      await new Promise((r) => setTimeout(r, 40));
    });

    const pTab2 = queue.enqueue(2, 0, async () => {
      await Promise.resolve();
      tab2FinishedFirst = true;
    });

    await pTab2;
    expect(tab2FinishedFirst).toBe(true);
    await pTab1;
  });

  it('clearTab allows new actions without deadlocking', async () => {
    const queue = new TabActionQueue();
    const tabId = 30;

    queue.clearTab(tabId);
    const result = await queue.enqueue(tabId, 0, async () => {
      await Promise.resolve();
      return 'ok';
    });
    expect(result).toBe('ok');
  });
});

describe('Message and Event Deduplication (isDuplicateEvent)', () => {
  it('identifies new events as non-duplicates and repeats as duplicates', () => {
    const eventId = 'test-event-1';
    const now = 1000;

    expect(isDuplicateEvent(eventId, now)).toBe(false);
    expect(isDuplicateEvent(eventId, now + 1000)).toBe(true);
  });

  it('allows re-processing after TTL expiration (60 seconds)', () => {
    const eventId = 'ttl-event';
    const start = 1000;

    expect(isDuplicateEvent(eventId, start)).toBe(false);
    expect(isDuplicateEvent(eventId, start + 30_000)).toBe(true);
    // After 60s TTL, event should be accepted again
    expect(isDuplicateEvent(eventId, start + 61_000)).toBe(false);
  });

  it('enforces maximum capacity cap (150) by evicting oldest events', () => {
    const baseTime = 10_000;
    // Fill with 150 unique events
    for (let i = 0; i < 150; i++) {
      expect(isDuplicateEvent(`event-${i}`, baseTime + i)).toBe(false);
    }

    // Adding event 151 triggers eviction of oldest event-0
    expect(isDuplicateEvent('event-150', baseTime + 200)).toBe(false);

    // event-0 was evicted, so it can be re-recorded
    expect(isDuplicateEvent('event-0', baseTime + 201)).toBe(false);
  });
});

describe('Transient structures bounds (pruneTransientStructures)', () => {
  beforeEach(() => {
    captureMap.clear();
    inFlightRequests.clear();
  });

  afterEach(() => {
    captureMap.clear();
    inFlightRequests.clear();
  });

  it('prunes entries older than 60 seconds from captureMap and inFlightRequests', () => {
    const now = 100_000;
    const staleTime = now - 65_000; // 65 seconds old
    const freshTime = now - 10_000; // 10 seconds old

    captureMap.set('req-stale', {
      tabId: 1,
      url: 'https://a.com',
      status: 200,
      headersReceived: null,
      rawHeadersReceived: [],
      headersStarted: null,
      rawHeadersStarted: [],
      fromCache: false,
      wasRedirected: false,
      timestamp: staleTime,
      redirectCount: 0,
    });

    captureMap.set('req-fresh', {
      tabId: 1,
      url: 'https://b.com',
      status: 200,
      headersReceived: null,
      rawHeadersReceived: [],
      headersStarted: null,
      rawHeadersStarted: [],
      fromCache: false,
      wasRedirected: false,
      timestamp: freshTime,
      redirectCount: 0,
    });

    inFlightRequests.set('xhr-stale', {
      method: 'GET',
      origin: 'https://a.com',
      timestamp: staleTime,
    });

    inFlightRequests.set('xhr-fresh', {
      method: 'POST',
      origin: 'https://b.com',
      timestamp: freshTime,
    });

    pruneTransientStructures(now);

    expect(captureMap.has('req-stale')).toBe(false);
    expect(captureMap.has('req-fresh')).toBe(true);

    expect(inFlightRequests.has('xhr-stale')).toBe(false);
    expect(inFlightRequests.has('xhr-fresh')).toBe(true);
  });

  it('caps captureMap and inFlightRequests to 100 entries', () => {
    const now = 200_000;
    for (let i = 0; i < 120; i++) {
      captureMap.set(`req-${i}`, {
        tabId: 1,
        url: `https://test${i}.com`,
        status: 200,
        headersReceived: null,
        rawHeadersReceived: [],
        headersStarted: null,
        rawHeadersStarted: [],
        fromCache: false,
        wasRedirected: false,
        timestamp: now,
        redirectCount: 0,
      });

      inFlightRequests.set(`xhr-${i}`, {
        method: 'GET',
        origin: `https://test${i}.com`,
        timestamp: now,
      });
    }

    pruneTransientStructures(now);

    expect(captureMap.size).toBeLessThanOrEqual(100);
    expect(inFlightRequests.size).toBeLessThanOrEqual(100);
  });
});

describe('correlateCookies generation awareness and bounding', () => {
  beforeEach(() => {
    resetInFlightCorrelationsForTesting();
    (globalThis as unknown as { chrome: unknown }).chrome = {
      cookies: {
        getAll: vi.fn().mockResolvedValue([
          {
            name: 'sess',
            value: '123',
            domain: '.example.com',
            path: '/',
            secure: true,
            httpOnly: true,
            sameSite: 'lax',
          },
        ]),
      },
    };
  });

  it('returns valid cookie records when navigation generation is current', async () => {
    const res = await correlateCookies(
      1,
      'https://example.com/',
      ['sess=123; Secure; HttpOnly; SameSite=Lax'],
      1,
      () => true,
    );

    expect(res.discarded).toBeUndefined();
    expect(res.records.length).toBeGreaterThan(0);
    expect(res.records[0]?.name).toBe('sess');
  });

  it('discards correlation if tab generation is superseded before query begins', async () => {
    const res = await correlateCookies(
      1,
      'https://example.com/',
      ['sess=123; Secure; HttpOnly'],
      1,
      () => false, // Tab already navigated to gen 2
    );

    expect(res.discarded).toBe(true);
    expect(res.records).toHaveLength(0);
    expect(res.findings).toHaveLength(0);
  });

  it('discards correlation if tab generation changes while chrome.cookies.getAll is awaiting', async () => {
    let currentGen = 1;
    (globalThis as unknown as { chrome: { cookies: { getAll: unknown } } }).chrome.cookies.getAll = vi
      .fn()
      .mockImplementation(async () => {
        await Promise.resolve();
        // Simulating navigation happening mid-query
        currentGen = 2;
        return [];
      });

    const res = await correlateCookies(
      1,
      'https://example.com/',
      ['sess=123'],
      1,
      (_t, g) => g === currentGen,
    );

    expect(res.discarded).toBe(true);
    expect(res.records).toHaveLength(0);
  });

  it('bounds set-cookie headers to MAX_SET_COOKIES (100)', async () => {
    const headers = Array.from({ length: 150 }, (_, i) => `c${i}=val; Secure; HttpOnly`);
    const res = await correlateCookies(1, 'https://example.com/', headers);

    expect(res.records.length).toBeLessThanOrEqual(MAX_COOKIE_RECORDS);
    expect(res.findings.length).toBeLessThanOrEqual(MAX_UNOBSERVED_FINDINGS);
  });

  it('deduplicates concurrent in-flight correlations for the same tab and url', async () => {
    const getAllSpy = vi.fn().mockImplementation(async () => {
      await new Promise((r) => setTimeout(r, 10));
      return [];
    });
    (globalThis as unknown as { chrome: { cookies: { getAll: unknown } } }).chrome.cookies.getAll = getAllSpy;

    const p1 = correlateCookies(5, 'https://dedup.example/', ['a=1']);
    const p2 = correlateCookies(5, 'https://dedup.example/', ['b=2']);

    const [r1, r2] = await Promise.all([p1, p2]);
    // Both callers get results, but chrome.cookies.getAll is invoked only once
    expect(getAllSpy).toHaveBeenCalledTimes(1);
    expect(r1.records).toEqual(r2.records);
  });
});
