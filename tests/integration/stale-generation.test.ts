import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const { mockLocalStorageData, mockSessionStorageData } = vi.hoisted(() => {
  const mockLocalStorageData: Record<string, unknown> = {};
  const mockSessionStorageData: Record<string, unknown> = {};

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
      query: vi.fn((_q: unknown, cb?: (tabs: unknown[]) => void) => {
        if (typeof cb === 'function') cb([]);
        return Promise.resolve([]);
      }),
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
      get: vi.fn((_name: string, cb?: (a: unknown) => void) => {
        if (cb) cb(null);
      }),
      create: vi.fn(),
      onAlarm: dummyEvent(),
    },
    sidePanel: {
      setPanelBehavior: vi.fn().mockResolvedValue(undefined),
    },
    permissions: {
      onRemoved: dummyEvent(),
      getAll: vi.fn().mockResolvedValue({ origins: [] }),
      contains: vi.fn((_p: unknown, cb?: (res: boolean) => void) => {
        if (typeof cb === 'function') cb(true);
        return Promise.resolve(true);
      }),
    },
    storage: {
      local: {
        get: vi.fn((keys?: unknown) => {
          if (keys === null || keys === undefined) return Promise.resolve({ ...mockLocalStorageData });
          if (typeof keys === 'string') return Promise.resolve({ [keys]: mockLocalStorageData[keys] });
          if (Array.isArray(keys)) {
            const res: Record<string, unknown> = {};
            for (const k of keys as string[]) {
              if (mockLocalStorageData[k] !== undefined) res[k] = mockLocalStorageData[k];
            }
            return Promise.resolve(res);
          }
          return Promise.resolve({ ...mockLocalStorageData });
        }),
        set: vi.fn((items: Record<string, unknown>) => {
          Object.assign(mockLocalStorageData, items);
          return Promise.resolve();
        }),
        remove: vi.fn((keys: string | string[]) => {
          const arr = Array.isArray(keys) ? keys : [keys];
          for (const k of arr) delete mockLocalStorageData[k];
          return Promise.resolve();
        }),
        clear: vi.fn(() => {
          for (const key of Object.keys(mockLocalStorageData)) delete mockLocalStorageData[key];
          return Promise.resolve();
        }),
      },
      session: {
        get: vi.fn((keys?: unknown) => {
          if (keys === null || keys === undefined) return Promise.resolve({ ...mockSessionStorageData });
          if (typeof keys === 'string') return Promise.resolve({ [keys]: mockSessionStorageData[keys] });
          if (Array.isArray(keys)) {
            const res: Record<string, unknown> = {};
            for (const k of keys as string[]) {
              if (mockSessionStorageData[k] !== undefined) res[k] = mockSessionStorageData[k];
            }
            return Promise.resolve(res);
          }
          return Promise.resolve({ ...mockSessionStorageData });
        }),
        set: vi.fn((items: Record<string, unknown>) => {
          Object.assign(mockSessionStorageData, items);
          return Promise.resolve();
        }),
        remove: vi.fn((keys: string | string[]) => {
          const arr = Array.isArray(keys) ? keys : [keys];
          for (const k of arr) delete mockSessionStorageData[k];
          return Promise.resolve();
        }),
        clear: vi.fn(() => {
          for (const key of Object.keys(mockSessionStorageData)) delete mockSessionStorageData[key];
          return Promise.resolve();
        }),
      },
    },
  };

  return { mockLocalStorageData, mockSessionStorageData };
});

import { hydrateFromSession, tabStates } from '../../src/background/lifecycle';
import {
  tabGenerations,
  getTabGeneration,
  incrementTabGeneration,
  clearTabGenerations,
  tabActionQueue,
} from '../../src/background/index';
import { SessionStorage } from '../../src/shared/storage';
import type { TabState } from '../../src/shared/types';

describe('Stale Generation Integration', () => {
  beforeEach(() => {
    for (const key of Object.keys(mockLocalStorageData)) delete mockLocalStorageData[key];
    for (const key of Object.keys(mockSessionStorageData)) delete mockSessionStorageData[key];
    tabStates.clear();
    clearTabGenerations();
    tabActionQueue.clearAll();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('restores navigation generation from session storage after SW restart and discards stale tasks', async () => {
    const tabId = 142;

    // Seed SessionStorage with a tab having navigationGeneration: 7
    const seededTabState: TabState = {
      tabId,
      navigationGeneration: 7,
      origin: 'https://example.com',
      url: 'https://example.com/checkout',
      hops: [],
      cookies: [],
      findings: [],
      grade: 'A',
      score: 95,
      qualityScore: 100,
      qualityGrade: 'A',
      scoreVersion: '1.0',
      scoreBreakdown: [],
      coverage: {
        hopsExpected: 1,
        hopsCaptured: 1,
        hasCache: false,
        hasServiceWorker: false,
        serviceWorkerStatus: 'unknown',
        serviceWorkerUrl: null,
        isRestricted: false,
        metaCspFound: false,
        blindSpots: [],
      },
      subdomainTrust: { hasEscalationPath: false, vectors: [] },
      monitoredByUser: true,
      updatedAt: Date.now(),
    };
    await SessionStorage.setTabState(seededTabState);

    // Verify generation counter is initially unhydrated (0)
    expect(getTabGeneration(tabId)).toBe(0);

    // Run hydrateFromSession() and assert getTabGeneration(tabId) is 7
    await hydrateFromSession();
    expect(getTabGeneration(tabId)).toBe(7);
    expect(tabGenerations.get(tabId)).toBe(7);

    // Verify incrementing tab generation yields 8
    const nextGen = incrementTabGeneration(tabId);
    expect(nextGen).toBe(8);
    expect(getTabGeneration(tabId)).toBe(8);

    // Verify an event tagged 7 is recognized as stale relative to generation 8
    let staleTaskExecuted = false;
    const staleResult = await tabActionQueue.enqueue(tabId, 7, () => {
      staleTaskExecuted = true;
      return Promise.resolve('stale-payload');
    });

    expect(staleResult).toBeUndefined();
    expect(staleTaskExecuted).toBe(false);

    // Verify an event tagged with the active generation 8 executes successfully
    let validTaskExecuted = false;
    const validResult = await tabActionQueue.enqueue(tabId, 8, () => {
      validTaskExecuted = true;
      return Promise.resolve('fresh-payload');
    });

    expect(validResult).toBe('fresh-payload');
    expect(validTaskExecuted).toBe(true);
  });

  it('correctly tracks and isolates multiple tabs across generations', async () => {
    const tabA = 201;
    const tabB = 202;

    await SessionStorage.setTabState({
      tabId: tabA,
      navigationGeneration: 3,
      origin: 'https://a.example.com',
      url: 'https://a.example.com/',
      hops: [],
      cookies: [],
      findings: [],
      grade: 'B',
      score: 80,
      qualityScore: 100,
      qualityGrade: 'A',
      scoreVersion: '1.0',
      scoreBreakdown: [],
      coverage: {
        hopsExpected: 1,
        hopsCaptured: 1,
        hasCache: false,
        hasServiceWorker: false,
        serviceWorkerStatus: 'unknown',
        serviceWorkerUrl: null,
        isRestricted: false,
        metaCspFound: false,
        blindSpots: [],
      },
      subdomainTrust: { hasEscalationPath: false, vectors: [] },
      monitoredByUser: true,
      updatedAt: Date.now(),
    });

    await SessionStorage.setTabState({
      tabId: tabB,
      navigationGeneration: 12,
      origin: 'https://b.example.com',
      url: 'https://b.example.com/',
      hops: [],
      cookies: [],
      findings: [],
      grade: 'A',
      score: 100,
      qualityScore: 100,
      qualityGrade: 'A',
      scoreVersion: '1.0',
      scoreBreakdown: [],
      coverage: {
        hopsExpected: 1,
        hopsCaptured: 1,
        hasCache: false,
        hasServiceWorker: false,
        serviceWorkerStatus: 'unknown',
        serviceWorkerUrl: null,
        isRestricted: false,
        metaCspFound: false,
        blindSpots: [],
      },
      subdomainTrust: { hasEscalationPath: false, vectors: [] },
      monitoredByUser: true,
      updatedAt: Date.now(),
    });

    await hydrateFromSession();

    expect(getTabGeneration(tabA)).toBe(3);
    expect(getTabGeneration(tabB)).toBe(12);

    incrementTabGeneration(tabA);
    expect(getTabGeneration(tabA)).toBe(4);
    expect(getTabGeneration(tabB)).toBe(12);
  });
});
