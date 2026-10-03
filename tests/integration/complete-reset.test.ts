import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const { mockLocalStorageData, mockSessionStorageData, onMessageListeners } = vi.hoisted(() => {
  const mockLocalStorageData: Record<string, unknown> = {};
  const mockSessionStorageData: Record<string, unknown> = {};
  const onMessageListeners: Array<
    (message: unknown, sender: unknown, sendResponse: (res: unknown) => void) => boolean | void
  > = [];

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
      id: 'mock-extension-id',
      onConnect: dummyEvent(),
      onMessage: {
        addListener: vi.fn((listener: (m: unknown, s: unknown, r: (res: unknown) => void) => boolean | void) => {
          onMessageListeners.push(listener);
        }),
        removeListener: vi.fn(),
        hasListener: vi.fn(),
      },
      getURL: vi.fn((path: string) => `chrome-extension://mock-extension-id/${path}`),
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

  return { mockLocalStorageData, mockSessionStorageData, onMessageListeners };
});

import {
  executeResetAllData,
  tabGenerations,
  badgeTrackedTabs,
} from '../../src/background/index';
import { tabStates, originAuthBaselines } from '../../src/background/lifecycle';
import {
  captureMap,
  inFlightRequests,
  incognitoTabIds,
  isCaptureActiveForUrl,
} from '../../src/background/capture';
import type { PartialCapture } from '../../src/background/capture';
import { CapturePolicy } from '../../src/background/capture-policy';
import { LocalStorage } from '../../src/shared/storage';
import { DEFAULT_SETTINGS } from '../../src/shared/constants';
import type { TabState, AuthBaseline } from '../../src/shared/types';

describe('Complete Reset Integration', () => {
  beforeEach(() => {
    for (const key of Object.keys(mockLocalStorageData)) delete mockLocalStorageData[key];
    for (const key of Object.keys(mockSessionStorageData)) delete mockSessionStorageData[key];
    tabStates.clear();
    originAuthBaselines.clear();
    captureMap.clear();
    inFlightRequests.clear();
    incognitoTabIds.clear();
    tabGenerations.clear();
    badgeTrackedTabs.clear();
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('immediately switches CapturePolicy snapshot to off and rejects traffic mid-reset', async () => {
    // 1. Configure active monitoring snapshot
    CapturePolicy.setSnapshotForTesting({
      ready: true,
      revision: 1,
      mode: 'all-sites',
      broadGrantActive: true,
      grantedOrigins: new Set(),
    });

    // Verify traffic is permitted before reset
    expect(isCaptureActiveForUrl('https://example.com/checkout')).toBe(true);

    // 2. Populate in-memory state and persistent stores
    const dummyState: TabState = {
      tabId: 10,
      navigationGeneration: 4,
      origin: 'https://example.com',
      url: 'https://example.com/checkout',
      hops: [],
      cookies: [],
      findings: [],
      grade: 'B',
      score: 75,
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
    tabStates.set(10, dummyState);
    tabGenerations.set(10, 4);
    badgeTrackedTabs.add(10);
    incognitoTabIds.add(10);

    const dummyPartial: PartialCapture = {
      tabId: 10,
      url: 'https://example.com/checkout',
      status: 200,
      headersReceived: null,
      rawHeadersReceived: [],
      headersStarted: null,
      rawHeadersStarted: [],
      fromCache: false,
      wasRedirected: false,
      timestamp: Date.now(),
      redirectCount: 0,
      generation: 4,
    };
    captureMap.set('req-pending', dummyPartial);

    inFlightRequests.set('req-xhr-pending', {
      method: 'POST',
      origin: 'https://example.com',
      timestamp: Date.now(),
      generation: 4,
    });

    const dummyBaseline: AuthBaseline = {
      origin: 'https://example.com',
      score: 80,
      grade: 'B',
      cookies: [],
      findings: [],
      hasSensitiveCookie: false,
      timestamp: Date.now(),
    };
    originAuthBaselines.set('https://example.com#tab:10', dummyBaseline);

    await LocalStorage.recordOriginHistory('https://example.com', {
      timestamp: Date.now(),
      score: 75,
      grade: 'B',
    });

    // 3. Initiate full reset
    const resetPromise = executeResetAllData();

    // Verify SYNCHRONOUS fail-closed gate: CapturePolicy is switched to 'off' FIRST
    const immediateSnapshot = CapturePolicy.getSnapshot();
    expect(immediateSnapshot.mode).toBe('off');

    // Any traffic arriving mid-reset must be rejected immediately at the boundary
    expect(isCaptureActiveForUrl('https://example.com/checkout')).toBe(false);
    expect(isCaptureActiveForUrl('https://any-other-site.com/')).toBe(false);

    // Verify synchronous clearing of all in-memory structures
    expect(tabStates.size).toBe(0);
    expect(originAuthBaselines.size).toBe(0);
    expect(captureMap.size).toBe(0);
    expect(inFlightRequests.size).toBe(0);
    expect(incognitoTabIds.size).toBe(0);
    expect(tabGenerations.size).toBe(0);

    // 4. Await full async completion
    await resetPromise;

    // Badges must be cleared across tabs
    expect(chrome.action.setBadgeText).toHaveBeenCalledWith({ text: '' });

    // LocalStorage must have no residual history or graph data
    const localKeys = Object.keys(mockLocalStorageData).filter(
      (k) => k.startsWith('history:') || k.startsWith('auth_diff:') || k.startsWith('graph:'),
    );
    expect(localKeys).toHaveLength(0);

    // Settings must be reset to defaults with monitoringMode 'off'
    const finalSettings = await LocalStorage.getSettings();
    expect(finalSettings.monitoringMode).toBe('off');
    expect(finalSettings).toEqual({ ...DEFAULT_SETTINGS, monitoringMode: 'off' });
  });

  it('handles RESET_ALL_DATA extension message with fail-closed gate and success response', async () => {
    CapturePolicy.setSnapshotForTesting({
      ready: true,
      revision: 2,
      mode: 'all-sites',
      broadGrantActive: true,
      grantedOrigins: new Set(),
    });

    expect(isCaptureActiveForUrl('https://secure.example.com')).toBe(true);

    const onMessageListener = onMessageListeners.at(-1);
    expect(onMessageListener).toBeDefined();

    const sender = {
      id: 'mock-extension-id',
      url: 'chrome-extension://mock-extension-id/options.html',
    };

    let responseResult: unknown;
    if (onMessageListener !== undefined) {
      const handled = onMessageListener(
        { type: 'RESET_ALL_DATA' },
        sender,
        (res: unknown) => {
          responseResult = res;
        },
      );
      expect(handled).toBe(true);
    }

    // Gate must immediately flip to 'off'
    expect(CapturePolicy.getSnapshot().mode).toBe('off');
    expect(isCaptureActiveForUrl('https://secure.example.com')).toBe(false);

    // Wait a tick for async completion
    await new Promise((r) => setTimeout(r, 50));

    expect(responseResult).toEqual({
      type: 'RESET_ALL_DATA_RESPONSE',
      success: true,
    });
  });
});
