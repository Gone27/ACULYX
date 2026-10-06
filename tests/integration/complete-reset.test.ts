import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Mock } from 'vitest';

const { mockLocalStorageData, mockSessionStorageData, onMessageListeners, cookieChangeListeners } = vi.hoisted(() => {
  const mockLocalStorageData: Record<string, unknown> = {};
  const mockSessionStorageData: Record<string, unknown> = {};
  const onMessageListeners: Array<
    (message: unknown, sender: unknown, sendResponse: (res: unknown) => void) => boolean | void
  > = [];
  const cookieChangeListeners: Array<(info: chrome.cookies.CookieChangeInfo) => void> = [];

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
      onChanged: {
        addListener: vi.fn((listener: (info: chrome.cookies.CookieChangeInfo) => void) => {
          cookieChangeListeners.push(listener);
        }),
        removeListener: vi.fn(),
        hasListener: vi.fn(),
      },
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

  return { mockLocalStorageData, mockSessionStorageData, onMessageListeners, cookieChangeListeners };
});

import {
  executeResetAllData,
  onHopComplete,
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
import { LocalStorage, getStorageResetEpoch } from '../../src/shared/storage';
import { DEFAULT_SETTINGS } from '../../src/shared/constants';
import type { TabState, AuthBaseline, Hop } from '../../src/shared/types';

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
    (chrome.storage.local.set as Mock).mockImplementation((items: Record<string, unknown>) => {
      Object.assign(mockLocalStorageData, items);
      return Promise.resolve();
    });
    (chrome.cookies.getAll as Mock).mockResolvedValue([]);
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

  it('invalidates in-flight capture work when reset occurs during cookie correlation', async () => {
    CapturePolicy.setSnapshotForTesting({
      ready: true,
      revision: 1,
      mode: 'all-sites',
      broadGrantActive: true,
      grantedOrigins: new Set(),
    });

    const tabId = 15;
    const testHop: Hop = {
      requestId: 'inflight-req-1',
      url: 'https://example.com/dashboard',
      status: 200,
      headers: {
        'content-type': 'text/html',
        'set-cookie': 'session=secret123; Path=/; Secure; HttpOnly',
      },
      rawHeaders: [
        { name: 'Content-Type', value: 'text/html' },
        { name: 'Set-Cookie', value: 'session=secret123; Path=/; Secure; HttpOnly' },
      ],
      fromCache: false,
      isHstsUpgrade: false,
      capturedAt: 'onResponseStarted',
      headersDiffer: false,
      timestamp: Date.now(),
      redirectCount: 0,
    };

    // Pause cookie correlation to simulate in-flight asynchronous work
    let resolveCookies!: (val: unknown[]) => void;
    const cookiesPromise = new Promise<unknown[]>((resolve) => {
      resolveCookies = resolve;
    });
    (chrome.cookies.getAll as Mock).mockImplementation(() => cookiesPromise);

    // Launch onHopComplete (asynchronously progresses until cookie correlation pause)
    const hopPromise = onHopComplete(tabId, testHop);

    // Give a tick for onHopComplete to pass the boundary and pause in correlateCookies
    await new Promise((r) => setTimeout(r, 20));

    // Execute complete reset while the capture is in flight
    await executeResetAllData();

    // Verify storage is completely empty after reset
    expect(tabStates.size).toBe(0);
    expect(Object.keys(mockSessionStorageData).length).toBe(0);

    // Now resume the in-flight cookie correlation
    resolveCookies([]);
    await hopPromise;

    // In-flight capture work must be discarded by reset epoch token
    expect(tabStates.has(tabId)).toBe(false);
    expect(mockSessionStorageData[`tab_${tabId}`]).toBeUndefined();

    const localKeys = Object.keys(mockLocalStorageData).filter(
      (k) => k.startsWith('history:') || k.startsWith('auth_diff:') || k.startsWith('graph:'),
    );
    expect(localKeys).toHaveLength(0);
  });

  it('linearizes storage writes against reset: pauses chrome.storage.local.set() after a pre-reset read, resets, resumes write, and asserts no old records return when monitoring is re-enabled', async () => {
    // 1. Enable monitoring
    CapturePolicy.setSnapshotForTesting({
      ready: true,
      revision: 1,
      mode: 'all-sites',
      broadGrantActive: true,
      grantedOrigins: new Set(),
    });

    const preResetEpoch = getStorageResetEpoch();
    const origin = 'https://example.com';

    // Set up a controllable deferred promise for chrome.storage.local.set
    let pauseSetPromiseResolve!: () => void;
    const pauseSetPromise = new Promise<void>((resolve) => {
      pauseSetPromiseResolve = resolve;
    });

    let setCalled = false;
    (chrome.storage.local.set as Mock).mockImplementation(async (items: Record<string, unknown>) => {
      // Pause only for origin history write
      if (Object.keys(items).some((k) => k.startsWith('hist:') || k.startsWith('history:'))) {
        setCalled = true;
        await pauseSetPromise;
      }
      Object.assign(mockLocalStorageData, items);
      return Promise.resolve();
    });

    // 2. Launch LocalStorage.recordOriginHistory with the current (pre-reset) epoch
    // This performs an async read (getOriginHistory, getSettings), then attempts to write
    const writeOpPromise = LocalStorage.recordOriginHistory(
      origin,
      {
        timestamp: Date.now(),
        score: 95,
        grade: 'A',
      },
      preResetEpoch,
    );

    // Wait until chrome.storage.local.set has been entered and is paused
    await vi.waitFor(() => {
      expect(setCalled).toBe(true);
    });

    // 3. While the write is paused inside set(), execute full reset!
    // The reset will increment the reset epoch, close the barrier, drain in-flight writes,
    // and wipe all local and session storage.
    const resetPromise = executeResetAllData();

    // Give a brief tick to ensure resetAllData is waiting in closeBarrierAndDrain
    await new Promise((r) => setTimeout(r, 20));

    // 4. Resume the paused set operation
    pauseSetPromiseResolve();

    // Both the write operation and the reset must resolve cleanly
    await Promise.all([writeOpPromise, resetPromise]);

    // 5. Re-enable monitoring to prove that no delayed/stale write resurrects data
    CapturePolicy.setSnapshotForTesting({
      ready: true,
      revision: 2,
      mode: 'all-sites',
      broadGrantActive: true,
      grantedOrigins: new Set(),
    });

    // 6. Assert zero old records returned in mockLocalStorageData
    const localKeys = Object.keys(mockLocalStorageData).filter(
      (k) =>
        k.startsWith('hist:') ||
        k.startsWith('history:') ||
        k.startsWith('auth_diff:') ||
        k.startsWith('authdiff:') ||
        k.startsWith('graph:'),
    );
    expect(localKeys).toHaveLength(0);

    const history = await LocalStorage.getOriginHistory(origin);
    expect(history).toEqual([]);
  });

  it('prevents resurrection on cookie-change: pauses correlateCookies during cookie change, resets, resumes, and asserts no old records return even if monitoring is re-enabled', async () => {
    // 1. Enable monitoring in all-sites mode
    CapturePolicy.setSnapshotForTesting({
      ready: true,
      revision: 1,
      mode: 'all-sites',
      broadGrantActive: true,
      grantedOrigins: new Set(),
    });

    const tabId = 22;
    const dummyState: TabState = {
      tabId,
      navigationGeneration: 1,
      origin: 'https://example.com',
      url: 'https://example.com/login',
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
      isIncognito: false,
    };
    tabStates.set(tabId, dummyState);
    tabGenerations.set(tabId, 1);

    // Setup pause for correlateCookies (via chrome.cookies.getAll)
    let resolveCookies!: (val: unknown[]) => void;
    const cookiesPromise = new Promise<unknown[]>((resolve) => {
      resolveCookies = resolve;
    });

    (chrome.cookies.getAll as Mock).mockImplementation(() => cookiesPromise);

    // 2. Trigger a cookie change event for example.com
    expect(cookieChangeListeners.length).toBeGreaterThan(0);
    const cookieListener = cookieChangeListeners[0];
    expect(cookieListener).toBeDefined();
    if (!cookieListener) throw new Error('cookieListener was not registered');

    cookieListener({
      removed: false,
      cause: 'explicit',
      cookie: {
        name: 'auth_token',
        value: 'sensitive-token',
        domain: '.example.com',
        path: '/',
        secure: true,
        httpOnly: true,
        sameSite: 'lax',
        session: true,
        hostOnly: false,
        storeId: '0',
      },
    });

    // Wait a tick for tabActionQueue to start and pause in correlateCookies
    await new Promise((r) => setTimeout(r, 20));

    // 3. Trigger full reset while correlateCookies is paused
    await executeResetAllData();

    // Verify state was cleared
    expect(tabStates.size).toBe(0);
    expect(Object.keys(mockSessionStorageData).length).toBe(0);

    // 4. Re-enable monitoring to test whether stale callback can resurrect the tab
    CapturePolicy.setSnapshotForTesting({
      ready: true,
      revision: 2,
      mode: 'all-sites',
      broadGrantActive: true,
      grantedOrigins: new Set(),
    });

    // 5. Resume correlateCookies with simulated cookie records
    resolveCookies([
      {
        name: 'auth_token',
        domain: '.example.com',
        path: '/',
        secure: true,
        httpOnly: true,
        sameSite: 'lax',
        session: true,
      },
    ]);

    // Give a tick for any resumed promises to settle
    await new Promise((r) => setTimeout(r, 50));

    // 6. Assert that the tab was NOT resurrected and storage remains completely clean
    expect(tabStates.has(tabId)).toBe(false);
    expect(mockSessionStorageData[`tab_${tabId}`]).toBeUndefined();

    const localKeys = Object.keys(mockLocalStorageData).filter(
      (k) =>
        k.startsWith('hist:') ||
        k.startsWith('history:') ||
        k.startsWith('auth_diff:') ||
        k.startsWith('authdiff:') ||
        k.startsWith('graph:'),
    );
    expect(localKeys).toHaveLength(0);
  });
});
