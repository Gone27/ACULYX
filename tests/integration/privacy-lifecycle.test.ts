import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Mock } from 'vitest';

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

import {
  resolveTabPrivacy,
  onHopComplete,
  pendingPrivacyLookups,
  tabGenerations,
} from '../../src/background/index';
import { tabStates } from '../../src/background/lifecycle';
import { incognitoTabIds } from '../../src/background/capture';
import { CapturePolicy } from '../../src/background/capture-policy';
import { LocalStorage } from '../../src/shared/storage';
import type { Hop } from '../../src/shared/types';

describe('Privacy Lifecycle Production Integration', () => {
  beforeEach(() => {
    for (const key of Object.keys(mockLocalStorageData)) delete mockLocalStorageData[key];
    for (const key of Object.keys(mockSessionStorageData)) delete mockSessionStorageData[key];
    tabStates.clear();
    incognitoTabIds.clear();
    pendingPrivacyLookups.clear();
    tabGenerations.clear();
    vi.clearAllMocks();

    CapturePolicy.setSnapshotForTesting({
      ready: true,
      revision: 1,
      mode: 'all-sites',
      broadGrantActive: true,
      grantedOrigins: new Set(),
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Authoritative resolveTabPrivacy', () => {
    it('queries chrome.tabs.get and marks tab incognito when tab.incognito is true', async () => {
      (chrome.tabs.get as Mock).mockResolvedValueOnce({ id: 101, incognito: true });

      const isIncognito = await resolveTabPrivacy(101);

      expect(isIncognito).toBe(true);
      expect(incognitoTabIds.has(101)).toBe(true);
      expect(chrome.tabs.get).toHaveBeenCalledWith(101);
    });

    it('returns false for negative tab IDs without looking up tabs', async () => {
      const isIncognito = await resolveTabPrivacy(-1);

      expect(isIncognito).toBe(false);
      expect(chrome.tabs.get).not.toHaveBeenCalled();
    });

    it('deduplicates concurrent in-flight privacy lookups', async () => {
      let resolveLookup!: (tab: { id: number; incognito: boolean }) => void;
      const delayedPromise = new Promise<{ id: number; incognito: boolean }>((resolve) => {
        resolveLookup = resolve;
      });
      (chrome.tabs.get as Mock).mockReturnValueOnce(delayedPromise);

      const promise1 = resolveTabPrivacy(102);
      const promise2 = resolveTabPrivacy(102);

      expect(pendingPrivacyLookups.has(102)).toBe(true);

      resolveLookup({ id: 102, incognito: true });
      const [res1, res2] = await Promise.all([promise1, promise2]);

      expect(res1).toBe(true);
      expect(res2).toBe(true);
      expect(chrome.tabs.get).toHaveBeenCalledTimes(1);
      expect(pendingPrivacyLookups.has(102)).toBe(false);
    });

    it('never demotes a known incognito tab if tab lookup subsequently throws or returns non-incognito', async () => {
      incognitoTabIds.add(103);

      const cachedResult = await resolveTabPrivacy(103);
      expect(cachedResult).toBe(true);
      expect(chrome.tabs.get).not.toHaveBeenCalled();

      // If simulated lookup fails on another call, remains true
      incognitoTabIds.add(104);
      (chrome.tabs.get as Mock).mockRejectedValueOnce(new Error('Tab closed'));
      pendingPrivacyLookups.delete(104);

      const errorResult = await resolveTabPrivacy(104);
      expect(errorResult).toBe(true);
      expect(incognitoTabIds.has(104)).toBe(true);
    });
  });

  describe('Fast cached response race isolation', () => {
    it('never writes history, auth-diff, or graph to LocalStorage for a new private tab on a fast cached response', async () => {
      const incognitoTabId = 205;

      // Intentional delay in chrome.tabs.get to simulate asynchronous tab resolution race
      (chrome.tabs.get as Mock).mockImplementation(async (id: number) => {
        await new Promise((r) => setTimeout(r, 20));
        return { id, incognito: true };
      });

      const recordHistorySpy = vi.spyOn(LocalStorage, 'recordOriginHistory');
      const recordAuthDiffSpy = vi.spyOn(LocalStorage, 'recordAuthDiff');
      const mutateGraphSpy = vi.spyOn(LocalStorage, 'mutateGraph');

      const fastCachedHop: Hop = {
        requestId: 'fast-cached-req-1',
        url: 'https://bank.example.com/login',
        status: 200,
        headers: {
          'content-type': 'text/html',
          'set-cookie': 'session_token=secret_val; Secure; HttpOnly',
        },
        rawHeaders: [
          { name: 'Content-Type', value: 'text/html' },
          { name: 'Set-Cookie', value: 'session_token=secret_val; Secure; HttpOnly' },
        ],
        fromCache: true,
        isHstsUpgrade: false,
        capturedAt: 'onResponseStarted',
        headersDiffer: false,
        timestamp: Date.now(),
        redirectCount: 0,
      };

      // In a fast cached response where onHeadersReceived was missed, isIncognito is initially undefined
      await onHopComplete(incognitoTabId, fastCachedHop, undefined);

      // Verify privacy was authoritatively resolved and tab state is incognito
      expect(incognitoTabIds.has(incognitoTabId)).toBe(true);
      const state = tabStates.get(incognitoTabId);
      expect(state?.isIncognito).toBe(true);

      // Verify LocalStorage was never touched for origin history, auth diffs, or graph
      expect(recordHistorySpy).not.toHaveBeenCalled();
      expect(recordAuthDiffSpy).not.toHaveBeenCalled();
      expect(mutateGraphSpy).not.toHaveBeenCalled();

      // Verify no persistence leaked into mockLocalStorageData
      const leakedHistoryKeys = Object.keys(mockLocalStorageData).filter(
        (k) => k.startsWith('history:') || k.startsWith('auth_diff:') || k.startsWith('graph:'),
      );
      expect(leakedHistoryKeys).toHaveLength(0);
    });

    it('never writes history, auth-diff, or graph to LocalStorage for an unknown tab whose tabs.get() rejects', async () => {
      const unknownTabId = 999;
      incognitoTabIds.delete(unknownTabId);
      tabStates.delete(unknownTabId);
      pendingPrivacyLookups.delete(unknownTabId);

      (chrome.tabs.get as Mock).mockRejectedValue(new Error('Cannot find tab 999'));

      const recordHistorySpy = vi.spyOn(LocalStorage, 'recordOriginHistory');
      const recordAuthDiffSpy = vi.spyOn(LocalStorage, 'recordAuthDiff');
      const mutateGraphSpy = vi.spyOn(LocalStorage, 'mutateGraph');

      const testHop: Hop = {
        requestId: 'unknown-tab-req-1',
        url: 'https://bank.example.com/login',
        status: 200,
        headers: {
          'content-type': 'text/html',
          'set-cookie': 'session_token=secret_val; Secure; HttpOnly',
        },
        rawHeaders: [
          { name: 'Content-Type', value: 'text/html' },
          { name: 'Set-Cookie', value: 'session_token=secret_val; Secure; HttpOnly' },
        ],
        fromCache: false,
        isHstsUpgrade: false,
        capturedAt: 'onResponseStarted',
        headersDiffer: false,
        timestamp: Date.now(),
        redirectCount: 0,
      };

      await onHopComplete(unknownTabId, testHop, undefined);

      const state = tabStates.get(unknownTabId);
      // Privacy is held as undefined (unresolved)
      expect(state?.isIncognito).toBeUndefined();

      // LocalStorage persistence sinks are NEVER touched
      expect(recordHistorySpy).not.toHaveBeenCalled();
      expect(recordAuthDiffSpy).not.toHaveBeenCalled();
      expect(mutateGraphSpy).not.toHaveBeenCalled();

      const leakedKeys = Object.keys(mockLocalStorageData).filter(
        (k) => k.startsWith('history:') || k.startsWith('auth_diff:') || k.startsWith('graph:'),
      );
      expect(leakedKeys).toHaveLength(0);
    });
  });
});
