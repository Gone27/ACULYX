import { describe, it, expect, beforeEach, vi } from 'vitest';
import { SessionStorage, LocalStorage } from '../../src/shared/storage';
import { STORAGE_KEYS } from '../../src/shared/constants';
import { incognitoTabIds } from '../../src/background/capture';
import type { TabState } from '../../src/shared/types';

describe('Incognito Isolation & Storage Resilience (WS4)', () => {
  let mockLocalStore: Record<string, unknown> = {};
  let mockSessionStore: Record<string, unknown> = {};

  beforeEach(() => {
    incognitoTabIds.clear();
    mockLocalStore = {};
    mockSessionStore = {};

    (globalThis as unknown as { chrome: unknown }).chrome = {
      storage: {
        local: {
          get: vi.fn((keys: unknown) => {
            if (keys === null) return Promise.resolve({ ...mockLocalStore });
            if (typeof keys === 'string') return Promise.resolve({ [keys]: mockLocalStore[keys] });
            if (Array.isArray(keys)) {
              const res: Record<string, unknown> = {};
              for (const k of keys as string[]) res[k] = mockLocalStore[k];
              return Promise.resolve(res);
            }
            return Promise.resolve({});
          }),
          set: vi.fn((items: Record<string, unknown>) => {
            Object.assign(mockLocalStore, items);
            return Promise.resolve();
          }),
          remove: vi.fn((keys: string | string[]) => {
            const list = Array.isArray(keys) ? keys : [keys];
            for (const k of list) delete mockLocalStore[k];
            return Promise.resolve();
          }),
        },
        session: {
          get: vi.fn((keys: unknown) => {
            if (keys === null) return Promise.resolve({ ...mockSessionStore });
            if (typeof keys === 'string') return Promise.resolve({ [keys]: mockSessionStore[keys] });
            if (Array.isArray(keys)) {
              const res: Record<string, unknown> = {};
              for (const k of keys as string[]) res[k] = mockSessionStore[k];
              return Promise.resolve(res);
            }
            return Promise.resolve({});
          }),
          set: vi.fn((items: Record<string, unknown>) => {
            Object.assign(mockSessionStore, items);
            return Promise.resolve();
          }),
          remove: vi.fn((keys: string | string[]) => {
            const list = Array.isArray(keys) ? keys : [keys];
            for (const k of list) delete mockSessionStore[k];
            return Promise.resolve();
          }),
        },
      },
    };
  });

  it('tracks incognitoTabIds explicitly and isolates incognito state', () => {
    incognitoTabIds.add(42);
    expect(incognitoTabIds.has(42)).toBe(true);
    expect(incognitoTabIds.has(43)).toBe(false);

    incognitoTabIds.delete(42);
    expect(incognitoTabIds.has(42)).toBe(false);
  });

  it('SessionStorage.getAllTabStates gracefully skips corrupt session records without throwing', async () => {
    const validState: TabState = {
      tabId: 101,
      origin: 'https://example.com',
      url: 'https://example.com/test',
      hops: [],
      cookies: [],
      findings: [],
      grade: 'A',
      score: 95,
      scoreVersion: '1.7.0',
      scoreBreakdown: [],
      coverage: {
        hopsExpected: 1,
        hopsCaptured: 1,
        hasCache: false,
        hasServiceWorker: false,
        serviceWorkerStatus: 'not-controlled',
        serviceWorkerUrl: null,
        isRestricted: false,
        metaCspFound: false,
      },
      subdomainTrust: { hasEscalationPath: false, vectors: [] },
      monitoredByUser: true,
      updatedAt: Date.now(),
    };

    mockSessionStore[`${STORAGE_KEYS.TAB_PREFIX}101`] = validState;
    mockSessionStore[`${STORAGE_KEYS.TAB_PREFIX}999`] = 'CORRUPT_NOT_AN_OBJECT_CRASH';

    const results = await SessionStorage.getAllTabStates();
    expect(results).toHaveLength(1);
    expect(results[0]?.tabId).toBe(101);
  });

  it('deletePrivateRecords purges only incognito tab states from session storage', async () => {
    mockSessionStore[`${STORAGE_KEYS.TAB_PREFIX}1`] = { tabId: 1, isIncognito: false };
    mockSessionStore[`${STORAGE_KEYS.TAB_PREFIX}2`] = { tabId: 2, isIncognito: true };
    mockSessionStore[`${STORAGE_KEYS.TAB_PREFIX}3`] = { tabId: 3 };
    mockSessionStore[`${STORAGE_KEYS.TAB_PREFIX}4`] = { tabId: 4, isIncognito: true };

    await LocalStorage.deletePrivateRecords();

    expect(mockSessionStore[`${STORAGE_KEYS.TAB_PREFIX}1`]).toBeDefined();
    expect(mockSessionStore[`${STORAGE_KEYS.TAB_PREFIX}2`]).toBeUndefined();
    expect(mockSessionStore[`${STORAGE_KEYS.TAB_PREFIX}3`]).toBeDefined();
    expect(mockSessionStore[`${STORAGE_KEYS.TAB_PREFIX}4`]).toBeUndefined();
  });

  it('deleteAllHistory removes all keys with HISTORY_PREFIX', async () => {
    mockLocalStore[`${STORAGE_KEYS.HISTORY_PREFIX}https://a.com`] = [{ timestamp: 1, score: 90, grade: 'A' }];
    mockLocalStore[`${STORAGE_KEYS.HISTORY_PREFIX}https://b.com`] = [{ timestamp: 2, score: 80, grade: 'B' }];
    mockLocalStore[STORAGE_KEYS.SETTINGS] = { monitoringMode: 'per-site' };

    await LocalStorage.deleteAllHistory();

    expect(mockLocalStore[`${STORAGE_KEYS.HISTORY_PREFIX}https://a.com`]).toBeUndefined();
    expect(mockLocalStore[`${STORAGE_KEYS.HISTORY_PREFIX}https://b.com`]).toBeUndefined();
    expect(mockLocalStore[STORAGE_KEYS.SETTINGS]).toBeDefined();
  });

  it('deleteOriginData purges history, auth diffs, and graph nodes for the target origin', async () => {
    const purgeSpy = vi.spyOn(LocalStorage, 'purgeOriginData').mockResolvedValue(undefined);

    await LocalStorage.deleteOriginData('https://example.com');
    expect(purgeSpy).toHaveBeenCalledWith('https://example.com');

    purgeSpy.mockRestore();
  });
});
