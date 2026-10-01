import { describe, it, expect, vi } from 'vitest';
import {
  isBroadGrant,
  normalizePermissionOrigin,
  isOriginPermitted,
  clearTabCapture,
  reconcilePermissionsOnRemoved,
  reconcilePermissionsOnStartup,
} from '../../src/background/permissions';
import type { TabState } from '../../src/shared/types';

describe('Permissions Representation and Helpers', () => {
  it('correctly identifies broad grants', () => {
    expect(isBroadGrant('<all_urls>')).toBe(true);
    expect(isBroadGrant('*://*/*')).toBe(true);
    expect(isBroadGrant('https://*/*')).toBe(true);
    expect(isBroadGrant('http://*/*')).toBe(true);
    expect(isBroadGrant('https://example.com/*')).toBe(false);
    expect(isBroadGrant('https://api.github.com/')).toBe(false);
    expect(isBroadGrant('')).toBe(false);
  });

  it('normalizes permission origin patterns to canonical origins', () => {
    expect(normalizePermissionOrigin('https://example.com/*')).toBe('https://example.com');
    expect(normalizePermissionOrigin('http://localhost:8080/*')).toBe('http://localhost:8080');
    expect(normalizePermissionOrigin('https://sub.domain.com/path/*')).toBe('https://sub.domain.com');
    expect(normalizePermissionOrigin('https://example.com/')).toBe('https://example.com');
    expect(normalizePermissionOrigin('https://example.com')).toBe('https://example.com');
    expect(normalizePermissionOrigin('<all_urls>')).toBe('<all_urls>');
    expect(normalizePermissionOrigin('')).toBe('');
  });

  it('determines whether an origin is permitted by granted patterns', () => {
    const patterns = ['https://example.com/*', 'https://api.test/*'];
    expect(isOriginPermitted('https://example.com', patterns)).toBe(true);
    expect(isOriginPermitted('https://api.test', patterns)).toBe(true);
    expect(isOriginPermitted('https://other.com', patterns)).toBe(false);
    expect(isOriginPermitted('http://example.com', patterns)).toBe(false);

    // Broad grant covers everything
    expect(isOriginPermitted('https://random.org', ['<all_urls>'])).toBe(true);
    expect(isOriginPermitted('https://random.org', ['*://*/*'])).toBe(true);
  });
});

describe('clearTabCapture and Revocation Cleanup', () => {
  function makeMockTabState(tabId: number, origin: string): TabState {
    return {
      tabId,
      origin,
      url: `${origin}/page`,
      hops: [],
      cookies: [],
      findings: [],
      grade: 'A',
      score: 100,
      scoreVersion: '2.0.0',
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
      },
      monitoredByUser: true,
      subdomainTrust: { hasEscalationPath: false, vectors: [] },
      updatedAt: Date.now(),
    };
  }

  it('evicts tab state, session storage, capture map, receipts, badge, and broadcasts null', async () => {
    const tabStates = new Map<number, TabState>();
    tabStates.set(101, makeMockTabState(101, 'https://example.com'));

    const removeTabStateMock = vi.fn().mockResolvedValue(undefined);
    const mockSessionStorage = { removeTabState: removeTabStateMock };

    const captureMap = new Map<string, { tabId: number }>();
    captureMap.set('req-1', { tabId: 101 });
    captureMap.set('req-2', { tabId: 102 });

    const pendingSW = new Map<number, unknown>([[101, { status: 'controlled' }]]);
    const pendingMeta = new Set<number>([101]);

    const setBadgeMock = vi.fn();
    const broadcastMock = vi.fn();

    await clearTabCapture(101, {
      tabStates,
      sessionStorage: mockSessionStorage,
      captureMap,
      pendingServiceWorkerReports: pendingSW,
      pendingMetaCspReports: pendingMeta,
      setBadge: setBadgeMock,
      broadcast: broadcastMock,
    });

    expect(tabStates.has(101)).toBe(false);
    expect(removeTabStateMock).toHaveBeenCalledWith(101);
    expect(captureMap.has('req-1')).toBe(false);
    expect(captureMap.has('req-2')).toBe(true); // tab 102 preserved
    expect(pendingSW.has(101)).toBe(false);
    expect(pendingMeta.has(101)).toBe(false);
    expect(setBadgeMock).toHaveBeenCalledWith(101, '');
    expect(broadcastMock).toHaveBeenCalledWith(101, { type: 'STATE_RESPONSE', state: null });
  });

  it('is idempotent when called multiple times on the same tab', async () => {
    const tabStates = new Map<number, TabState>();
    const removeTabStateMock = vi.fn().mockResolvedValue(undefined);

    await clearTabCapture(999, {
      tabStates,
      sessionStorage: { removeTabState: removeTabStateMock },
    });

    await clearTabCapture(999, {
      tabStates,
      sessionStorage: { removeTabState: removeTabStateMock },
    });

    expect(removeTabStateMock).toHaveBeenCalledTimes(2);
  });
});

describe('Permission Reconciliation (onRemoved & startup)', () => {
  function makeMockTabState(tabId: number, origin: string): TabState {
    return {
      tabId,
      origin,
      url: `${origin}/`,
      hops: [],
      cookies: [],
      findings: [],
      grade: 'B',
      score: 80,
      scoreVersion: '2.0.0',
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
      },
      monitoredByUser: true,
      subdomainTrust: { hasEscalationPath: false, vectors: [] },
      updatedAt: Date.now(),
    };
  }

  it('reconcilePermissionsOnRemoved cleans up only revoked origin tabs', async () => {
    const tabStates = new Map<number, TabState>();
    tabStates.set(1, makeMockTabState(1, 'https://revoked.com'));
    tabStates.set(2, makeMockTabState(2, 'https://kept.com'));

    const removeTabStateMock = vi.fn().mockResolvedValue(undefined);

    const cleared = await reconcilePermissionsOnRemoved(['https://revoked.com/*'], {
      tabStates,
      sessionStorage: { removeTabState: removeTabStateMock },
      getActiveOrigins: vi.fn().mockResolvedValue(['https://kept.com']),
      isBroadGrantActive: vi.fn().mockResolvedValue(false),
    });

    expect(cleared).toEqual([1]);
    expect(tabStates.has(1)).toBe(false);
    expect(tabStates.has(2)).toBe(true);
    expect(removeTabStateMock).toHaveBeenCalledWith(1);
    expect(removeTabStateMock).not.toHaveBeenCalledWith(2);
  });

  it('reconcilePermissionsOnStartup clears any hydrated tab missing active permission', async () => {
    const tabStates = new Map<number, TabState>();
    tabStates.set(10, makeMockTabState(10, 'https://allowed.com'));
    tabStates.set(20, makeMockTabState(20, 'https://stale.com'));

    const removeTabStateMock = vi.fn().mockResolvedValue(undefined);

    const cleared = await reconcilePermissionsOnStartup({
      tabStates,
      sessionStorage: { removeTabState: removeTabStateMock },
      getActiveOrigins: vi.fn().mockResolvedValue(['https://allowed.com']),
      isBroadGrantActive: vi.fn().mockResolvedValue(false),
    });

    expect(cleared).toEqual([20]);
    expect(tabStates.has(10)).toBe(true);
    expect(tabStates.has(20)).toBe(false);
  });
});
