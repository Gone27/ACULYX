import { describe, it, expect, vi } from 'vitest';
import {
  isBroadGrant,
  hasAllSitesCoverage,
  normalizePermissionOrigin,
  patternFromOrigin,
  isOriginPermitted,
  clearTabCapture,
  reconcilePermissionsOnRemoved,
  reconcilePermissionsOnStartup,
  PermissionsService,
} from '../../src/background/permissions';
import { CapturePolicy } from '../../src/background/capture-policy';
import { SettingsService } from '../../src/shared/settings';
import { DEFAULT_SETTINGS } from '../../src/shared/constants';
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

  it('generates valid Chrome match patterns without ports via patternFromOrigin', () => {
    expect(patternFromOrigin('http://127.0.0.1:3464')).toBe('http://127.0.0.1/*');
    expect(patternFromOrigin('http://127.0.0.1:3464/')).toBe('http://127.0.0.1/*');
    expect(patternFromOrigin('https://example.com:8443/test')).toBe('https://example.com/*');
    expect(patternFromOrigin('https://example.com')).toBe('https://example.com/*');
    expect(patternFromOrigin('<all_urls>')).toBe('<all_urls>');
    expect(patternFromOrigin('*://*/*')).toBe('*://*/*');
    expect(patternFromOrigin('')).toBe('');
  });

  it('determines whether an origin is permitted by granted patterns (including port tolerance)', () => {
    const patterns = ['https://example.com/*', 'https://api.test/*', 'http://127.0.0.1/*'];
    expect(isOriginPermitted('https://example.com', patterns)).toBe(true);
    expect(isOriginPermitted('https://api.test', patterns)).toBe(true);
    expect(isOriginPermitted('http://127.0.0.1:3464', patterns)).toBe(true);
    expect(isOriginPermitted('https://example.com:8443', patterns)).toBe(true);
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

  it('retains tabs with narrow grants when broad grant is removed', async () => {
    const tabStates = new Map<number, TabState>();
    tabStates.set(1, makeMockTabState(1, 'https://app.example'));
    tabStates.set(2, makeMockTabState(2, 'https://other.example'));

    const removeTabStateMock = vi.fn().mockResolvedValue(undefined);

    // User removes <all_urls>, but https://app.example/* is still in activeOrigins
    const cleared = await reconcilePermissionsOnRemoved(['<all_urls>'], {
      tabStates,
      sessionStorage: { removeTabState: removeTabStateMock },
      getActiveOrigins: vi.fn().mockResolvedValue(['https://app.example']),
      isBroadGrantActive: vi.fn().mockResolvedValue(false),
    });

    // Only other.example should be cleared; app.example retains its state!
    expect(cleared).toEqual([2]);
    expect(tabStates.has(1)).toBe(true);
    expect(tabStates.has(2)).toBe(false);
    expect(removeTabStateMock).toHaveBeenCalledWith(2);
    expect(removeTabStateMock).not.toHaveBeenCalledWith(1);
  });
});

describe('PermissionsService.removeAllBroadGrants', () => {
  it('identifies and removes all broad grants truthfully', async () => {
    let callCount = 0;
    const getAllMock = vi.fn().mockImplementation(() => {
      callCount += 1;
      if (callCount === 1) {
        return Promise.resolve({
          origins: ['<all_urls>', '*://*/*', 'https://*/*', 'https://app.example/*'],
        });
      }
      // After removal, only narrow grant remains
      return Promise.resolve({
        origins: ['https://app.example/*'],
      });
    });

    let removedPatterns: string[] = [];
    const removeMock = vi.fn().mockImplementation((options: { origins: string[] }, callback: (res: boolean) => void) => {
      removedPatterns = options.origins;
      callback(true);
    });

    const chromeMock = {
      permissions: {
        getAll: getAllMock,
        remove: removeMock,
      },
    } as unknown as typeof chrome;

    vi.stubGlobal('chrome', chromeMock);

    try {
      const result = await PermissionsService.removeAllBroadGrants();
      expect(result).toBe(true);
      expect(removedPatterns).toEqual(['<all_urls>', '*://*/*', 'https://*/*']);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('returns false if broad pattern removal fails or access remains', async () => {
    const getAllMock = vi.fn().mockResolvedValue({
      origins: ['<all_urls>', 'https://app.example/*'],
    });
    const removeMock = vi.fn().mockImplementation((_options: unknown, callback: (res: boolean) => void) => {
      callback(false);
    });

    const chromeMock = {
      permissions: {
        getAll: getAllMock,
        remove: removeMock,
      },
    } as unknown as typeof chrome;

    vi.stubGlobal('chrome', chromeMock);

    try {
      const result = await PermissionsService.removeAllBroadGrants();
      expect(result).toBe(false);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe('WS1 1B: Truthful All-Sites Permission and Fallthrough Elimination', () => {
  it('hasAllSitesCoverage validates full coverage across schemes and rejects partial grants', () => {
    // Complete broad patterns
    expect(hasAllSitesCoverage(['<all_urls>'])).toBe(true);
    expect(hasAllSitesCoverage(['*://*/*'])).toBe(true);
    expect(hasAllSitesCoverage(['*://*'])).toBe(true);
    expect(hasAllSitesCoverage(['https://*/*', 'http://*/*'])).toBe(true);
    expect(hasAllSitesCoverage(['https://*/', 'http://*/'])).toBe(true);

    // Incomplete one-scheme-only broad patterns
    expect(hasAllSitesCoverage(['https://*/*'])).toBe(false);
    expect(hasAllSitesCoverage(['http://*/*'])).toBe(false);
    expect(hasAllSitesCoverage(['https://*/*', 'https://example.com/*'])).toBe(false);

    // Narrow origin grants only
    expect(hasAllSitesCoverage(['https://example.com/*', 'https://api.test/*'])).toBe(false);
    expect(hasAllSitesCoverage([])).toBe(false);
  });

  it('PermissionsService.hasCompleteBroadGrant queries browser permissions truthfully', async () => {
    // 1. One-scheme-only grant in browser
    const oneSchemeChrome = {
      permissions: {
        getAll: vi.fn().mockResolvedValue({ origins: ['https://*/*'] }),
      },
    } as unknown as typeof chrome;
    vi.stubGlobal('chrome', oneSchemeChrome);

    try {
      expect(await PermissionsService.hasCompleteBroadGrant()).toBe(false);
    } finally {
      vi.unstubAllGlobals();
    }

    // 2. Full broad grant in browser
    const fullChrome = {
      permissions: {
        getAll: vi.fn().mockResolvedValue({ origins: ['<all_urls>'] }),
      },
    } as unknown as typeof chrome;
    vi.stubGlobal('chrome', fullChrome);

    try {
      expect(await PermissionsService.hasCompleteBroadGrant()).toBe(true);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('CapturePolicy.evaluate in All-sites mode eliminates fallthrough to individual origin grants', async () => {
    const getSettingsSpy = vi.spyOn(SettingsService, 'getSettings').mockResolvedValue({
      ...DEFAULT_SETTINGS,
      monitoringMode: 'all-sites',
    });

    // Simulate browser state: broad grant is missing, but origin https://granted.com has an individual grant!
    const chromeMock = {
      permissions: {
        getAll: vi.fn().mockResolvedValue({ origins: ['https://granted.com/*'] }),
        contains: vi.fn((_opt: { origins: string[] }, cb: (res: boolean) => void) => {
          cb(true); // Individual grant passes
        }),
      },
    } as unknown as typeof chrome;
    vi.stubGlobal('chrome', chromeMock);

    try {
      // Synthetic probe on granted origin: must STILL be denied because All-sites broad grant is missing!
      const grantedSiteResult = await CapturePolicy.evaluate('https://granted.com/app');
      expect(grantedSiteResult.allowed).toBe(false);
      expect(grantedSiteResult.reason).toBe('all-sites-missing-grant');
      expect(grantedSiteResult.monitoringState).toBe('Paused — All-sites permission missing');

      // Synthetic probe on ungranted origin: also denied with identical reason!
      const ungrantedSiteResult = await CapturePolicy.evaluate('https://ungranted.com/app');
      expect(ungrantedSiteResult.allowed).toBe(false);
      expect(ungrantedSiteResult.reason).toBe('all-sites-missing-grant');
      expect(ungrantedSiteResult.monitoringState).toBe('Paused — All-sites permission missing');
    } finally {
      vi.unstubAllGlobals();
      getSettingsSpy.mockRestore();
    }
  });

  it('CapturePolicy.getMonitoringState returns truthful state across all modes and conditions', async () => {
    const getSettingsSpy = vi.spyOn(SettingsService, 'getSettings');

    // 1. Off mode
    getSettingsSpy.mockResolvedValueOnce({ ...DEFAULT_SETTINGS, monitoringMode: 'off' });
    expect(await CapturePolicy.getMonitoringState()).toBe('Off');

    // 2. All-sites mode with missing broad grant
    getSettingsSpy.mockResolvedValueOnce({ ...DEFAULT_SETTINGS, monitoringMode: 'all-sites' });
    const missingBroadChrome = {
      permissions: { getAll: vi.fn().mockResolvedValue({ origins: ['https://example.com/*'] }) },
    } as unknown as typeof chrome;
    vi.stubGlobal('chrome', missingBroadChrome);
    expect(await CapturePolicy.getMonitoringState()).toBe('Paused — All-sites permission missing');
    vi.unstubAllGlobals();

    // 3. All-sites mode with active broad grant
    getSettingsSpy.mockResolvedValueOnce({ ...DEFAULT_SETTINGS, monitoringMode: 'all-sites' });
    const activeBroadChrome = {
      permissions: { getAll: vi.fn().mockResolvedValue({ origins: ['<all_urls>'] }) },
    } as unknown as typeof chrome;
    vi.stubGlobal('chrome', activeBroadChrome);
    expect(await CapturePolicy.getMonitoringState()).toBe('Active — All sites');
    vi.unstubAllGlobals();

    // 4. Per-site mode with broad grant conflict
    getSettingsSpy.mockResolvedValueOnce({ ...DEFAULT_SETTINGS, monitoringMode: 'per-site' });
    const conflictChrome = {
      permissions: { getAll: vi.fn().mockResolvedValue({ origins: ['<all_urls>'] }) },
    } as unknown as typeof chrome;
    vi.stubGlobal('chrome', conflictChrome);
    expect(await CapturePolicy.getMonitoringState()).toBe('Paused — Broad access conflict');
    vi.unstubAllGlobals();

    // 5. Per-site mode without broad grant (normal active per-site)
    getSettingsSpy.mockResolvedValueOnce({ ...DEFAULT_SETTINGS, monitoringMode: 'per-site' });
    const normalChrome = {
      permissions: { getAll: vi.fn().mockResolvedValue({ origins: ['https://example.com/*'] }) },
    } as unknown as typeof chrome;
    vi.stubGlobal('chrome', normalChrome);
    expect(await CapturePolicy.getMonitoringState()).toBe('Active — Per-site');
    vi.unstubAllGlobals();

    getSettingsSpy.mockRestore();
  });
});

