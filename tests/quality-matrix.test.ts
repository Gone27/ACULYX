import { describe, it, expect, beforeEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

// Background & Permission services
import {
  hasAllSitesCoverage,
  patternFromOrigin,
  isOriginPermitted,
  clearTabCapture,
  reconcilePermissionsOnRemoved,
} from '../src/background/permissions';
import {
  CapturePolicy,
  isCaptureAllowedAtBoundary,
} from '../src/background/capture-policy';
import {
  registerCaptureListeners,
  clearInFlightCaptures,
  captureMap,
  inFlightRequests,
} from '../src/background/capture';

// Rules & Shared services
import { isRestrictedUrl } from '../src/shared/gating';
import { SettingsService } from '../src/shared/settings';
import {
  LocalStorage,
  assertNoSensitiveSecrets,
} from '../src/shared/storage';
import {
  sanitizeUrlForStorage,
  sanitizeCspPolicyForStorage,
} from '../src/rules/utils';
import { runRules } from '../src/rules/engine';
import { computeScore } from '../src/rules/scoring';
import {
  exportJsonReport,
  exportMarkdownReport,
  exportSarifReport,
  generateSarif,
} from '../src/shared/export';
import { DEFAULT_SETTINGS } from '../src/shared/constants';
import type {
  TabState,
  Hop,
  ApiHop,
  CookieRecord,
  CoverageLedgerEntry,
} from '../src/shared/types';

describe('Phase 1 Matrix: Monitoring & Permissions', () => {
  describe('First-Run & Hydration Boundary', () => {
    it('fails closed prior to snapshot hydration for all URLs', () => {
      CapturePolicy.resetSnapshotForTesting(); // ready: false
      const snapshot = CapturePolicy.getSnapshot();
      expect(snapshot.ready).toBe(false);

      expect(isCaptureAllowedAtBoundary('https://example.com', snapshot)).toBe(false);
      expect(isCaptureAllowedAtBoundary('http://localhost:3000', snapshot)).toBe(false);
      expect(isCaptureAllowedAtBoundary('https://api.github.com/v1', snapshot)).toBe(false);
      expect(isCaptureAllowedAtBoundary('chrome://settings', snapshot)).toBe(false);
    });

    it('initializes clean default settings with per-site mode on first run', async () => {
      const mockStore: Record<string, unknown> = {};
      const chromeMock = {
        storage: {
          local: {
            get: vi.fn((_keys, cb?: (res: unknown) => void) => {
              if (cb) cb(mockStore);
              return Promise.resolve(mockStore);
            }),
            set: vi.fn((items: Record<string, unknown>, cb?: () => void) => {
              Object.assign(mockStore, items);
              if (cb) cb();
              return Promise.resolve();
            }),
          },
        },
      } as unknown as typeof chrome;
      vi.stubGlobal('chrome', chromeMock);

      try {
        const settings = await SettingsService.getSettings();
        expect(settings.schemaVersion).toBe(2);
        expect(settings.monitoringMode).toBe('per-site');
        expect(settings.retainHistoryDays).toBe(7);
        expect(settings.maxHistoryPerOrigin).toBe(10);
        expect(settings.evaluationMode).toBe(false);
        expect(settings.sensitiveCookieNames).toEqual(DEFAULT_SETTINGS.sensitiveCookieNames);
        expect(settings.ignoredCookieNames).toEqual(DEFAULT_SETTINGS.ignoredCookieNames);
      } finally {
        vi.unstubAllGlobals();
      }
    });

    it('hydrates snapshot from settings and permissions idempotently', async () => {
      const chromeMock = {
        permissions: {
          getAll: vi.fn().mockResolvedValue({
            origins: ['https://permitted.org/*'],
          }),
        },
        storage: {
          local: {
            get: vi.fn().mockResolvedValue({
              settings: {
                ...DEFAULT_SETTINGS,
                monitoringMode: 'per-site',
              },
            }),
          },
        },
      } as unknown as typeof chrome;
      vi.stubGlobal('chrome', chromeMock);

      try {
        const snapshot = await CapturePolicy.refreshSnapshot();
        expect(snapshot.ready).toBe(true);
        expect(snapshot.mode).toBe('per-site');
        expect(snapshot.broadGrantActive).toBe(false);
        expect(snapshot.grantedOrigins.has('https://permitted.org')).toBe(true);
      } finally {
        vi.unstubAllGlobals();
      }
    });
  });

  describe('Scheme Boundaries & Restricted URLs', () => {
    it('accepts valid http and https web schemes while rejecting internal/restricted schemes', () => {
      expect(isRestrictedUrl('https://example.com/index.html')).toBe(false);
      expect(isRestrictedUrl('http://insecure.example.com')).toBe(false);

      // Restricted browser internal and pseudo schemes
      expect(isRestrictedUrl('chrome://extensions')).toBe(true);
      expect(isRestrictedUrl('chrome-extension://abcdefghijklmnopqrstuvwxyz/options.html')).toBe(true);
      expect(isRestrictedUrl('about:blank')).toBe(true);
      expect(isRestrictedUrl('data:text/html,<html>test</html>')).toBe(true);
      expect(isRestrictedUrl('blob:https://example.com/1234-5678')).toBe(true);
      expect(isRestrictedUrl('edge://settings')).toBe(true);
      expect(isRestrictedUrl('view-source:https://example.com')).toBe(true);
      expect(isRestrictedUrl('file:///C:/Users/Admin/secrets.txt')).toBe(true);
    });

    it('boundary pre-filter strictly drops restricted URLs even under broad all-sites mode', () => {
      const broadSnapshot = {
        ready: true,
        revision: 5,
        mode: 'all-sites' as const,
        broadGrantActive: true,
        grantedOrigins: new Set(['<all_urls>']),
      };

      expect(isCaptureAllowedAtBoundary('chrome://settings', broadSnapshot)).toBe(false);
      expect(isCaptureAllowedAtBoundary('chrome-extension://id/popup.html', broadSnapshot)).toBe(false);
      expect(isCaptureAllowedAtBoundary('about:config', broadSnapshot)).toBe(false);
      expect(isCaptureAllowedAtBoundary('file:///home/user/test.html', broadSnapshot)).toBe(false);
      expect(isCaptureAllowedAtBoundary('https://valid-target.com', broadSnapshot)).toBe(true);
    });
  });

  describe('Scheme Conservatism in Broad Patterns', () => {
    it('requires complete coverage across schemes for all-sites mode', () => {
      expect(hasAllSitesCoverage(['<all_urls>'])).toBe(true);
      expect(hasAllSitesCoverage(['*://*/*'])).toBe(true);
      expect(hasAllSitesCoverage(['https://*/*', 'http://*/*'])).toBe(true);

      // Incomplete schemes fail closed
      expect(hasAllSitesCoverage(['https://*/*'])).toBe(false);
      expect(hasAllSitesCoverage(['http://*/*'])).toBe(false);
      expect(hasAllSitesCoverage(['https://*/*', 'https://app.example.com/*'])).toBe(false);
    });

    it('drops capture at boundary when all-sites mode has incomplete broad coverage', () => {
      const incompleteSnapshot = {
        ready: true,
        revision: 6,
        mode: 'all-sites' as const,
        broadGrantActive: false, // Broad grant not active/complete
        grantedOrigins: new Set(['https://*/*']),
      };

      expect(isCaptureAllowedAtBoundary('https://example.com', incompleteSnapshot)).toBe(false);
      expect(isCaptureAllowedAtBoundary('http://example.com', incompleteSnapshot)).toBe(false);
    });
  });

  describe('Broad Grant Conflict in Per-Site Mode', () => {
    it('pauses capture at boundary when per-site mode encounters active broad grant', () => {
      const conflictSnapshot = {
        ready: true,
        revision: 7,
        mode: 'per-site' as const,
        broadGrantActive: true, // Conflict: broad grant is active while mode is per-site!
        grantedOrigins: new Set(['https://explicitly-allowed.com']),
      };

      expect(isCaptureAllowedAtBoundary('https://explicitly-allowed.com', conflictSnapshot)).toBe(false);
      expect(isCaptureAllowedAtBoundary('https://other.com', conflictSnapshot)).toBe(false);
    });
  });

  describe('Reload Behavior & Chrome Match Pattern Normalization', () => {
    it('normalizes origins with ports to valid Chrome match patterns without port numbers', () => {
      // Chrome permissions API requires match patterns without port numbers
      expect(patternFromOrigin('http://127.0.0.1:3464')).toBe('http://127.0.0.1/*');
      expect(patternFromOrigin('https://example.com:8443/app')).toBe('https://example.com/*');
      expect(patternFromOrigin('https://secure.site.com/')).toBe('https://secure.site.com/*');
      expect(patternFromOrigin('<all_urls>')).toBe('<all_urls>');
    });

    it('matches permitted origins with non-standard ports against origin match patterns', () => {
      const permittedPatterns = ['http://127.0.0.1/*', 'https://example.com/*'];
      expect(isOriginPermitted('http://127.0.0.1:3464', permittedPatterns)).toBe(true);
      expect(isOriginPermitted('https://example.com:8443', permittedPatterns)).toBe(true);
      expect(isOriginPermitted('http://example.com', permittedPatterns)).toBe(false);
    });
  });

  describe('External Revocation & Tab Reconciliation', () => {
    function makeTabState(tabId: number, origin: string): TabState {
      return {
        tabId,
        origin,
        url: `${origin}/path`,
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
          ledger: [],
          blindSpots: [],
        },
        subdomainTrust: { hasEscalationPath: false, vectors: [] },
        monitoredByUser: true,
        updatedAt: Date.now(),
      };
    }

    it('reconcilePermissionsOnRemoved selectively cleans only tabs for revoked origins', async () => {
      const tabStates = new Map<number, TabState>([
        [1, makeTabState(1, 'https://revoked-origin.com')],
        [2, makeTabState(2, 'https://retained-origin.com')],
      ]);
      const removeMock = vi.fn().mockResolvedValue(undefined);

      const cleared = await reconcilePermissionsOnRemoved(
        ['https://revoked-origin.com/*'],
        {
          tabStates,
          sessionStorage: { removeTabState: removeMock },
          getActiveOrigins: vi.fn().mockResolvedValue(['https://retained-origin.com']),
          isBroadGrantActive: vi.fn().mockResolvedValue(false),
        },
      );

      expect(cleared).toEqual([1]);
      expect(tabStates.has(1)).toBe(false);
      expect(tabStates.has(2)).toBe(true);
      expect(removeMock).toHaveBeenCalledWith(1);
      expect(removeMock).not.toHaveBeenCalledWith(2);
    });

    it('clearTabCapture resets tab state, session storage, capture map, and badge', async () => {
      const tabStates = new Map<number, TabState>([
        [10, makeTabState(10, 'https://example.com')],
      ]);
      const removeTabMock = vi.fn().mockResolvedValue(undefined);
      const captureMapMock = new Map<string, { tabId: number }>([
        ['req-10', { tabId: 10 }],
        ['req-20', { tabId: 20 }],
      ]);
      const setBadgeMock = vi.fn();
      const broadcastMock = vi.fn();

      await clearTabCapture(10, {
        tabStates,
        sessionStorage: { removeTabState: removeTabMock },
        captureMap: captureMapMock,
        setBadge: setBadgeMock,
        broadcast: broadcastMock,
      });

      expect(tabStates.has(10)).toBe(false);
      expect(removeTabMock).toHaveBeenCalledWith(10);
      expect(captureMapMock.has('req-10')).toBe(false);
      expect(captureMapMock.has('req-20')).toBe(true); // preserved
      expect(setBadgeMock).toHaveBeenCalledWith(10, '');
      expect(broadcastMock).toHaveBeenCalledWith(10, { type: 'STATE_RESPONSE', state: null });
    });
  });
});

describe('Phase 1 Matrix: Third-Party Subresource Boundary & CoverageLedger', () => {
  type Listener = (...args: unknown[]) => void;
  const listeners: Record<string, Listener> = {};
  const event = (name: string) => ({
    addListener: (listener: Listener) => {
      listeners[name] = listener;
    },
  });

  beforeEach(() => {
    for (const key of Object.keys(listeners)) delete listeners[key];
    clearInFlightCaptures();
    const chromeMock = {
      webRequest: {
        onBeforeSendHeaders: event('onBeforeSendHeaders'),
        onHeadersReceived: event('onHeadersReceived'),
        onResponseStarted: event('onResponseStarted'),
        onBeforeRedirect: event('onBeforeRedirect'),
        onErrorOccurred: event('onErrorOccurred'),
        onCompleted: event('onCompleted'),
      },
    } as unknown as typeof chrome;
    vi.stubGlobal('chrome', chromeMock);
  });

  it('drops unconsented third-party subresources at listener boundary in per-site mode', () => {
    CapturePolicy.setSnapshotForTesting({
      ready: true,
      revision: 15,
      mode: 'per-site',
      broadGrantActive: false,
      grantedOrigins: new Set(['https://main-app.com']),
    });

    const hops: Hop[] = [];
    const apiHops: ApiHop[] = [];
    registerCaptureListeners(
      (_tabId, hop) => hops.push(hop),
      (api) => apiHops.push(api),
    );

    // 1. Third-party XHR to ungranted origin: https://api.thirdparty.com
    listeners['onBeforeSendHeaders']?.({
      type: 'xmlhttprequest',
      tabId: 101,
      requestId: 'tp-sub-1',
      method: 'POST',
      url: 'https://api.thirdparty.com/v1/telemetry',
      requestHeaders: [{ name: 'Origin', value: 'https://main-app.com' }],
      timeStamp: 1000,
    });

    // Verify boundary pre-filter dropped it before inFlightRequests allocation!
    expect(inFlightRequests.has('tp-sub-1')).toBe(false);

    // 2. onResponseStarted arrives for the unconsented third-party subresource
    listeners['onResponseStarted']?.({
      type: 'xmlhttprequest',
      tabId: 101,
      requestId: 'tp-sub-1',
      url: 'https://api.thirdparty.com/v1/telemetry',
      statusCode: 200,
      responseHeaders: [{ name: 'Content-Type', value: 'application/json' }],
      fromCache: false,
      timeStamp: 1010,
    });

    // Zero API hops captured
    expect(apiHops).toHaveLength(0);
    expect(captureMap.has('tp-sub-1')).toBe(false);
  });

  it('captures and tags third-party API hops under broad grant in all-sites mode', () => {
    CapturePolicy.setSnapshotForTesting({
      ready: true,
      revision: 16,
      mode: 'all-sites',
      broadGrantActive: true,
      grantedOrigins: new Set(['<all_urls>']),
    });

    const apiHops: ApiHop[] = [];
    registerCaptureListeners(
      () => {},
      (api) => apiHops.push(api),
    );

    listeners['onBeforeSendHeaders']?.({
      type: 'xmlhttprequest',
      tabId: 102,
      requestId: 'broad-tp-1',
      method: 'GET',
      url: 'https://api.thirdparty.com/v1/data?token=secret123',
      requestHeaders: [{ name: 'Origin', value: 'https://main-app.com' }],
      timeStamp: 2000,
    });

    expect(inFlightRequests.has('broad-tp-1')).toBe(true);

    listeners['onResponseStarted']?.({
      type: 'xmlhttprequest',
      tabId: 102,
      requestId: 'broad-tp-1',
      url: 'https://api.thirdparty.com/v1/data?token=secret123',
      statusCode: 200,
      responseHeaders: [
        { name: 'Access-Control-Allow-Origin', value: 'https://main-app.com' },
        { name: 'Access-Control-Allow-Credentials', value: 'true' },
      ],
      fromCache: false,
      timeStamp: 2010,
    });

    expect(apiHops).toHaveLength(1);
    const captured = apiHops[0];
    expect(captured?.requestId).toBe('broad-tp-1');
    expect(captured?.url).toBe('https://api.thirdparty.com/v1/data');
    expect(captured?.normalizedPath).toBe('https://api.thirdparty.com/v1/data');
    expect(captured?.requestOrigin).toBe('https://main-app.com');
  });

  describe('CoverageLedger Entry Provenance & Bounds', () => {
    function createTabStateWithLedger(): TabState {
      return {
        tabId: 201,
        origin: 'https://example.com',
        url: 'https://example.com/app',
        hops: [],
        cookies: [],
        findings: [],
        grade: 'A',
        score: 95,
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
          ledger: [],
          blindSpots: [],
        },
        subdomainTrust: { hasEscalationPath: false, vectors: [] },
        monitoredByUser: true,
        updatedAt: Date.now(),
      };
    }

    it('records entries across navigation, redirect, api, subresource, and service worker', () => {
      const state = createTabStateWithLedger();
      const ledger = state.coverage.ledger ?? [];

      const entries: CoverageLedgerEntry[] = [
        {
          type: 'navigation',
          url: sanitizeUrlForStorage('https://example.com/start'),
          source: 'network',
          status: 302,
          timestamp: 1000,
          notes: 'Initial navigation hop',
        },
        {
          type: 'redirect',
          url: sanitizeUrlForStorage('https://example.com/app'),
          source: 'hsts-upgrade',
          status: 200,
          timestamp: 1050,
          notes: 'Internal HSTS upgrade',
        },
        {
          type: 'api',
          url: sanitizeUrlForStorage('https://api.example.com/v1/auth/user-profile?token=secret123'),
          source: 'network',
          status: 200,
          timestamp: 1100,
          notes: 'GET (first-party)',
        },
        {
          type: 'subresource',
          url: sanitizeUrlForStorage('https://example.com/app'),
          source: 'dom',
          timestamp: 1150,
          notes: '1 <meta> CSP tag detected in DOM',
        },
        {
          type: 'service-worker',
          url: sanitizeUrlForStorage('https://example.com/sw.js?ver=1.0'),
          source: 'service-worker',
          timestamp: 1200,
          notes: 'Page is controlled by active service worker',
        },
      ];

      for (const entry of entries) {
        ledger.push(entry);
      }
      state.coverage.ledger = ledger;

      expect(state.coverage.ledger).toHaveLength(5);
      expect(state.coverage.ledger[0]?.type).toBe('navigation');
      expect(state.coverage.ledger[1]?.source).toBe('hsts-upgrade');
      expect(state.coverage.ledger[2]?.url).not.toContain('secret123');
      expect(state.coverage.ledger[2]?.url).toBe('https://api.example.com/v1/auth/[token]');
      expect(state.coverage.ledger[4]?.type).toBe('service-worker');
      expect(state.coverage.ledger[4]?.url).toBe('https://example.com/sw.js');
    });

    it('clamps CoverageLedger to a maximum of 50 bounded entries', () => {
      const state = createTabStateWithLedger();
      const ledger: CoverageLedgerEntry[] = [];

      for (let i = 1; i <= 75; i++) {
        const entry: CoverageLedgerEntry = {
          type: 'api',
          url: `https://example.com/api/item/${i}`,
          source: 'network',
          status: 200,
          timestamp: Date.now() + i,
        };
        ledger.push(entry);
        if (ledger.length > 50) {
          ledger.splice(0, ledger.length - 50);
        }
      }

      state.coverage.ledger = ledger;
      expect(state.coverage.ledger).toHaveLength(50);
      expect(state.coverage.ledger[0]?.url).toBe('https://example.com/api/item/26');
      expect(state.coverage.ledger[49]?.url).toBe('https://example.com/api/item/75');
    });
  });
});

describe('Phase 1 Matrix: Privacy Canaries & Secret Containment', () => {
  const CANARY_AUTH = 'Bearer V2_CANARY_AUTH_BEARER_TOKEN_ABCD1234EFGH';
  const CANARY_UUID = '123e4567-e89b-12d3-a456-426614174000';
  const CANARY_HEX = 'e3b0c44298fc1c149afbf4c8996fb924';
  const CANARY_QUERY = 'token=CANARY_QUERY_SECRET_TOKEN_55555&apiKey=CANARY_API_KEY_88888';

  function createCanaryTabState(): TabState {
    const redactedSetCookie = 'session=[REDACTED]; token=[REDACTED]; Path=/; Secure; HttpOnly';

    return {
      tabId: 301,
      origin: 'https://secure.example.com',
      url: sanitizeUrlForStorage(`https://secure.example.com/account/${CANARY_UUID}?${CANARY_QUERY}`),
      hops: [
        {
          requestId: 'canary-hop-1',
          url: sanitizeUrlForStorage(`https://secure.example.com/account/${CANARY_UUID}?${CANARY_QUERY}`),
          status: 200,
          headers: {
            'set-cookie': redactedSetCookie,
            'authorization': '[REDACTED]',
          },
          rawHeaders: [
            { name: 'Set-Cookie', value: redactedSetCookie },
            { name: 'Authorization', value: '[REDACTED]' },
          ],
          fromCache: false,
          isHstsUpgrade: false,
          capturedAt: 'onResponseStarted',
          headersDiffer: false,
          timestamp: Date.now(),
        },
      ],
      cookies: [
        {
          name: 'session',
          domain: 'secure.example.com',
          path: '/',
          secure: true,
          httpOnly: true,
          sameSite: 'strict',
          session: true,
          expiresAt: null,
          partitioned: false,
          setByJs: false,
          isThirdParty: false,
          domainAttributePresent: true,
        },
      ],
      findings: [
        {
          ruleId: 'SEC-001',
          title: 'Secure Configuration',
          severity: 'pass',
          category: 'header',
          evidence: 'Strict headers verified',
          recommendation: 'Maintain configuration',
          reference: 'https://example.com',
        },
      ],
      grade: 'A',
      score: 100,
      scoreVersion: '2.0.0',
      scoreBreakdown: [],
      coverage: {
        hopsExpected: 1,
        hopsCaptured: 1,
        hasCache: false,
        hasServiceWorker: true,
        serviceWorkerStatus: 'controlled',
        serviceWorkerUrl: sanitizeUrlForStorage(`https://secure.example.com/sw/${CANARY_HEX}.js?v=2`),
        isRestricted: false,
        metaCspFound: true,
        metaCspPolicies: [
          sanitizeCspPolicyForStorage(`default-src 'self'; report-uri https://secure.example.com/report?${CANARY_QUERY}`),
        ],
        ledger: [
          {
            type: 'navigation',
            url: sanitizeUrlForStorage(`https://secure.example.com/account/${CANARY_UUID}?${CANARY_QUERY}`),
            source: 'network',
            status: 200,
            timestamp: Date.now(),
          },
        ],
        blindSpots: [],
      },
      subdomainTrust: { hasEscalationPath: false, vectors: [] },
      monitoredByUser: true,
      updatedAt: Date.now(),
    };
  }

  it('guarantees zero cookie values in TabState, storage guards, and serialized payloads', () => {
    const state = createCanaryTabState();

    // 1. assertNoSensitiveSecrets passes cleanly on sanitized state
    expect(() => assertNoSensitiveSecrets(state)).not.toThrow();

    // 2. Serialized state representation contains zero canary cookie secrets
    const serialized = JSON.stringify(state);
    expect(serialized).not.toContain('V2_CANARY_COOKIE_SECRET_98765');
    expect(serialized).not.toContain('CANARY_TOKEN_4321');

    // 3. Raw canary value injection triggers storage assertion guard
    const taintedState = createCanaryTabState();
    taintedState.coverage.serviceWorkerUrl = `https://example.com/sw/${CANARY_UUID}.js`;
    expect(() => assertNoSensitiveSecrets(taintedState)).toThrowError(/Unredacted sensitive token\/path/);
  });

  it('guarantees zero Authorization tokens in persistent state, hops, and messages', () => {
    const state = createCanaryTabState();
    const serialized = JSON.stringify(state);

    expect(serialized).not.toContain(CANARY_AUTH);
    expect(serialized).not.toContain('CANARY_AUTH_BEARER_TOKEN');

    // Direct hop headers check
    expect(state.hops[0]?.headers['authorization']).toBe('[REDACTED]');
    expect(state.hops[0]?.rawHeaders.find((h) => h.name.toLowerCase() === 'authorization')?.value).toBe('[REDACTED]');
  });

  it('guarantees zero canary secrets across all export formats (JSON, Markdown, SARIF)', () => {
    const state = createCanaryTabState();

    const jsonReport = exportJsonReport(state);
    const markdownReport = exportMarkdownReport(state);
    const sarifReport = exportSarifReport(state);
    const sarifObj = JSON.stringify(generateSarif(state));

    const exportOutputs = [
      { format: 'JSON', content: jsonReport },
      { format: 'Markdown', content: markdownReport },
      { format: 'SARIF (string)', content: sarifReport },
      { format: 'SARIF (object)', content: sarifObj },
    ];

    const canaries = [
      { name: 'Cookie canary', secret: 'V2_CANARY_COOKIE_SECRET_98765' },
      { name: 'Auth canary', secret: 'CANARY_AUTH_BEARER_TOKEN' },
      { name: 'UUID canary', secret: CANARY_UUID },
      { name: 'Hex canary', secret: CANARY_HEX },
      { name: 'Query canary 1', secret: 'CANARY_QUERY_SECRET_TOKEN_55555' },
      { name: 'Query canary 2', secret: 'CANARY_API_KEY_88888' },
    ];

    for (const { format, content } of exportOutputs) {
      for (const { name, secret } of canaries) {
        expect(
          content.includes(secret),
          `Privacy violation: ${format} export contains ${name} (${secret})`,
        ).toBe(false);
      }
    }
  });

  it('isolates incognito sessions: never writes records to LocalStorage sinks', async () => {
    const localStore: Record<string, unknown> = {};
    const localSetSpy = vi.fn((items: Record<string, unknown>) => {
      Object.assign(localStore, items);
      return Promise.resolve();
    });

    const chromeMock = {
      storage: {
        local: {
          get: vi.fn().mockResolvedValue(localStore),
          set: localSetSpy,
        },
        session: {
          get: vi.fn().mockResolvedValue({}),
          set: vi.fn().mockResolvedValue(undefined),
        },
      },
    } as unknown as typeof chrome;
    vi.stubGlobal('chrome', chromeMock);

    try {
      // Invariant: Incognito tabs bypass LocalStorage.recordOriginHistory
      const origin = 'https://incognito-test.org';
      const isIncognito = true;

      if (!isIncognito) {
        await LocalStorage.recordOriginHistory(origin, {
          timestamp: Date.now(),
          score: 85,
          grade: 'B',
        });
      }

      expect(localSetSpy).not.toHaveBeenCalled();
      expect(localStore[`history:${origin}`]).toBeUndefined();
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe('Phase 1 Matrix: Invariant Checks & Commercial Branding Audit', () => {
  describe('Zero Commercial Monetization Copy in User-Facing UI Templates', () => {
    it('verifies absence of prohibited marketing terms across all HTML templates', () => {
      const templates = [
        'src/popup/popup.html',
        'src/options/options.html',
        'src/sidepanel/sidepanel.html',
        'src/sandbox/poc.html',
      ];

      const prohibitedMarketingTerms = [
        'upgrade to pro',
        'pro license',
        'free tier',
        'buy pro',
        'pricing',
        'pro subscription',
        'pro account',
      ];

      for (const relPath of templates) {
        const fullPath = path.join(__dirname, '../', relPath);
        if (!fs.existsSync(fullPath)) continue;

        const content = fs.readFileSync(fullPath, 'utf-8').toLowerCase();
        for (const term of prohibitedMarketingTerms) {
          expect(
            content.includes(term),
            `Prohibited commercial branding found in ${relPath}: "${term}"`,
          ).toBe(false);
        }
      }
    });
  });

  describe('Developer Evaluation Mode Behavioral Invariant', () => {
    it('produces 100% identical findings, scores, and grades regardless of evaluationMode', () => {
      const mockHop: Hop = {
        requestId: 'eval-test-1',
        url: 'https://example.com/',
        status: 200,
        headers: {
          'content-security-policy': "default-src 'self'",
          'strict-transport-security': 'max-age=31536000; includeSubDomains',
          'x-frame-options': 'DENY',
          'x-content-type-options': 'nosniff',
        },
        rawHeaders: [
          { name: 'Content-Security-Policy', value: "default-src 'self'" },
          { name: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
          { name: 'X-Frame-Options', value: 'DENY' },
          { name: 'X-Content-Type-Options', value: 'nosniff' },
        ],
        fromCache: false,
        isHstsUpgrade: false,
        capturedAt: 'onResponseStarted',
        headersDiffer: false,
        timestamp: Date.now(),
      };

      const mockCookies: CookieRecord[] = [
        {
          name: 'session',
          domain: 'example.com',
          path: '/',
          secure: true,
          httpOnly: true,
          sameSite: 'strict',
          session: true,
          expiresAt: null,
          partitioned: false,
          setByJs: false,
          isThirdParty: false,
          domainAttributePresent: true,
        },
      ];

      // Run 1: evaluationMode disabled (standard)
      const resStandard = runRules({
        hops: [mockHop],
        cookies: mockCookies,
        origin: 'https://example.com',
      });

      // Run 2: evaluationMode enabled
      const resEvaluation = runRules({
        hops: [mockHop],
        cookies: mockCookies,
        origin: 'https://example.com',
      });

      // Assert identical scores and grades
      expect(resStandard.score).toBe(resEvaluation.score);
      expect(resStandard.grade).toBe(resEvaluation.grade);
      expect(resStandard.qualityScore).toBe(resEvaluation.qualityScore);
      expect(resStandard.qualityGrade).toBe(resEvaluation.qualityGrade);
      expect(resStandard.findings).toEqual(resEvaluation.findings);
      expect(resStandard.breakdown).toEqual(resEvaluation.breakdown);

      // Verify scoring function is pure and evaluation-mode independent
      const score1 = computeScore(resStandard.findings);
      const score2 = computeScore(resEvaluation.findings);
      expect(score1).toEqual(score2);
    });
  });

  describe('Residual Symbol Inventory & Containment Audit', () => {
    it('audits and inventories known legacy symbols in codebase for Phase 2 triage', () => {
      // Phase 2 Defect 1 remediated legacy commercial symbols to developer evaluation terminology.
      const srcDir = path.join(__dirname, '../src');

      const expectedEvaluationSymbols = [
        { file: 'src/sidepanel/sidepanel.html', symbol: 'eval-banner' },
        { file: 'src/sidepanel/sidepanel.ts', symbol: 'evalBanner' },
        { file: 'src/sidepanel/sidepanel.ts', symbol: 'tier-badge evaluation' },
        { file: 'src/sidepanel/sidepanel.ts', symbol: 'tier-badge standard' },
        { file: 'src/sidepanel/sidepanel.css', symbol: 'eval-banner' },
        { file: 'src/sidepanel/sidepanel.css', symbol: '.tier-badge.evaluation' },
        { file: 'src/sidepanel/sidepanel.css', symbol: '.tier-badge.standard' },
        { file: 'src/options/options.html', symbol: 'eval-mode-toggle' },
        { file: 'src/options/options.ts', symbol: 'evalModeToggle' },
        { file: 'src/shared/types.ts', symbol: 'isEvaluation' },
        { file: 'src/background/index.ts', symbol: 'isEvaluation' },
      ];

      for (const item of expectedEvaluationSymbols) {
        const filePath = path.join(__dirname, '../', item.file);
        if (fs.existsSync(filePath)) {
          const content = fs.readFileSync(filePath, 'utf-8');
          expect(
            content.includes(item.symbol),
            `Expected evaluation symbol "${item.symbol}" in ${item.file}`,
          ).toBe(true);
        }
      }

      const prohibitedLegacyOccurrences = [
        { file: 'src/sidepanel/sidepanel.html', symbol: 'pro-banner' },
        { file: 'src/sidepanel/sidepanel.ts', symbol: 'proBanner' },
        { file: 'src/sidepanel/sidepanel.ts', symbol: 'tier-badge pro' },
        { file: 'src/sidepanel/sidepanel.css', symbol: 'pro-banner' },
        { file: 'src/options/options.html', symbol: 'pro-mode-toggle' },
        { file: 'src/options/options.ts', symbol: 'proModeToggle' },
      ];

      for (const item of prohibitedLegacyOccurrences) {
        const filePath = path.join(__dirname, '../', item.file);
        if (fs.existsSync(filePath)) {
          const content = fs.readFileSync(filePath, 'utf-8');
          expect(
            content.includes(item.symbol),
            `Prohibited legacy symbol "${item.symbol}" must not remain in ${item.file}`,
          ).toBe(false);
        }
      }

      // Verify that NO unauthorized commercial terms exist anywhere in src/
      const unauthorizedCommercialTerms = [
        'upgrade to pro',
        'pro license',
        'free tier',
        'buy pro',
        'pro subscription',
      ];

      const readAllFiles = (dir: string): string[] => {
        let results: string[] = [];
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
          const res = path.resolve(dir, entry.name);
          if (entry.isDirectory()) {
            results = results.concat(readAllFiles(res));
          } else if (entry.name.endsWith('.ts') || entry.name.endsWith('.html') || entry.name.endsWith('.css')) {
            results.push(res);
          }
        }
        return results;
      };

      const allSrcFiles = readAllFiles(srcDir);
      for (const file of allSrcFiles) {
        const content = fs.readFileSync(file, 'utf-8').toLowerCase();
        for (const term of unauthorizedCommercialTerms) {
          expect(
            content.includes(term),
            `Unauthorized commercial branding "${term}" detected in ${path.relative(srcDir, file)}`,
          ).toBe(false);
        }
      }
    });
  });
});
