import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Mock } from 'vitest';

const {
  mockLocalStorageData,
  mockSessionStorageData,
  webRequestListeners,
  openBrowserTabs,
} = vi.hoisted(() => {
  const mockLocalStorageData: Record<string, unknown> = {};
  const mockSessionStorageData: Record<string, unknown> = {};
  const webRequestListeners: Record<string, Array<(...args: unknown[]) => unknown>> = {
    onBeforeSendHeaders: [],
    onHeadersReceived: [],
    onResponseStarted: [],
    onBeforeRedirect: [],
    onErrorOccurred: [],
    onCompleted: [],
  };

  const createWebRequestListener = (eventName: string) => ({
    addListener: vi.fn((listener: (...args: unknown[]) => unknown) => {
      webRequestListeners[eventName]?.push(listener);
    }),
    removeListener: vi.fn(),
    hasListener: vi.fn(),
  });

  const dummyEvent = () => ({
    addListener: vi.fn(),
    removeListener: vi.fn(),
    hasListener: vi.fn(),
  });

  const openBrowserTabs: Array<{ id: number; url?: string; incognito?: boolean }> = [];

  (globalThis as unknown as { chrome: unknown }).chrome = {
    webNavigation: {
      onBeforeNavigate: dummyEvent(),
      onCommitted: dummyEvent(),
      onHistoryStateUpdated: dummyEvent(),
    },
    webRequest: {
      onBeforeSendHeaders: createWebRequestListener('onBeforeSendHeaders'),
      onHeadersReceived: createWebRequestListener('onHeadersReceived'),
      onResponseStarted: createWebRequestListener('onResponseStarted'),
      onBeforeRedirect: createWebRequestListener('onBeforeRedirect'),
      onErrorOccurred: createWebRequestListener('onErrorOccurred'),
      onCompleted: createWebRequestListener('onCompleted'),
    },
    cookies: {
      onChanged: dummyEvent(),
      getAll: vi.fn().mockResolvedValue([]),
    },
    tabs: {
      onRemoved: dummyEvent(),
      query: vi.fn((_q: unknown, cb?: (tabs: unknown[]) => void) => {
        if (typeof cb === 'function') cb([...openBrowserTabs]);
        return Promise.resolve([...openBrowserTabs]);
      }),
      get: vi.fn((tabId: number) => {
        const found = openBrowserTabs.find((t) => t.id === tabId);
        if (found) return Promise.resolve({ ...found });
        return Promise.reject(new Error(`Tab ${tabId} not found`));
      }),
      create: vi.fn().mockResolvedValue({}),
      reload: vi.fn().mockResolvedValue(undefined),
    },
    runtime: {
      id: 'mock-extension-id',
      onConnect: dummyEvent(),
      onMessage: dummyEvent(),
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
      onAdded: dummyEvent(),
      getAll: vi.fn().mockResolvedValue({ origins: ['<all_urls>'] }),
      contains: vi.fn((_p: unknown, cb?: (res: boolean) => void) => {
        if (typeof cb === 'function') cb(true);
        return Promise.resolve(true);
      }),
      request: vi.fn().mockResolvedValue(true),
      remove: vi.fn().mockResolvedValue(true),
    },
    storage: {
      local: {
        get: vi.fn((keys?: unknown, cb?: unknown) => {
          const callback = typeof keys === 'function' ? (keys as (r: unknown) => void) : (typeof cb === 'function' ? (cb as (r: unknown) => void) : undefined);
          let res: Record<string, unknown> = { ...mockLocalStorageData };
          if (typeof keys === 'string') {
            res = { [keys]: mockLocalStorageData[keys] };
          } else if (Array.isArray(keys)) {
            res = {};
            for (const k of keys as string[]) {
              if (mockLocalStorageData[k] !== undefined) res[k] = mockLocalStorageData[k];
            }
          }
          if (callback) callback(res);
          return Promise.resolve(res);
        }),
        set: vi.fn((items: Record<string, unknown>, cb?: () => void) => {
          Object.assign(mockLocalStorageData, items);
          if (typeof cb === 'function') cb();
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
        get: vi.fn((keys?: unknown, cb?: unknown) => {
          const callback = typeof keys === 'function' ? (keys as (r: unknown) => void) : (typeof cb === 'function' ? (cb as (r: unknown) => void) : undefined);
          let res: Record<string, unknown> = { ...mockSessionStorageData };
          if (typeof keys === 'string') {
            res = { [keys]: mockSessionStorageData[keys] };
          } else if (Array.isArray(keys)) {
            res = {};
            for (const k of keys as string[]) {
              if (mockSessionStorageData[k] !== undefined) res[k] = mockSessionStorageData[k];
            }
          }
          if (callback) callback(res);
          return Promise.resolve(res);
        }),
        set: vi.fn((items: Record<string, unknown>, cb?: () => void) => {
          Object.assign(mockSessionStorageData, items);
          if (typeof cb === 'function') cb();
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

  return { mockLocalStorageData, mockSessionStorageData, webRequestListeners, openBrowserTabs };
});

import {
  registerCaptureListeners,
  captureMap,
  inFlightRequests,
  incognitoTabIds,
  isCaptureActiveForUrl,
} from '../../src/background/capture';
import { CapturePolicy, isCaptureAllowedAtBoundary } from '../../src/background/capture-policy';
import { PermissionsService } from '../../src/background/permissions';
import {
  onHopComplete,
  clearBadgesOnAllTabs,
  tabGenerations,
  pendingPrivacyLookups,
} from '../../src/background/index';
import { tabStates, originAuthBaselines } from '../../src/background/lifecycle';
import {
  assertNoSensitiveSecrets,
  SessionStorage,
  LocalStorage,
} from '../../src/shared/storage';
import {
  exportJsonReport,
  exportMarkdownReport,
  exportSarifReport,
  generateSarif,
} from '../../src/shared/export';
import { PortRegistry } from '../../src/shared/messaging';
import { POPUP_PORT_NAME, DEFAULT_SETTINGS, STORAGE_KEYS } from '../../src/shared/constants';
import type { Hop, ApiHop, TabState, SettingsV2 } from '../../src/shared/types';
import { SettingsService, settingsTransitionPipeline } from '../../src/shared/settings';

describe('Adversarial Verification Suite — Phase 1', () => {
  const CANARY_COOKIE_VALUE = 'CANARY_SECRET_123';
  const CANARY_BEARER_TOKEN = 'SECRET_TOKEN_XYZ';
  const CANARY_LONG_SECRET = 'secret_token_canary_long_hash_4a8f9c2d1e0b';
  const CANARY_PROXY_PWD = 'SECRET_PROXY_PASSWORD_888';
  const CANARY_QUERY_TOKEN = 'SENSITIVE_PARAM_456';
  const CANARY_API_KEY = 'SENSITIVE_API_KEY_789';

  beforeEach(() => {
    // Reset caches and settings
    SettingsService.clearCache();
    for (const key of Object.keys(mockLocalStorageData)) delete mockLocalStorageData[key];
    for (const key of Object.keys(mockSessionStorageData)) delete mockSessionStorageData[key];
    openBrowserTabs.length = 0;
    tabStates.clear();
    originAuthBaselines.clear();
    captureMap.clear();
    inFlightRequests.clear();
    incognitoTabIds.clear();
    tabGenerations.clear();
    pendingPrivacyLookups.clear();
    vi.clearAllMocks();

    // Default: configured all-sites mode with broad grant active
    mockLocalStorageData[STORAGE_KEYS.SETTINGS] = {
      ...DEFAULT_SETTINGS,
      monitoringMode: 'all-sites',
    };
    (chrome.permissions.getAll as Mock).mockResolvedValue({ origins: ['<all_urls>'] });
    (chrome.permissions.contains as Mock).mockImplementation((_p: unknown, cb?: (res: boolean) => void) => {
      if (typeof cb === 'function') cb(true);
      return Promise.resolve(true);
    });

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

  // =========================================================================
  // TASK 1: Secret Canaries, Boundary Redaction, Storage Guards & Export Sinks
  // =========================================================================
  describe('Task 1: Secret Canaries and Redaction Defenses', () => {
    it('redacts sensitive cookie values, bearer tokens, and query params at the WebRequest boundary', () => {
      const capturedHops: Hop[] = [];
      const capturedApiHops: ApiHop[] = [];

      registerCaptureListeners(
        (_tabId, hop) => capturedHops.push(hop),
        (apiHop) => capturedApiHops.push(apiHop),
      );

      const navUrl = `https://secure.example.com/login?token=${CANARY_QUERY_TOKEN}&apikey=${CANARY_API_KEY}&safeParam=regular_value`;
      const navRequestId = 'nav-canary-001';
      const navTabId = 10;

      // 1. Stage 1: onHeadersReceived with sensitive Set-Cookie and Authorization headers
      const onHeadersReceived = webRequestListeners['onHeadersReceived']?.at(-1);
      expect(onHeadersReceived).toBeDefined();

      onHeadersReceived?.({
        type: 'main_frame',
        tabId: navTabId,
        requestId: navRequestId,
        url: navUrl,
        statusCode: 200,
        responseHeaders: [
          {
            name: 'Set-Cookie',
            value: `session=${CANARY_COOKIE_VALUE}; Path=/; Secure; HttpOnly; SameSite=Strict`,
          },
          { name: 'Authorization', value: `Bearer ${CANARY_BEARER_TOKEN}` },
          { name: 'Proxy-Authorization', value: `Basic ${CANARY_PROXY_PWD}` },
          { name: 'X-Safe-Header', value: 'harmless_metadata' },
        ],
        timeStamp: 1000,
      });

      // 2. Stage 2: onResponseStarted
      const onResponseStarted = webRequestListeners['onResponseStarted']?.at(-1);
      expect(onResponseStarted).toBeDefined();

      onResponseStarted?.({
        type: 'main_frame',
        tabId: navTabId,
        requestId: navRequestId,
        url: navUrl,
        statusCode: 200,
        responseHeaders: [
          {
            name: 'Set-Cookie',
            value: `session=${CANARY_COOKIE_VALUE}; Path=/; Secure; HttpOnly; SameSite=Strict`,
          },
          { name: 'Authorization', value: `Bearer ${CANARY_BEARER_TOKEN}` },
          { name: 'Proxy-Authorization', value: `Basic ${CANARY_PROXY_PWD}` },
          { name: 'X-Safe-Header', value: 'harmless_metadata' },
        ],
        fromCache: false,
        timeStamp: 1010,
      });

      expect(capturedHops).toHaveLength(1);
      const hop = capturedHops[0];
      if (hop === undefined) {
        throw new Error('Expected captured hop');
      }

      // Assert zero secret canaries in normalized headers
      expect(hop.headers['set-cookie']).toBe('session=[REDACTED]; Path=/; Secure; HttpOnly; SameSite=Strict');
      expect(hop.headers['set-cookie']?.includes(CANARY_COOKIE_VALUE)).toBe(false);
      expect(hop.headers['authorization']).toBe('[REDACTED]');
      expect(hop.headers['authorization']?.includes(CANARY_BEARER_TOKEN)).toBe(false);
      expect(hop.headers['proxy-authorization']).toBe('[REDACTED]');
      expect(hop.headers['proxy-authorization']?.includes(CANARY_PROXY_PWD)).toBe(false);
      expect(hop.headers['x-safe-header']).toBe('harmless_metadata');

      // Assert zero secret canaries in rawHeaders
      for (const raw of hop.rawHeaders) {
        expect(raw.value.includes(CANARY_COOKIE_VALUE)).toBe(false);
        expect(raw.value.includes(CANARY_BEARER_TOKEN)).toBe(false);
        expect(raw.value.includes(CANARY_PROXY_PWD)).toBe(false);
      }

      // Assert entire query string was stripped for privacy
      expect(hop.url.includes('?')).toBe(false);
      expect(hop.url.includes(CANARY_QUERY_TOKEN)).toBe(false);
      expect(hop.url.includes(CANARY_API_KEY)).toBe(false);
      expect(hop.url.includes('safeParam')).toBe(false);

      // 3. API Request: onBeforeSendHeaders + onResponseStarted for XHR
      const onBeforeSendHeaders = webRequestListeners['onBeforeSendHeaders']?.at(-1);
      const apiUrl = `https://secure.example.com/api/v1/user?auth_token=${CANARY_QUERY_TOKEN}`;
      const apiReqId = 'api-canary-002';

      onBeforeSendHeaders?.({
        type: 'xmlhttprequest',
        tabId: navTabId,
        requestId: apiReqId,
        url: apiUrl,
        method: 'POST',
        requestHeaders: [
          { name: 'Authorization', value: `Bearer ${CANARY_BEARER_TOKEN}` },
          { name: 'Cookie', value: `session=${CANARY_COOKIE_VALUE}; tracker=abc` },
        ],
        timeStamp: 2000,
      });

      onResponseStarted?.({
        type: 'xmlhttprequest',
        tabId: navTabId,
        requestId: apiReqId,
        url: apiUrl,
        statusCode: 200,
        responseHeaders: [
          { name: 'Authorization', value: `Bearer ${CANARY_BEARER_TOKEN}` },
        ],
        fromCache: false,
        timeStamp: 2050,
      });

      expect(capturedApiHops).toHaveLength(1);
      const apiHop = capturedApiHops[0];
      if (apiHop === undefined) {
        throw new Error('Expected captured API hop');
      }

      // Assert API hop has redacted URL and zero canaries
      expect(apiHop.url.includes(CANARY_QUERY_TOKEN)).toBe(false);
      expect(apiHop.normalizedPath.includes(CANARY_QUERY_TOKEN)).toBe(false);
      expect(apiHop.headers['authorization']).toBe('[REDACTED]');
      expect(apiHop.rawHeaders[0]?.value).toBe('[REDACTED]');
    });

    it('assertNoSensitiveSecrets reliably catches unredacted cookies, auth headers, and url tokens', () => {
      const cleanState: TabState = {
        tabId: 55,
        origin: 'https://secure.example.com',
        url: 'https://secure.example.com/dashboard',
        hops: [
          {
            requestId: 'req-clean',
            url: 'https://secure.example.com/dashboard',
            status: 200,
            headers: {
              'set-cookie': 'session=[REDACTED]; Path=/; Secure; HttpOnly',
              authorization: '[REDACTED]',
              'proxy-authorization': '[REDACTED]',
            },
            rawHeaders: [
              { name: 'Set-Cookie', value: 'session=[REDACTED]; Path=/; Secure; HttpOnly' },
              { name: 'Authorization', value: '[REDACTED]' },
              { name: 'Proxy-Authorization', value: '[REDACTED]' },
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
        findings: [],
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
          serviceWorkerUrl: 'https://secure.example.com/sw.js',
          isRestricted: false,
          metaCspFound: false,
        },
        subdomainTrust: { hasEscalationPath: false, vectors: [] },
        monitoredByUser: true,
        updatedAt: Date.now(),
      };

      // Clean state must pass
      expect(() => assertNoSensitiveSecrets(cleanState)).not.toThrow();

      // Injection 1: Cookie value present on CookieRecord
      const cookieValueLeak = structuredClone(cleanState);
      (cookieValueLeak.cookies[0] as unknown as Record<string, unknown>)['value'] = CANARY_COOKIE_VALUE;
      expect(() => assertNoSensitiveSecrets(cookieValueLeak)).toThrowError(
        /Cookie value detected on session/
      );

      // Injection 2: Unredacted Set-Cookie header in hop
      const hopSetCookieLeak = structuredClone(cleanState);
      const hop0SetCookie = hopSetCookieLeak.hops[0];
      if (hop0SetCookie === undefined) {
        throw new Error('Expected hop in cleanState');
      }
      hop0SetCookie.headers['set-cookie'] = `session=${CANARY_COOKIE_VALUE}; Path=/`;
      expect(() => assertNoSensitiveSecrets(hopSetCookieLeak)).toThrowError(
        /Unredacted set-cookie header detected/
      );

      // Injection 3: Unredacted Authorization header in hop
      const hopAuthLeak = structuredClone(cleanState);
      const hop0Auth = hopAuthLeak.hops[0];
      if (hop0Auth === undefined) {
        throw new Error('Expected hop in cleanState');
      }
      hop0Auth.headers['authorization'] = `Bearer ${CANARY_BEARER_TOKEN}`;
      expect(() => assertNoSensitiveSecrets(hopAuthLeak)).toThrowError(
        /Unredacted authorization header detected/
      );

      // Injection 4: Unredacted Authorization in hop.rawHeaders
      const hopRawAuthLeak = structuredClone(cleanState);
      const hop0Raw = hopRawAuthLeak.hops[0];
      if (hop0Raw === undefined) {
        throw new Error('Expected hop in cleanState');
      }
      hop0Raw.rawHeaders[1] = {
        name: 'Authorization',
        value: `Bearer ${CANARY_BEARER_TOKEN}`,
      };
      expect(() => assertNoSensitiveSecrets(hopRawAuthLeak)).toThrowError(
        /Unredacted Authorization rawHeader detected/
      );

      // Injection 5: Unredacted Proxy-Authorization in API endpoint
      const apiLeak = structuredClone(cleanState);
      apiLeak.apiEndpoints = new Map([
        [
          '/api/v1/data',
          {
            lastHop: {
              requestId: 'api-1',
              tabId: 55,
              url: 'https://secure.example.com/api/v1/data',
              normalizedPath: '/api/v1/data',
              method: 'GET',
              status: 200,
              headers: { 'proxy-authorization': `Basic ${CANARY_PROXY_PWD}` },
              rawHeaders: [{ name: 'Proxy-Authorization', value: `Basic ${CANARY_PROXY_PWD}` }],
              fromCache: false,
              timestamp: Date.now(),
            },
            normalizedPath: '/api/v1/data',
            findings: [],
            isFirstParty: true,
          },
        ],
      ]);
      expect(() => assertNoSensitiveSecrets(apiLeak)).toThrowError(
        /Unredacted proxy-authorization header detected/
      );

      // Injection 6: Unredacted query param in serviceWorkerUrl
      const swQueryLeak = structuredClone(cleanState);
      swQueryLeak.coverage.serviceWorkerUrl = `https://secure.example.com/sw.js?token=${CANARY_QUERY_TOKEN}`;
      expect(() => assertNoSensitiveSecrets(swQueryLeak)).toThrowError(
        /Unredacted query string detected in serviceWorkerUrl/
      );

      // Injection 7: Unredacted sensitive token/path in metaCspPolicies (>=20 char token)
      const cspTokenLeak = structuredClone(cleanState);
      cspTokenLeak.coverage.metaCspPolicies = [
        `default-src 'self'; report-uri https://secure.example.com/report/${CANARY_LONG_SECRET}`,
      ];
      expect(() => assertNoSensitiveSecrets(cspTokenLeak)).toThrowError(
        /Unredacted sensitive token\/path detected in metaCspPolicies/
      );
    });

    it('SessionStorage.setTabState aborts storage writes on any unredacted canary secret', async () => {
      const stateWithSecret: TabState = {
        tabId: 99,
        origin: 'https://secure.example.com',
        url: 'https://secure.example.com/app',
        hops: [
          {
            requestId: 'req-bad',
            url: 'https://secure.example.com/app',
            status: 200,
            headers: { authorization: `Bearer ${CANARY_BEARER_TOKEN}` },
            rawHeaders: [],
            fromCache: false,
            isHstsUpgrade: false,
            capturedAt: 'onResponseStarted',
            headersDiffer: false,
            timestamp: Date.now(),
          },
        ],
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
        subdomainTrust: { hasEscalationPath: false, vectors: [] },
        monitoredByUser: true,
        updatedAt: Date.now(),
      };

      await expect(SessionStorage.setTabState(stateWithSecret)).rejects.toThrowError(
        /Unredacted authorization header detected/
      );

      // Verify nothing was written to mockSessionStorageData
      expect(mockSessionStorageData['tab:99']).toBeUndefined();
    });

    it('ensures PortRegistry broadcasts and UI export sinks contain ZERO secret canaries', () => {
      const sanitizedState: TabState = {
        tabId: 105,
        origin: 'https://secure.example.com',
        url: 'https://secure.example.com/checkout?token=[redacted]',
        hops: [
          {
            requestId: 'hop-1',
            url: 'https://secure.example.com/checkout?token=[redacted]',
            status: 200,
            headers: {
              'set-cookie': 'session=[REDACTED]; Path=/; Secure; HttpOnly',
              authorization: '[REDACTED]',
            },
            rawHeaders: [
              { name: 'Set-Cookie', value: 'session=[REDACTED]; Path=/; Secure; HttpOnly' },
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
            title: 'Sample Security Finding',
            severity: 'medium',
            category: 'header',
            impact: 'Potential exposure',
            evidence: 'Header checked',
            recommendation: 'Configure securely',
            reference: 'https://docs.example.com',
          },
        ],
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
        },
        subdomainTrust: { hasEscalationPath: false, vectors: [] },
        monitoredByUser: true,
        updatedAt: Date.now(),
      };

      // 1. Port Broadcast Channel verification
      const registry = new PortRegistry();
      const transmittedMessages: unknown[] = [];

      const mockPort = {
        name: POPUP_PORT_NAME,
        postMessage: vi.fn((msg: unknown) => {
          transmittedMessages.push(msg);
        }),
        onDisconnect: {
          addListener: vi.fn(),
          removeListener: vi.fn(),
          hasListener: vi.fn(),
        },
        onMessage: {
          addListener: vi.fn(),
          removeListener: vi.fn(),
          hasListener: vi.fn(),
        },
        disconnect: vi.fn(),
      } as unknown as chrome.runtime.Port;

      registry.register(mockPort, 105);
      registry.broadcast(105, { type: 'TAB_STATE_UPDATE', state: sanitizedState });

      const broadcastJson = JSON.stringify(transmittedMessages);
      expect(broadcastJson.includes(CANARY_COOKIE_VALUE)).toBe(false);
      expect(broadcastJson.includes(CANARY_BEARER_TOKEN)).toBe(false);
      expect(broadcastJson.includes(CANARY_QUERY_TOKEN)).toBe(false);
      expect(broadcastJson.includes(CANARY_API_KEY)).toBe(false);

      // 2. UI Export Sinks verification (JSON, Markdown, SARIF)
      const jsonReport = exportJsonReport(sanitizedState);
      const markdownReport = exportMarkdownReport(sanitizedState);
      const sarifReport = exportSarifReport(sanitizedState);
      const sarifObjectJson = JSON.stringify(generateSarif(sanitizedState));

      const sinks = [
        { name: 'JSON Export', payload: jsonReport },
        { name: 'Markdown Export', payload: markdownReport },
        { name: 'SARIF Export (string)', payload: sarifReport },
        { name: 'SARIF Export (object)', payload: sarifObjectJson },
      ];

      const canaryTokens = [
        CANARY_COOKIE_VALUE,
        CANARY_BEARER_TOKEN,
        CANARY_PROXY_PWD,
        CANARY_QUERY_TOKEN,
        CANARY_API_KEY,
      ];

      for (const { name, payload } of sinks) {
        for (const canary of canaryTokens) {
          expect(
            payload.includes(canary),
            `Canary leak found in ${name}: ${canary}`
          ).toBe(false);
        }
      }
    });
  });

  // =========================================================================
  // TASK 2: Private / Incognito Isolation
  // =========================================================================
  describe('Task 2: Private and Incognito Isolation', () => {
    it('guarantees incognito tab states NEVER create or update LocalStorage keys (history, graph, auth_diff)', async () => {
      const incognitoTabId = 200;
      openBrowserTabs.push({ id: incognitoTabId, incognito: true });

      const recordHistorySpy = vi.spyOn(LocalStorage, 'recordOriginHistory');
      const recordAuthDiffSpy = vi.spyOn(LocalStorage, 'recordAuthDiff');
      const mutateGraphSpy = vi.spyOn(LocalStorage, 'mutateGraph');

      const hop: Hop = {
        requestId: 'incog-req-1',
        url: 'https://private-bank.example.com/account',
        status: 200,
        headers: {
          'set-cookie': 'session=[REDACTED]; Path=/; Secure; HttpOnly',
        },
        rawHeaders: [
          { name: 'Set-Cookie', value: 'session=[REDACTED]; Path=/; Secure; HttpOnly' },
        ],
        fromCache: false,
        isHstsUpgrade: false,
        capturedAt: 'onResponseStarted',
        headersDiffer: false,
        timestamp: Date.now(),
      };

      // Process hop through authoritative tab pipeline
      await onHopComplete(incognitoTabId, hop, true);

      // Verify in-memory state is marked incognito
      expect(incognitoTabIds.has(incognitoTabId)).toBe(true);
      const state = tabStates.get(incognitoTabId);
      expect(state).toBeDefined();
      expect(state?.isIncognito).toBe(true);

      // Await WriteBatcher flush interval (500ms) for SessionStorage write
      await new Promise((r) => setTimeout(r, 600));

      // Verify SessionStorage received the ephemeral state with isIncognito: true
      const sessionState = await SessionStorage.getTabState(incognitoTabId);
      expect(sessionState).toBeDefined();
      expect(sessionState?.isIncognito).toBe(true);

      // Verify LocalStorage mutation methods were NEVER invoked
      expect(recordHistorySpy).not.toHaveBeenCalled();
      expect(recordAuthDiffSpy).not.toHaveBeenCalled();
      expect(mutateGraphSpy).not.toHaveBeenCalled();

      // Verify no keys leaked into mockLocalStorageData
      const persistentLeakedKeys = Object.keys(mockLocalStorageData).filter(
        (k) => k.startsWith('history:') || k.startsWith('graph:') || k.startsWith('auth_diff:')
      );
      expect(persistentLeakedKeys).toHaveLength(0);
    });

    it('withstands race conditions: delayed tabs.get resolution never allows premature LocalStorage persistence', async () => {
      const raceTabId = 201;

      // Simulate a slow asynchronous chrome.tabs.get call (e.g. 30ms latency)
      (chrome.tabs.get as Mock).mockImplementation(async (id: number) => {
        await new Promise((resolve) => setTimeout(resolve, 30));
        return { id, incognito: true };
      });

      const recordHistorySpy = vi.spyOn(LocalStorage, 'recordOriginHistory');
      const recordAuthDiffSpy = vi.spyOn(LocalStorage, 'recordAuthDiff');

      const fastHop: Hop = {
        requestId: 'race-fast-hop',
        url: 'https://health-portal.example.com/records',
        status: 200,
        headers: {},
        rawHeaders: [],
        fromCache: true,
        isHstsUpgrade: false,
        capturedAt: 'onResponseStarted',
        headersDiffer: false,
        timestamp: Date.now(),
      };

      // In a fast cached response where isIncognito is initially undefined
      const pipelinePromise = onHopComplete(raceTabId, fastHop, undefined);

      // Wait for pipeline completion
      await pipelinePromise;

      // Verify tab was resolved as incognito before any persistence occurred
      expect(incognitoTabIds.has(raceTabId)).toBe(true);
      expect(recordHistorySpy).not.toHaveBeenCalled();
      expect(recordAuthDiffSpy).not.toHaveBeenCalled();

      const leakedKeys = Object.keys(mockLocalStorageData).filter(
        (k) => k.startsWith('history:') || k.startsWith('graph:') || k.startsWith('auth_diff:')
      );
      expect(leakedKeys).toHaveLength(0);
    });

    it('deletePrivateRecords purges only incognito tab states from session storage', async () => {
      mockSessionStorageData['tab:10'] = { tabId: 10, isIncognito: false, origin: 'https://regular.com' };
      mockSessionStorageData['tab:20'] = { tabId: 20, isIncognito: true, origin: 'https://private.com' };
      mockSessionStorageData['tab:30'] = { tabId: 30, isIncognito: true, origin: 'https://secret.com' };
      mockSessionStorageData['tab:40'] = { tabId: 40, origin: 'https://standard.com' };

      await LocalStorage.deletePrivateRecords();

      expect(mockSessionStorageData['tab:10']).toBeDefined();
      expect(mockSessionStorageData['tab:20']).toBeUndefined();
      expect(mockSessionStorageData['tab:30']).toBeUndefined();
      expect(mockSessionStorageData['tab:40']).toBeDefined();
    });
  });

  // =========================================================================
  // TASK 3: Broad Grant Conflict & All-Sites Missing Grant Fail-Closed Assertions
  // =========================================================================
  describe('Task 3: Broad Grant Conflict and All-Sites Missing Grant States', () => {
    it('fails closed at the listener boundary in per-site mode when broad grant is active (conflict)', async () => {
      // Configure per-site settings and browser permissions with broad grant present
      mockLocalStorageData[STORAGE_KEYS.SETTINGS] = {
        ...DEFAULT_SETTINGS,
        monitoringMode: 'per-site',
      };
      (chrome.permissions.getAll as Mock).mockResolvedValue({
        origins: ['<all_urls>', 'https://consented.example.com/*'],
      });
      (chrome.permissions.contains as Mock).mockImplementation((perm: { origins?: string[] }, cb?: (res: boolean) => void) => {
        const matches = perm?.origins?.includes('<all_urls>') ?? false;
        if (typeof cb === 'function') cb(matches);
        return Promise.resolve(matches);
      });

      // Configure snapshot: per-site with broadGrantActive: true
      CapturePolicy.setSnapshotForTesting({
        ready: true,
        revision: 10,
        mode: 'per-site',
        broadGrantActive: true, // Conflict
        grantedOrigins: new Set(['https://consented.example.com']),
      });

      // Assert synchronous pre-filter drops capture at the boundary
      expect(isCaptureActiveForUrl('https://consented.example.com/app')).toBe(false);
      expect(isCaptureActiveForUrl('https://unconsented.example.com/')).toBe(false);

      // Verify WebRequest listeners do not allocate inFlightRequests or captureMap
      const capturedHops: Hop[] = [];
      registerCaptureListeners((_t, h) => capturedHops.push(h));

      const onBeforeSendHeaders = webRequestListeners['onBeforeSendHeaders']?.at(-1);
      const onHeadersReceived = webRequestListeners['onHeadersReceived']?.at(-1);

      onBeforeSendHeaders?.({
        type: 'xmlhttprequest',
        tabId: 1,
        requestId: 'conflict-api-req',
        url: 'https://consented.example.com/api/data',
        method: 'GET',
        requestHeaders: [],
        timeStamp: Date.now(),
      });

      onHeadersReceived?.({
        type: 'main_frame',
        tabId: 1,
        requestId: 'conflict-nav-req',
        url: 'https://consented.example.com/app',
        statusCode: 200,
        responseHeaders: [{ name: 'Server', value: 'Apache' }],
        timeStamp: Date.now(),
      });

      // Assert zero retained metadata in maps
      expect(inFlightRequests.size).toBe(0);
      expect(captureMap.size).toBe(0);
      expect(capturedHops).toHaveLength(0);

      // Assert authoritative evaluation produces 'broad-access-conflict'
      const evaluation = await CapturePolicy.evaluate('https://consented.example.com/app');
      expect(evaluation.allowed).toBe(false);
      expect(evaluation.reason).toBe('broad-access-conflict');

      // Assert truthful monitoring state in UI
      const monitoringState = await CapturePolicy.getMonitoringState();
      expect(monitoringState).toBe('Paused — Broad access conflict');
    });

    it('fails closed in all-sites mode when broad grant is missing and NEVER degrades to narrow grants', async () => {
      // Configure all-sites settings and browser permissions without broad grant
      mockLocalStorageData[STORAGE_KEYS.SETTINGS] = {
        ...DEFAULT_SETTINGS,
        monitoringMode: 'all-sites',
      };
      (chrome.permissions.getAll as Mock).mockResolvedValue({
        origins: ['https://narrow-site.example.com/*'],
      });
      (chrome.permissions.contains as Mock).mockImplementation((_p: unknown, cb?: (res: boolean) => void) => {
        if (typeof cb === 'function') cb(false);
        return Promise.resolve(false);
      });

      CapturePolicy.setSnapshotForTesting({
        ready: true,
        revision: 20,
        mode: 'all-sites',
        broadGrantActive: false, // Missing broad grant
        grantedOrigins: new Set(['https://narrow-site.example.com']),
      });

      // Boundary pre-filter must reject ALL origins, including the narrow grant
      expect(isCaptureActiveForUrl('https://narrow-site.example.com/')).toBe(false);
      expect(isCaptureActiveForUrl('https://other.example.com/')).toBe(false);

      const onHeadersReceived = webRequestListeners['onHeadersReceived']?.at(-1);
      onHeadersReceived?.({
        type: 'main_frame',
        tabId: 2,
        requestId: 'missing-grant-req',
        url: 'https://narrow-site.example.com/',
        statusCode: 200,
        responseHeaders: [{ name: 'Server', value: 'nginx' }],
        timeStamp: Date.now(),
      });

      expect(captureMap.size).toBe(0);

      // Assert authoritative evaluation produces 'all-sites-missing-grant'
      const evaluation = await CapturePolicy.evaluate('https://narrow-site.example.com/');
      expect(evaluation.allowed).toBe(false);
      expect(evaluation.reason).toBe('all-sites-missing-grant');

      // Assert truthful monitoring state in UI
      const monitoringState = await CapturePolicy.getMonitoringState();
      expect(monitoringState).toBe('Paused — All-sites permission missing');
    });

    it('rejects incomplete broad grants (e.g. https://*/* without http://*/*) in all-sites mode', async () => {
      // Mock chrome.permissions.getAll returning only https://*/*
      (chrome.permissions.getAll as Mock).mockResolvedValue({
        origins: ['https://*/*'],
      });
      (chrome.permissions.contains as Mock).mockImplementation((perm: { origins?: string[] }, cb?: (res: boolean) => void) => {
        const origins = perm.origins ?? [];
        const hasHttps = origins.includes('https://*/*');
        const hasHttp = origins.includes('http://*/*');
        const hasAll = origins.includes('<all_urls>');
        const matches = hasHttps && !hasHttp && !hasAll;
        if (typeof cb === 'function') cb(matches);
        return Promise.resolve(matches);
      });

      const hasCompleteCoverage = await PermissionsService.hasCompleteBroadGrant();
      expect(hasCompleteCoverage).toBe(false);

      // Snapshot refreshed with incomplete grant must fail closed
      const incompleteSnapshot = {
        ready: true,
        revision: 30,
        mode: 'all-sites' as const,
        broadGrantActive: false,
        grantedOrigins: new Set(['https://*/*']),
      };

      expect(isCaptureAllowedAtBoundary('https://example.com/', incompleteSnapshot)).toBe(false);
      expect(isCaptureAllowedAtBoundary('http://example.com/', incompleteSnapshot)).toBe(false);
    });

    it('fails closed immediately when snapshot is unhydrated (ready === false)', () => {
      const unhydratedSnapshot = {
        ready: false,
        revision: 0,
        mode: 'all-sites' as const,
        broadGrantActive: true,
        grantedOrigins: new Set<string>(),
      };

      expect(isCaptureAllowedAtBoundary('https://example.com/', unhydratedSnapshot)).toBe(false);
      expect(isCaptureAllowedAtBoundary('https://google.com/', unhydratedSnapshot)).toBe(false);
    });
  });

  // =========================================================================
  // TASK 4: Off-Mode Transitions & Universal Action Badge Clearing
  // =========================================================================
  describe('Task 4: Off-Mode Transitions & Universal Action Badge Clearing', () => {
    it('halts all capture, clears in-flight maps, purges session storage, and notifies open ports on Off transition', async () => {
      // Setup active state before transition
      CapturePolicy.setSnapshotForTesting({
        ready: true,
        revision: 40,
        mode: 'all-sites',
        broadGrantActive: true,
        grantedOrigins: new Set(),
      });

      const tab1State: TabState = {
        tabId: 101,
        origin: 'https://site-a.com',
        url: 'https://site-a.com/page',
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
        },
        subdomainTrust: { hasEscalationPath: false, vectors: [] },
        monitoredByUser: true,
        updatedAt: Date.now(),
      };
      tabStates.set(101, tab1State);
      mockSessionStorageData['tab:101'] = { tabId: 101 };

      captureMap.set('in-flight-1', {
        tabId: 101,
        url: 'https://site-a.com/page',
        status: 200,
        headersReceived: null,
        rawHeadersReceived: [],
        headersStarted: null,
        rawHeadersStarted: [],
        fromCache: false,
        wasRedirected: false,
        timestamp: Date.now(),
        redirectCount: 0,
      });

      inFlightRequests.set('xhr-flight-1', {
        method: 'POST',
        origin: 'https://site-a.com',
        timestamp: Date.now(),
      });

      // Register open browser tabs
      openBrowserTabs.push({ id: 101 }, { id: 102 }, { id: 999 });

      // Execute transition to 'off' mode via settings pipeline
      const offSettings: SettingsV2 = {
        ...(await SettingsService.getSettings()),
        monitoringMode: 'off',
      };

      await settingsTransitionPipeline.transition(offSettings, 'message');
      await CapturePolicy.refreshSnapshot();

      // 1. Assert synchronous gate flip to 'off'
      expect(CapturePolicy.getSnapshot().mode).toBe('off');
      expect(isCaptureActiveForUrl('https://site-a.com/')).toBe(false);

      // 2. Assert in-flight maps cleared
      expect(captureMap.size).toBe(0);
      expect(inFlightRequests.size).toBe(0);

      // 3. Assert in-memory tab state cleared
      expect(tabStates.size).toBe(0);

      // 4. Assert session storage entries removed
      expect(mockSessionStorageData['tab:101']).toBeUndefined();

      // 5. Assert authoritative evaluation returns reason: 'off'
      const evalOff = await CapturePolicy.evaluate('https://site-a.com/');
      expect(evalOff.allowed).toBe(false);
      expect(evalOff.reason).toBe('off');

      // 6. Assert monitoring state returns 'Off'
      const monState = await CapturePolicy.getMonitoringState();
      expect(monState).toBe('Off');
    });

    it('universally clears action badges across ALL browser tabs, including tabs without TabState records', async () => {
      // Setup tabs:
      // Tab 10: has TabState (was monitored, grade 'A')
      // Tab 20: has TabState (was monitored, grade 'B')
      // Tab 888: NO TabState (unmonitored tab or restricted tab with lingering '?' badge)
      openBrowserTabs.length = 0;
      openBrowserTabs.push({ id: 10 }, { id: 20 }, { id: 888 });

      tabStates.set(10, { tabId: 10, grade: 'A' } as unknown as TabState);
      tabStates.set(20, { tabId: 20, grade: 'B' } as unknown as TabState);

      // Execute universal badge clearing
      await clearBadgesOnAllTabs();

      // Assert chrome.action.setBadgeText was called with empty string for tab 10, 20, AND tab 888
      expect(chrome.action.setBadgeText).toHaveBeenCalledWith({ tabId: 10, text: '' });
      expect(chrome.action.setBadgeText).toHaveBeenCalledWith({ tabId: 20, text: '' });
      expect(chrome.action.setBadgeText).toHaveBeenCalledWith({ tabId: 888, text: '' });

      // Assert global fallback badge was also cleared
      expect(chrome.action.setBadgeText).toHaveBeenCalledWith({ text: '' });
    });

    it('drops new navigations and API requests at the boundary while in off mode', () => {
      CapturePolicy.setSnapshotForTesting({
        ready: true,
        revision: 50,
        mode: 'off',
        broadGrantActive: false,
        grantedOrigins: new Set(),
      });

      const onBeforeSendHeaders = webRequestListeners['onBeforeSendHeaders']?.at(-1);
      const onHeadersReceived = webRequestListeners['onHeadersReceived']?.at(-1);

      onBeforeSendHeaders?.({
        type: 'xmlhttprequest',
        tabId: 300,
        requestId: 'off-req-1',
        url: 'https://example.com/api',
        method: 'GET',
        requestHeaders: [],
        timeStamp: Date.now(),
      });

      onHeadersReceived?.({
        type: 'main_frame',
        tabId: 300,
        requestId: 'off-req-2',
        url: 'https://example.com/',
        statusCode: 200,
        responseHeaders: [{ name: 'Server', value: 'nginx' }],
        timeStamp: Date.now(),
      });

      expect(inFlightRequests.size).toBe(0);
      expect(captureMap.size).toBe(0);
    });
  });
});
