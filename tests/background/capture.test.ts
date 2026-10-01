import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  registerCaptureListeners,
  clearInFlightCaptures,
  captureMap,
  inFlightRequests,
} from '../../src/background/capture';
import type { Hop, ApiHop } from '../../src/shared/types';
import { SettingsService } from '../../src/shared/settings';
import { DEFAULT_SETTINGS } from '../../src/shared/constants';

type Listener = (...args: unknown[]) => void;

describe('redirect response capture', () => {
  const listeners: Record<string, Listener> = {};
  const event = (name: string) => ({
    addListener: (listener: Listener) => {
      listeners[name] = listener;
    },
  });

  beforeEach(() => {
    for (const key of Object.keys(listeners)) delete listeners[key];
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

  it('emits an intermediate redirect response with its headers before the final hop', () => {
    const hops: Hop[] = [];
    registerCaptureListeners((_tabId, hop) => hops.push(hop));

    listeners['onHeadersReceived']?.({
      type: 'main_frame',
      tabId: 4,
      requestId: 'redirect-chain',
      url: 'https://first.example/start',
      statusCode: 302,
      responseHeaders: [{ name: 'Content-Security-Policy', value: "default-src 'self'" }],
      timeStamp: 100,
    });
    listeners['onBeforeRedirect']?.({
      type: 'main_frame',
      tabId: 4,
      requestId: 'redirect-chain',
      url: 'https://first.example/start',
      redirectUrl: 'https://second.example/final',
      statusCode: 302,
      timeStamp: 101,
    });

    expect(hops).toHaveLength(1);
    expect(hops[0]?.url).toBe('https://first.example/start');
    expect(hops[0]?.status).toBe(302);
    expect(hops[0]?.headers['content-security-policy']).toBe("default-src 'self'");

    listeners['onHeadersReceived']?.({
      type: 'main_frame',
      tabId: 4,
      requestId: 'redirect-chain',
      url: 'https://second.example/final',
      statusCode: 200,
      responseHeaders: [],
      timeStamp: 102,
    });
    listeners['onResponseStarted']?.({
      type: 'main_frame',
      tabId: 4,
      requestId: 'redirect-chain',
      url: 'https://second.example/final',
      statusCode: 200,
      responseHeaders: [],
      fromCache: false,
      timeStamp: 103,
    });

    expect(hops.map((hop) => hop.url)).toEqual([
      'https://first.example/start',
      'https://second.example/final',
    ]);
  });

  it('captures XHR/fetch requests and invokes onApiHopComplete with sanitized URL and Origin', () => {
    const hops: Hop[] = [];
    const apiHops: ApiHop[] = [];
    registerCaptureListeners(
      (_tabId, hop) => hops.push(hop),
      (apiHop) => apiHops.push(apiHop),
    );

    // 1. Simulate onBeforeSendHeaders with an Origin header and sensitive token in query param
    listeners['onBeforeSendHeaders']?.({
      type: 'xmlhttprequest',
      tabId: 5,
      requestId: 'api-req-1',
      method: 'POST',
      url: 'https://api.example.com/v1/users?token=secret123&page=1',
      requestHeaders: [
        { name: 'Origin', value: 'https://app.example.com' },
        { name: 'User-Agent', value: 'TestAgent' },
      ],
      timeStamp: 200,
    });

    // 2. Simulate onResponseStarted
    listeners['onResponseStarted']?.({
      type: 'xmlhttprequest',
      tabId: 5,
      requestId: 'api-req-1',
      url: 'https://api.example.com/v1/users?token=secret123&page=1',
      statusCode: 200,
      responseHeaders: [
        { name: 'Access-Control-Allow-Origin', value: 'https://app.example.com' },
        { name: 'Access-Control-Allow-Credentials', value: 'true' },
        { name: 'Content-Type', value: 'application/json' },
      ],
      fromCache: false,
      timeStamp: 250,
    });

    // Verify main hops is empty (API calls don't pollute document hops)
    expect(hops).toHaveLength(0);

    // Verify apiHops received the correctly processed ApiHop
    expect(apiHops).toHaveLength(1);
    const api = apiHops[0];
    expect(api?.tabId).toBe(5);
    expect(api?.requestId).toBe('api-req-1');
    expect(api?.method).toBe('POST');
    expect(api?.requestOrigin).toBe('https://app.example.com');
    expect(api?.normalizedPath).toBe('https://api.example.com/v1/users');
    // Verify query param token was redacted!
    expect(api?.url).toBe('https://api.example.com/v1/users?token=%5Bredacted%5D&page=1');
    expect(api?.headers['access-control-allow-origin']).toBe('https://app.example.com');
  });

  it('cleans up in-flight requests on error or completion', () => {
    let capturedApi: ApiHop | null = null;
    registerCaptureListeners(
      () => {},
      (api) => { capturedApi = api; },
    );

    listeners['onBeforeSendHeaders']?.({
      type: 'xmlhttprequest',
      tabId: 5,
      requestId: 'api-error-1',
      method: 'GET',
      url: 'https://api.example.com/v1/fail',
      requestHeaders: [{ name: 'Origin', value: 'https://app.example.com' }],
      timeStamp: 300,
    });

    // Simulate network error before response
    listeners['onErrorOccurred']?.({
      type: 'xmlhttprequest',
      tabId: 5,
      requestId: 'api-error-1',
    });

    // Now if onResponseStarted fires later without metadata, method falls back to 'GET' and origin is undefined
    listeners['onResponseStarted']?.({
      type: 'xmlhttprequest',
      tabId: 5,
      requestId: 'api-error-1',
      url: 'https://api.example.com/v1/fail',
      statusCode: 500,
      responseHeaders: [],
      fromCache: false,
      timeStamp: 350,
    });

    expect(capturedApi).not.toBeNull();
    expect((capturedApi as unknown as ApiHop)?.requestOrigin).toBeUndefined();
  });

  it('redacts sensitive path segments in normalizedPath and hop URLs', () => {
    const hops: Hop[] = [];
    const apiHops: ApiHop[] = [];
    registerCaptureListeners(
      (_tabId, hop) => hops.push(hop),
      (apiHop) => apiHops.push(apiHop),
    );

    // Main frame navigation with sensitive path segment and query parameter
    listeners['onHeadersReceived']?.({
      type: 'main_frame',
      tabId: 6,
      requestId: 'doc-reset-1',
      url: 'https://example.com/reset/4f53cda18c2baa0c0354bb5f9a?token=supersecret',
      statusCode: 200,
      responseHeaders: [],
      timeStamp: 400,
    });
    listeners['onResponseStarted']?.({
      type: 'main_frame',
      tabId: 6,
      requestId: 'doc-reset-1',
      url: 'https://example.com/reset/4f53cda18c2baa0c0354bb5f9a?token=supersecret',
      statusCode: 200,
      responseHeaders: [],
      fromCache: false,
      timeStamp: 401,
    });

    expect(hops).toHaveLength(1);
    expect(hops[0]?.url).toBe('https://example.com/reset/[token]?token=%5Bredacted%5D');

    // API request with UUID and secret path keyword
    listeners['onResponseStarted']?.({
      type: 'xmlhttprequest',
      tabId: 6,
      requestId: 'api-reset-1',
      url: 'https://api.example.com/v1/auth/a1b2c3d4e5f6a7b8c9d0e1f2/verify',
      statusCode: 200,
      responseHeaders: [],
      fromCache: false,
      timeStamp: 402,
    });

    expect(apiHops).toHaveLength(1);
    expect(apiHops[0]?.normalizedPath).toBe('https://api.example.com/v1/auth/[token]/verify');
    expect(apiHops[0]?.url).toBe('https://api.example.com/v1/auth/[token]/verify');
  });

  it('redacts Set-Cookie, Cookie, and Authorization header values in captured main_frame and API responses (synthetic canary test)', () => {
    const hops: Hop[] = [];
    const apiHops: ApiHop[] = [];
    registerCaptureListeners(
      (_tabId, hop) => hops.push(hop),
      (apiHop) => apiHops.push(apiHop),
    );

    const canaryCookie = 'session=V2_SYNTHETIC_CANARY; Path=/; Secure; HttpOnly; SameSite=Lax';
    const canaryAuth = 'Bearer V2_SYNTHETIC_CANARY_AUTH';

    // 1. Navigation request setting the canary cookie
    listeners['onHeadersReceived']?.({
      type: 'main_frame',
      tabId: 7,
      requestId: 'doc-canary-1',
      url: 'https://example.com/login',
      statusCode: 200,
      responseHeaders: [
        { name: 'Set-Cookie', value: canaryCookie },
        { name: 'Authorization', value: canaryAuth },
      ],
      timeStamp: 500,
    });
    listeners['onResponseStarted']?.({
      type: 'main_frame',
      tabId: 7,
      requestId: 'doc-canary-1',
      url: 'https://example.com/login',
      statusCode: 200,
      responseHeaders: [
        { name: 'Set-Cookie', value: canaryCookie },
        { name: 'Authorization', value: canaryAuth },
      ],
      fromCache: false,
      timeStamp: 501,
    });

    expect(hops).toHaveLength(1);
    const hop = hops[0];
    expect(hop).toBeDefined();
    if (hop === undefined) throw new Error('Expected hop to be defined');
    expect(hop.headers['set-cookie']).toBe('session=[REDACTED]; Path=/; Secure; HttpOnly; SameSite=Lax');
    expect(hop.headers['set-cookie']).not.toContain('V2_SYNTHETIC_CANARY');
    expect(hop.headers['authorization']).toBe('[REDACTED]');
    expect(hop.rawHeaders.find((h) => h.name.toLowerCase() === 'set-cookie')?.value).toBe('session=[REDACTED]; Path=/; Secure; HttpOnly; SameSite=Lax');
    expect(JSON.stringify(hop)).not.toContain('V2_SYNTHETIC_CANARY');

    // 2. API response setting canary cookie
    listeners['onResponseStarted']?.({
      type: 'xmlhttprequest',
      tabId: 7,
      requestId: 'api-canary-1',
      url: 'https://example.com/api/user',
      statusCode: 200,
      responseHeaders: [
        { name: 'Set-Cookie', value: canaryCookie },
      ],
      fromCache: false,
      timeStamp: 502,
    });

    expect(apiHops).toHaveLength(1);
    const apiHop = apiHops[0];
    expect(apiHop).toBeDefined();
    if (apiHop === undefined) throw new Error('Expected apiHop to be defined');
    expect(apiHop.headers['set-cookie']).toBe('session=[REDACTED]; Path=/; Secure; HttpOnly; SameSite=Lax');
    expect(apiHop.rawHeaders.find((h) => h.name.toLowerCase() === 'set-cookie')?.value).toBe('session=[REDACTED]; Path=/; Secure; HttpOnly; SameSite=Lax');
    expect(JSON.stringify(apiHop)).not.toContain('V2_SYNTHETIC_CANARY');
  });

  describe('Off mode capture gating and in-flight cleanup', () => {
    it('stops capturing navigation and API hops when mode is off', () => {
      const getCachedSpy = vi.spyOn(SettingsService, 'getCachedSettings').mockReturnValue({
        ...DEFAULT_SETTINGS,
        monitoringMode: 'off',
      });

      const hops: Hop[] = [];
      const apiHops: ApiHop[] = [];
      registerCaptureListeners(
        (_tabId, hop) => hops.push(hop),
        (apiHop) => apiHops.push(apiHop),
      );

      try {
        // Attempt navigation capture in Off mode
        listeners['onHeadersReceived']?.({
          type: 'main_frame',
          tabId: 10,
          requestId: 'req-off-1',
          url: 'https://example.com/',
          statusCode: 200,
          responseHeaders: [{ name: 'Content-Security-Policy', value: "default-src 'self'" }],
          timeStamp: 1000,
        });

        expect(captureMap.has('req-off-1')).toBe(false);

        listeners['onResponseStarted']?.({
          type: 'main_frame',
          tabId: 10,
          requestId: 'req-off-1',
          url: 'https://example.com/',
          statusCode: 200,
          responseHeaders: [{ name: 'Content-Security-Policy', value: "default-src 'self'" }],
          fromCache: false,
          timeStamp: 1001,
        });

        expect(hops).toHaveLength(0);

        // Attempt API capture in Off mode
        listeners['onBeforeSendHeaders']?.({
          type: 'xmlhttprequest',
          tabId: 10,
          requestId: 'api-off-1',
          method: 'GET',
          url: 'https://api.example.com/data',
          requestHeaders: [],
          timeStamp: 1002,
        });

        expect(inFlightRequests.has('api-off-1')).toBe(false);

        listeners['onResponseStarted']?.({
          type: 'xmlhttprequest',
          tabId: 10,
          requestId: 'api-off-1',
          url: 'https://api.example.com/data',
          statusCode: 200,
          responseHeaders: [],
          fromCache: false,
          timeStamp: 1003,
        });

        expect(apiHops).toHaveLength(0);
      } finally {
        getCachedSpy.mockRestore();
      }
    });

    it('clearInFlightCaptures empties captureMap and inFlightRequests', () => {
      captureMap.set('c1', {
        tabId: 1,
        url: 'https://test.com',
        status: 200,
        headersReceived: null,
        rawHeadersReceived: [],
        headersStarted: null,
        rawHeadersStarted: [],
        fromCache: false,
        wasRedirected: false,
        timestamp: 1,
        redirectCount: 0,
      });
      inFlightRequests.set('req1', { method: 'GET', timestamp: 1 });

      expect(captureMap.size).toBe(1);
      expect(inFlightRequests.size).toBe(1);

      clearInFlightCaptures();

      expect(captureMap.size).toBe(0);
      expect(inFlightRequests.size).toBe(0);
    });

    it('cleanup listeners still run for requests already started', () => {
      registerCaptureListeners(() => {});

      // Request started
      captureMap.set('in-flight-err', {
        tabId: 1,
        url: 'https://test.com',
        status: 200,
        headersReceived: null,
        rawHeadersReceived: [],
        headersStarted: null,
        rawHeadersStarted: [],
        fromCache: false,
        wasRedirected: false,
        timestamp: 1,
        redirectCount: 0,
      });
      inFlightRequests.set('in-flight-err', { method: 'GET', timestamp: 1 });

      // onErrorOccurred runs
      listeners['onErrorOccurred']?.({
        requestId: 'in-flight-err',
      });

      expect(captureMap.has('in-flight-err')).toBe(false);
      expect(inFlightRequests.has('in-flight-err')).toBe(false);
    });
  });
});