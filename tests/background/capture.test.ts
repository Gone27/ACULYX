import { beforeEach, describe, expect, it, vi } from 'vitest';
import { registerCaptureListeners } from '../../src/background/capture';
import type { Hop, ApiHop } from '../../src/shared/types';

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
});