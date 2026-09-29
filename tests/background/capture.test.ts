import { beforeEach, describe, expect, it, vi } from 'vitest';
import { registerCaptureListeners } from '../../src/background/capture';
import type { Hop } from '../../src/shared/types';

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
        onHeadersReceived: event('onHeadersReceived'),
        onResponseStarted: event('onResponseStarted'),
        onBeforeRedirect: event('onBeforeRedirect'),
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
});