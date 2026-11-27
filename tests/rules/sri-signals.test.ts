import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { reportPageSignals } from '../../src/content/service-worker-detection';

interface SriMessage {
  type: string;
  externalScripts?: number;
  missingIntegrity?: number;
  externalStylesheets?: number;
  missingStyleIntegrity?: number;
  missingScriptUrls?: string[];
  missingStyleUrls?: string[];
  dynamicMissingCount?: number;
}

describe('Cross-origin SRI signal enumeration and DOM mutation handling', () => {
  let scripts: Array<{ tagName: string; src: string; integrity: string; querySelector: () => null }>;
  let links: Array<{ tagName: string; href: string; integrity: string; querySelector: () => null }>;
  let sentMessages: SriMessage[];
  let observerCallbacks: Array<(mutations: Array<{ type: string; addedNodes: Array<{ nodeType: number; tagName: string; querySelector: (s: string) => unknown }> }>) => void>;

  beforeEach(() => {
    scripts = [];
    links = [];
    sentMessages = [];
    observerCallbacks = [];

    Reflect.deleteProperty(globalThis, '__seccheckPageSignalsInstalled');

    vi.stubGlobal('chrome', {
      runtime: {
        sendMessage: vi.fn((msg: SriMessage) => {
          sentMessages.push(msg);
          return Promise.resolve();
        }),
      },
    });

    vi.stubGlobal('location', {
      href: 'https://app.example.com/dashboard',
      origin: 'https://app.example.com',
    });

    vi.stubGlobal('navigator', { serviceWorker: { controller: null } });

    vi.stubGlobal('document', {
      documentElement: {},
      querySelectorAll: vi.fn((selector: string) => {
        if (selector === 'script[src]') return scripts;
        if (selector === 'link[rel~="stylesheet"][href]') return links;
        return [];
      }),
    });

    vi.stubGlobal('MutationObserver', class {
      constructor(cb: (mutations: Array<{ type: string; addedNodes: Array<{ nodeType: number; tagName: string; querySelector: (s: string) => unknown }> }>) => void) {
        observerCallbacks.push(cb);
      }
      observe(): void {}
      disconnect(): void {}
    });

    vi.stubGlobal('requestAnimationFrame', (fn: FrameRequestCallback) => {
      queueMicrotask(() => fn(0));
      return 1;
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    Reflect.deleteProperty(globalThis, '__seccheckPageSignalsInstalled');
  });

  it('enumerates only cross-origin HTTP(S) resources lacking integrity and excludes inline, same-origin, and data/blob URLs', () => {
    scripts.push(
      // Same-origin script -> MUST be excluded
      { tagName: 'SCRIPT', src: 'https://app.example.com/static/main.js', integrity: '', querySelector: () => null },
      // Inline/protocol URLs -> MUST be excluded
      { tagName: 'SCRIPT', src: 'data:text/javascript,alert(1)', integrity: '', querySelector: () => null },
      { tagName: 'SCRIPT', src: 'blob:https://app.example.com/1234', integrity: '', querySelector: () => null },
      // Cross-origin WITH integrity -> counted in externalScripts, NOT missing
      { tagName: 'SCRIPT', src: 'https://cdn.trusted.net/lib.js?cache=123', integrity: 'sha384-abc123', querySelector: () => null },
      // Cross-origin WITHOUT integrity -> MUST be flagged with sanitized origin+pathname URL
      { tagName: 'SCRIPT', src: 'https://cdn.thirdparty.net/sdk.js?token=secretQuery', integrity: '', querySelector: () => null },
    );

    links.push(
      // Same-origin stylesheet -> MUST be excluded
      { tagName: 'LINK', href: 'https://app.example.com/styles/app.css', integrity: '', querySelector: () => null },
      // Cross-origin stylesheet WITHOUT integrity -> MUST be flagged
      { tagName: 'LINK', href: 'https://fonts.cdn.net/css2.css?family=Inter', integrity: '', querySelector: () => null },
    );

    reportPageSignals(1);

    const sriMsg = sentMessages.find((m) => m.type === 'SRI_SCAN');
    expect(sriMsg).toBeDefined();
    expect(sriMsg?.externalScripts).toBe(2);
    expect(sriMsg?.missingIntegrity).toBe(1);
    expect(sriMsg?.missingScriptUrls).toEqual(['https://cdn.thirdparty.net/sdk.js']);
    expect(sriMsg?.externalStylesheets).toBe(1);
    expect(sriMsg?.missingStyleIntegrity).toBe(1);
    expect(sriMsg?.missingStyleUrls).toEqual(['https://fonts.cdn.net/css2.css']);
    expect(sriMsg?.dynamicMissingCount).toBe(0);
    expect(JSON.stringify(sriMsg)).not.toContain('secretQuery');
  });

  it('tracks dynamically injected cross-origin scripts separately and updates when integrity is set via DOM mutation', async () => {
    scripts.push({
      tagName: 'SCRIPT',
      src: 'https://static.vendor.net/analytics.js',
      integrity: '',
      querySelector: () => null,
    });

    reportPageSignals(2);
    expect(sentMessages.filter((m) => m.type === 'SRI_SCAN')).toHaveLength(1);

    // Dynamically inject a second cross-origin script without integrity
    const dynamicScript = {
      tagName: 'SCRIPT',
      src: 'https://widgets.vendor.net/loader.js',
      integrity: '',
      querySelector: () => null,
    };
    scripts.push(dynamicScript);

    const sriObserverCb = observerCallbacks[observerCallbacks.length - 1];
    expect(sriObserverCb).toBeDefined();
    sriObserverCb?.([
      {
        type: 'childList',
        addedNodes: [{ nodeType: 1, tagName: 'SCRIPT', querySelector: () => null }],
      },
    ]);
    await Promise.resolve();

    const afterAdd = sentMessages.filter((m) => m.type === 'SRI_SCAN').at(-1);
    expect(afterAdd?.missingIntegrity).toBe(2);
    expect(afterAdd?.dynamicMissingCount).toBe(1);
    expect(afterAdd?.missingScriptUrls).toEqual([
      'https://static.vendor.net/analytics.js',
      'https://widgets.vendor.net/loader.js',
    ]);

    // Attribute mutation adds integrity to dynamicScript
    dynamicScript.integrity = 'sha384-xyz';
    sriObserverCb?.([{ type: 'attributes', addedNodes: [] }]);
    await Promise.resolve();

    const afterIntegrityAdded = sentMessages.filter((m) => m.type === 'SRI_SCAN').at(-1);
    expect(afterIntegrityAdded?.missingIntegrity).toBe(1);
    expect(afterIntegrityAdded?.dynamicMissingCount).toBe(0);
  });
});
