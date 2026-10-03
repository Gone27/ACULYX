import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { registerPageSignalInjection } from '../src/background/page-signals';
import { reportPageSignals } from '../src/content/service-worker-detection';
import { SettingsService } from '../src/shared/settings';
import { DEFAULT_SETTINGS } from '../src/shared/constants';

interface NavigationDetails {
  frameId: number;
  tabId: number;
  url: string;
}

describe('permission-gated page signal injection', () => {
  let committedListeners: Array<(details: NavigationDetails) => void>;
  let historyStateListeners: Array<(details: NavigationDetails) => void>;
  let permissionGranted: boolean;
  let permissionContains: ReturnType<typeof vi.fn>;
  let executeScript: ReturnType<typeof vi.fn>;
  let sendMessage: ReturnType<typeof vi.fn>;
  let observerCount: number;

  beforeEach(() => {
    committedListeners = [];
    historyStateListeners = [];
    permissionGranted = true;
    observerCount = 0;
    permissionContains = vi.fn((_permission: unknown, callback: (granted: boolean) => void) => callback(permissionGranted));
    executeScript = vi.fn(() => Promise.resolve([]));
    sendMessage = vi.fn(() => Promise.resolve());

    const chromeMock = {
      webNavigation: {
        onCommitted: { addListener: (listener: (details: NavigationDetails) => void) => committedListeners.push(listener) },
        onHistoryStateUpdated: { addListener: (listener: (details: NavigationDetails) => void) => historyStateListeners.push(listener) },
      },
      permissions: { contains: permissionContains },
      scripting: { executeScript },
      runtime: { sendMessage },
    } as unknown as typeof chrome;
    vi.stubGlobal('chrome', chromeMock);
    vi.stubGlobal('navigator', { serviceWorker: { controller: null } });
    vi.stubGlobal('document', { querySelectorAll: vi.fn(() => []) });
    vi.stubGlobal('MutationObserver', class {
      constructor(_callback: MutationCallback) {
        observerCount += 1;
      }
      observe(): void {}
      disconnect(): void {}
    });
    Reflect.deleteProperty(globalThis, '__seccheckPageSignalsInstalled');

    registerPageSignalInjection();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    Reflect.deleteProperty(globalThis, '__seccheckPageSignalsInstalled');
  });

  it('injects on SPA history updates after confirming the origin grant', () => {
    historyStateListeners[0]?.({ frameId: 0, tabId: 12, url: 'https://example.test/app/route' });

    expect(permissionContains).toHaveBeenCalledWith(
      { origins: ['https://example.test/*'] },
      expect.any(Function),
    );
    expect(executeScript).toHaveBeenCalledWith({
      target: { tabId: 12, frameIds: [0] },
      func: reportPageSignals,
      args: [expect.any(Number)],
    });
  });

  it('does not inject after the origin permission is revoked', () => {
    permissionGranted = false;
    historyStateListeners[0]?.({ frameId: 0, tabId: 12, url: 'https://example.test/app/route' });

    expect(executeScript).not.toHaveBeenCalled();
  });

  it('does not inject when monitoring mode is off', () => {
    const getCachedSpy = vi.spyOn(SettingsService, 'getCachedSettings').mockReturnValue({
      ...DEFAULT_SETTINGS,
      monitoringMode: 'off',
    });

    try {
      historyStateListeners[0]?.({ frameId: 0, tabId: 12, url: 'https://example.test/app/route' });
      expect(permissionContains).not.toHaveBeenCalled();
      expect(executeScript).not.toHaveBeenCalled();
    } finally {
      getCachedSpy.mockRestore();
    }
  });

  it('does not inject when in broad-access-conflict mode', () => {
    const getCachedSpy = vi.spyOn(SettingsService, 'getCachedSettings').mockReturnValue({
      ...DEFAULT_SETTINGS,
      monitoringMode: 'per-site',
    });

    // Provide getAll that returns <all_urls> to simulate broad-access conflict
    const getAllMock = vi.fn().mockImplementation((cb: (perms: { origins: string[] }) => void) => {
      cb({ origins: ['<all_urls>'] });
    });

    const chromeWithGetAll = {
      ...chrome,
      permissions: {
        contains: permissionContains,
        getAll: getAllMock,
      },
    };
    vi.stubGlobal('chrome', chromeWithGetAll);

    try {
      historyStateListeners[0]?.({ frameId: 0, tabId: 12, url: 'https://example.test/app/route' });
      expect(executeScript).not.toHaveBeenCalled();
    } finally {
      getCachedSpy.mockRestore();
    }
  });

  it('ignores SPA history updates in subframes', () => {
    historyStateListeners[0]?.({ frameId: 2, tabId: 12, url: 'https://frame.example.test/' });

    expect(permissionContains).not.toHaveBeenCalled();
    expect(executeScript).not.toHaveBeenCalled();
  });

  it('registers both hard-navigation and history-state injection handlers', () => {
    expect(committedListeners).toHaveLength(1);
    expect(historyStateListeners).toHaveLength(1);
  });

  it('keeps SPA reinjection idempotent and does not multiply observers or messages', () => {
    reportPageSignals();
    reportPageSignals();

    // reportPageSignals creates two observers on first call:
    //   1. A MutationObserver watching for <meta http-equiv="Content-Security-Policy"> appearing
    //   2. A MutationObserver watching for <script src> elements (SRI coverage scan)
    // The idempotency guard (__seccheckPageSignalsInstalled) prevents the second call
    // from creating any additional observers, so the total stays at 2.
    expect(observerCount).toBe(2);
    // First call sends 2 messages: SERVICE_WORKER_STATUS + SRI_SCAN.
    // Second call is fully blocked by the __seccheckPageSignalsInstalled guard.
    expect(sendMessage).toHaveBeenCalledTimes(2);
  });
});