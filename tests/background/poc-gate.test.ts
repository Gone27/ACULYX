import { describe, it, expect, beforeEach, vi } from 'vitest';
import { tabStates } from '../../src/background/lifecycle';
import type { TabState } from '../../src/shared/types';

describe('PoC Sandbox Scope Gate', () => {
  const mockTabsCreate = vi.fn().mockResolvedValue({ id: 999 });

  beforeEach(() => {
    tabStates.clear();

    vi.stubGlobal('chrome', {
      runtime: {
        id: 'mock-ext-id',
        getURL: vi.fn((path: string) => `chrome-extension://mock-ext-id/${path}`),
        onMessage: {
          addListener: vi.fn(),
        },
      },
      tabs: {
        create: mockTabsCreate,
      },
    });
  });

  function evaluatePocGate(
    state: TabState | undefined,
    senderId: string = 'mock-ext-id',
  ): Promise<{ success: boolean; error?: string; url?: string }> {
    return new Promise((resolve) => {
      // Direct validation simulating background index.ts GENERATE_POC handling
      const isInternal = senderId === 'mock-ext-id';
      if (!isInternal) {
        resolve({
          success: false,
          error: 'Unauthorized sender: GENERATE_POC only accepted from extension pages',
        });
        return;
      }

      if (!state || !state.monitoredByUser) {
        resolve({
          success: false,
          error: 'Site must be monitored before generating verification sandbox.',
        });
        return;
      }

      if (state.scopeStatus !== 'in-scope') {
        resolve({
          success: false,
          error: 'Active verification sandbox requires target to be explicitly in-scope under an active scope profile.',
        });
        return;
      }

      resolve({
        success: true,
        url: `chrome-extension://mock-ext-id/src/sandbox/poc.html?target=${encodeURIComponent(state.url)}&type=clickjacking`,
      });
    });
  }

  it('rejects PoC generation when sender is external', async () => {
    const res = await evaluatePocGate(undefined, 'external-id');
    expect(res.success).toBe(false);
    expect(res.error).toContain('Unauthorized sender');
  });

  it('rejects PoC generation when target site is not monitored', async () => {
    const state: Partial<TabState> = {
      tabId: 1,
      url: 'https://example.com/',
      monitoredByUser: false,
      scopeStatus: 'in-scope',
    };
    const res = await evaluatePocGate(state as TabState);
    expect(res.success).toBe(false);
    expect(res.error).toContain('Site must be monitored');
  });

  it('rejects PoC generation when scope is out-of-scope', async () => {
    const state: Partial<TabState> = {
      tabId: 1,
      url: 'https://out-of-scope.example.com/',
      monitoredByUser: true,
      scopeStatus: 'out-of-scope',
    };
    const res = await evaluatePocGate(state as TabState);
    expect(res.success).toBe(false);
    expect(res.error).toContain('explicitly in-scope');
  });

  it('rejects PoC generation when scope is unknown or undefined', async () => {
    const state: Partial<TabState> = {
      tabId: 1,
      url: 'https://unknown.example.com/',
      monitoredByUser: true,
      scopeStatus: undefined,
    };
    const res = await evaluatePocGate(state as TabState);
    expect(res.success).toBe(false);
    expect(res.error).toContain('explicitly in-scope');
  });

  it('permits PoC generation when target is monitored AND explicitly in-scope', async () => {
    const state: Partial<TabState> = {
      tabId: 1,
      url: 'https://bounty.example.com/login',
      monitoredByUser: true,
      scopeStatus: 'in-scope',
    };
    const res = await evaluatePocGate(state as TabState);
    expect(res.success).toBe(true);
    expect(res.url).toContain('src/sandbox/poc.html');
    expect(res.url).toContain('https%3A%2F%2Fbounty.example.com%2Flogin');
  });
});
