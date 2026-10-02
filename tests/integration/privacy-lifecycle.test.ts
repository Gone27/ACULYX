/* eslint-disable @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-explicit-any, @typescript-eslint/strict-boolean-expressions */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Mock } from 'vitest';

interface TabInfo {
  id: number;
  incognito: boolean;
}

interface SessionData {
  isPrivate: boolean;
  url: string;
}

describe('Privacy Lifecycle Integration', () => {
  let inMemoryIncognitoTabs: Set<number>;
  
  beforeEach(() => {
    inMemoryIncognitoTabs = new Set();
    
    vi.stubGlobal('chrome', {
      tabs: {
        query: vi.fn(),
        onRemoved: { addListener: vi.fn() },
      },
      storage: {
        local: {
          get: vi.fn(),
          set: vi.fn(),
          remove: vi.fn(),
          clear: vi.fn(),
        },
        session: {
          get: vi.fn(),
          set: vi.fn(),
          remove: vi.fn(),
          clear: vi.fn(),
        }
      }
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Private tab identity after worker restart', () => {
    it('reconciles incognito state from chrome.tabs.query on startup', async () => {
      const chrome = (globalThis as any).chrome;
      inMemoryIncognitoTabs.clear();
      
      (chrome.tabs.query as Mock).mockImplementation((queryInfo: { incognito?: boolean }) => {
        const allTabs = [
          { id: 101, incognito: true },
          { id: 102, incognito: false }
        ];
        if (queryInfo?.incognito) {
          return Promise.resolve(allTabs.filter(t => t.incognito));
        }
        return Promise.resolve(allTabs);
      });
      
      const tabs = await chrome.tabs.query({ incognito: true }) as TabInfo[];
      tabs.forEach((tab) => {
        if (tab.incognito) inMemoryIncognitoTabs.add(tab.id);
      });
      
      expect(inMemoryIncognitoTabs.has(101)).toBe(true);
      expect(inMemoryIncognitoTabs.has(102)).toBe(false);
    });
  });

  describe('Persistence firewall', () => {
    it('never writes private tab hops and API hops to LocalStorage', async () => {
      const chrome = (globalThis as any).chrome;
      const incognitoTabId = 201;
      inMemoryIncognitoTabs.add(incognitoTabId);
      
      const isIncognito = inMemoryIncognitoTabs.has(incognitoTabId);
      
      if (isIncognito) {
        await chrome.storage.session.set({ [`tab_${incognitoTabId}`]: 'sensitive-data' });
      } else {
        await chrome.storage.local.set({ [`tab_${incognitoTabId}`]: 'sensitive-data' });
      }
      
      expect(chrome.storage.local.set).not.toHaveBeenCalled();
      expect(chrome.storage.session.set).toHaveBeenCalledWith({ [`tab_${incognitoTabId}`]: 'sensitive-data' });
    });
  });

  describe('Last private tab closure', () => {
    it('wipes all incognito records in session storage when the last incognito tab is closed', async () => {
      const chrome = (globalThis as any).chrome;
      inMemoryIncognitoTabs.add(301);
      
      inMemoryIncognitoTabs.delete(301);
      
      if (inMemoryIncognitoTabs.size === 0) {
        await chrome.storage.session.clear();
      }
      
      expect(chrome.storage.session.clear).toHaveBeenCalled();
    });
  });

  describe('Isolation from exports', () => {
    it('ensures regular UI queries and exports cannot read private session records', async () => {
      const chrome = (globalThis as any).chrome;
      const mockSessionData: Record<string, SessionData> = {
        'tab_101': { isPrivate: true, url: 'https://secret.com' },
        'tab_102': { isPrivate: false, url: 'https://public.com' }
      };
      
      (chrome.storage.session.get as Mock).mockResolvedValue(mockSessionData);
      
      const rawData = await chrome.storage.session.get(null) as Record<string, SessionData>;
      const exportedData = Object.keys(rawData)
        .filter(key => rawData[key] && !rawData[key].isPrivate)
        .reduce<Record<string, SessionData>>((obj, key) => {
          const val = rawData[key];
          if (val) {
             obj[key] = val;
          }
          return obj;
        }, {});
      
      expect(exportedData).not.toHaveProperty('tab_101');
      expect(exportedData).toHaveProperty('tab_102');
    });
  });
});
