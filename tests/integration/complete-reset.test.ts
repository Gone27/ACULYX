/* eslint-disable @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-explicit-any, @typescript-eslint/require-await */
import { describe, it, expect, vi, beforeEach } from 'vitest';

describe('Complete Reset Integration', () => {
  let localData: Record<string, unknown>;
  let sessionData: Record<string, unknown>;
  let inMemoryTabs: Map<number, unknown>;
  let actionBadge: string;
  
  beforeEach(() => {
    localData = {};
    sessionData = {};
    inMemoryTabs = new Map();
    actionBadge = '';

    vi.stubGlobal('chrome', {
      storage: {
        local: {
          get: vi.fn(async (keys: unknown) => {
            if (keys === null) return localData;
            return {};
          }),
          set: vi.fn(async (data: Record<string, unknown>) => {
            Object.assign(localData, data);
          }),
          remove: vi.fn(async (keys: string | string[]) => {
            const keysArray = Array.isArray(keys) ? keys : [keys];
            keysArray.forEach((k: string) => { delete localData[k]; });
          }),
          clear: vi.fn(async () => {
            localData = {};
          })
        },
        session: {
          clear: vi.fn(async () => {
            sessionData = {};
          })
        }
      },
      action: {
        setBadgeText: vi.fn(async ({ text }: { text: string }) => {
          actionBadge = text;
        })
      }
    });
  });

  const performFullReset = async () => {
    const chrome = (globalThis as any).chrome;
    // 1. Clear session storage
    await chrome.storage.session.clear();
    
    // 2. Clear local storage entirely, or remove specific keys + history
    const allLocal = await chrome.storage.local.get(null);
    const historyKeys = Object.keys(allLocal).filter(k => k.startsWith('history:'));
    if (historyKeys.length > 0) {
      await chrome.storage.local.remove(historyKeys);
    }
    await chrome.storage.local.clear();
    
    // 3. Restore default settings
    await chrome.storage.local.set({ settings: { default: true } });
    
    // 4. Clear badges
    await chrome.action.setBadgeText({ text: '' });
    
    // 5. Clear in-memory state
    inMemoryTabs.clear();
  };

  it('completely resets storage, memory, badges, and settings', async () => {
    // Setup state
    localData = {
      'settings': { modified: true },
      'history:123': 'some-history',
      'history:456': 'other-history',
      'random_key': 'random-value'
    };
    sessionData = {
      'tab_1': 'session-data'
    };
    inMemoryTabs.set(1, { generation: 2 });
    actionBadge = '9+';

    // Execute full reset
    await performFullReset();

    const chrome = (globalThis as any).chrome;

    // Verify local storage is default
    expect(localData).toEqual({ settings: { default: true } });
    // Verify legacy history keys are removed
    expect(localData).not.toHaveProperty('history:123');
    expect(localData).not.toHaveProperty('history:456');
    
    // Verify session is empty
    expect(sessionData).toEqual({});
    expect(chrome.storage.session.clear).toHaveBeenCalled();
    
    // Verify badges are cleared
    expect(actionBadge).toBe('');
    expect(chrome.action.setBadgeText).toHaveBeenCalledWith({ text: '' });
    
    // Verify in-memory maps are empty
    expect(inMemoryTabs.size).toBe(0);
  });
});
