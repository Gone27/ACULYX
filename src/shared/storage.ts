import type { TabState, Settings, OriginHistoryItem } from './types';
import { DEFAULT_SETTINGS, STORAGE_KEYS } from './constants';

// ─── Session storage ──────────────────────────────────────────────────────────
//
// Stores per-tab live state. chrome.storage.session persists across
// service-worker restarts within a browser session (not across browser close).
// This is how we survive MV3's SW-kill-on-idle.

export const SessionStorage = {
  async getTabState(tabId: number): Promise<TabState | null> {
    const key = `${STORAGE_KEYS.TAB_PREFIX}${tabId}`;
    const result = await chrome.storage.session.get(key);
    return (result[key] as TabState | undefined) ?? null;
  },

  async setTabState(state: TabState): Promise<void> {
    // Assertion: cookie values must never appear in storage.
    // CookieRecord has no 'value' field by type, but this runtime guard
    // catches any accidental extension of the type that adds one.
    for (const cookie of state.cookies) {
      if ('value' in cookie) {
        throw new Error(
          `[SecCheck] Cookie value detected on ${cookie.name} — storage aborted.`
        );
      }
    }
    const key = `${STORAGE_KEYS.TAB_PREFIX}${state.tabId}`;
    await chrome.storage.session.set({ [key]: state });
  },

  async removeTabState(tabId: number): Promise<void> {
    const key = `${STORAGE_KEYS.TAB_PREFIX}${tabId}`;
    await chrome.storage.session.remove(key);
  },

  async getAllTabStates(): Promise<TabState[]> {
    const all = await chrome.storage.session.get(null);
    return Object.entries(all)
      .filter(([k]) => k.startsWith(STORAGE_KEYS.TAB_PREFIX))
      .map(([, v]) => v as TabState);
  },
};

// ─── Local storage ────────────────────────────────────────────────────────────
//
// Stores user settings, capped per-origin history, and onboarding state.

const MAX_HISTORY_PER_ORIGIN = 10;

export const LocalStorage = {
  async getSettings(): Promise<Settings> {
    const result = await chrome.storage.local.get(STORAGE_KEYS.SETTINGS);
    const stored = result[STORAGE_KEYS.SETTINGS] as Partial<Settings> | undefined;
    // Merge with defaults so new keys added in future versions populate
    return { ...DEFAULT_SETTINGS, ...stored };
  },

  async setSettings(settings: Settings): Promise<void> {
    await chrome.storage.local.set({ [STORAGE_KEYS.SETTINGS]: settings });
  },

  async getOriginHistory(origin: string): Promise<OriginHistoryItem[]> {
    if (!origin) return [];
    const key = `${STORAGE_KEYS.HISTORY_PREFIX}${origin}`;
    const result = await chrome.storage.local.get(key);
    return (result[key] as OriginHistoryItem[] | undefined) ?? [];
  },

  async recordOriginHistory(origin: string, item: OriginHistoryItem): Promise<void> {
    if (!origin) return;
    const history = await this.getOriginHistory(origin);
    // Avoid spamming history if the score and grade haven't changed in the last 60 seconds
    const last = history[history.length - 1];
    if (last && last.score === item.score && last.grade === item.grade && (item.timestamp - last.timestamp) < 60_000) {
      return;
    }
    const updated = [...history, item].slice(-MAX_HISTORY_PER_ORIGIN);
    const key = `${STORAGE_KEYS.HISTORY_PREFIX}${origin}`;
    await chrome.storage.local.set({ [key]: updated });
  },

  async isOnboardingDismissed(): Promise<boolean> {
    const result = await chrome.storage.local.get(STORAGE_KEYS.ONBOARDING_DISMISSED);
    return Boolean(result[STORAGE_KEYS.ONBOARDING_DISMISSED]);
  },

  async setOnboardingDismissed(dismissed: boolean): Promise<void> {
    await chrome.storage.local.set({ [STORAGE_KEYS.ONBOARDING_DISMISSED]: dismissed });
  },

  async clearAll(): Promise<void> {
    await chrome.storage.local.clear();
  },
};
