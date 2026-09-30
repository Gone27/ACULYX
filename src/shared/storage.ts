import type { TabState, Settings, OriginHistoryItem } from './types';
import { DEFAULT_SETTINGS, STORAGE_KEYS } from './constants';

// ─── Session storage ──────────────────────────────────────────────────────────
//
// Stores per-tab live state. chrome.storage.session persists across
// service-worker restarts within a browser session (not across browser close).
// This is how we survive MV3's SW-kill-on-idle.

/** Serialized form stored in chrome.storage.session (JSON-safe). */
type SerializedTabState = Omit<TabState, 'apiEndpoints'> & {
  apiEndpoints?: [string, import('./types').ApiEndpointState][];
};

function serializeTabState(state: TabState): SerializedTabState {
  const { apiEndpoints, ...rest } = state;
  if (apiEndpoints !== undefined) {
    return { ...rest, apiEndpoints: Array.from(apiEndpoints.entries()) };
  }
  return rest;
}

function deserializeTabState(raw: SerializedTabState): TabState {
  const { apiEndpoints, ...rest } = raw;
  if (Array.isArray(apiEndpoints)) {
    return { ...rest, apiEndpoints: new Map(apiEndpoints) };
  }
  return rest;
}

function hasUnredactedCookieValue(headerStr: string): boolean {
  if (!headerStr) return false;
  const semiIdx = headerStr.indexOf(';');
  const firstPart = semiIdx !== -1 ? headerStr.slice(0, semiIdx) : headerStr;
  const eqIdx = firstPart.indexOf('=');
  if (eqIdx !== -1) {
    const val = firstPart.slice(eqIdx + 1).trim();
    if (val !== '' && val !== '[REDACTED]' && val !== '[redacted]') {
      return true;
    }
  }
  return false;
}

export function assertNoSensitiveSecrets(state: TabState): void {
  // 1. Guard against cookie records having a 'value' property
  if (Array.isArray(state.cookies)) {
    for (const cookie of state.cookies) {
      if ('value' in cookie) {
        throw new Error(
          `[SecCheck] Cookie value detected on ${cookie.name} — storage aborted.`
        );
      }
    }
  }

  const checkHeaders = (
    headers: Record<string, string> | undefined,
    rawHeaders: Array<{ name: string; value: string }> | undefined,
    context: string,
  ): void => {
    if (headers) {
      for (const [k, v] of Object.entries(headers)) {
        const lower = k.toLowerCase();
        if (lower === 'set-cookie' || lower === 'cookie') {
          if (hasUnredactedCookieValue(v)) {
            throw new Error(`[SecCheck] Unredacted ${k} header detected in ${context} — storage aborted.`);
          }
        } else if (lower === 'authorization' || lower === 'proxy-authorization') {
          if (v !== '[REDACTED]' && v !== '[redacted]') {
            throw new Error(`[SecCheck] Unredacted ${k} header detected in ${context} — storage aborted.`);
          }
        }
      }
    }

    if (rawHeaders) {
      for (const h of rawHeaders) {
        const lower = h.name.toLowerCase();
        if (lower === 'set-cookie' || lower === 'cookie') {
          if (hasUnredactedCookieValue(h.value)) {
            throw new Error(`[SecCheck] Unredacted ${h.name} rawHeader detected in ${context} — storage aborted.`);
          }
        } else if (lower === 'authorization' || lower === 'proxy-authorization') {
          if (h.value !== '[REDACTED]' && h.value !== '[redacted]') {
            throw new Error(`[SecCheck] Unredacted ${h.name} rawHeader detected in ${context} — storage aborted.`);
          }
        }
      }
    }
  };

  // 2. Guard hops
  if (Array.isArray(state.hops)) {
    for (let i = 0; i < state.hops.length; i++) {
      const hop = state.hops[i];
      if (hop) {
        checkHeaders(hop.headers, hop.rawHeaders, `hop[${i}]`);
      }
    }
  }

  // 3. Guard API endpoints
  if (state.apiEndpoints instanceof Map) {
    for (const [path, endpoint] of state.apiEndpoints.entries()) {
      checkHeaders(endpoint.lastHop.headers, endpoint.lastHop.rawHeaders, `apiEndpoint[${path}]`);
    }
  }
}

export const SessionStorage = {
  async getTabState(tabId: number): Promise<TabState | null> {
    const key = `${STORAGE_KEYS.TAB_PREFIX}${tabId}`;
    const result = await chrome.storage.session.get(key);
    const raw = result[key] as SerializedTabState | undefined;
    if (raw === undefined) return null;
    return deserializeTabState(raw);
  },

  async setTabState(state: TabState): Promise<void> {
    assertNoSensitiveSecrets(state);
    const serialized = serializeTabState(state);
    const key = `${STORAGE_KEYS.TAB_PREFIX}${state.tabId}`;
    await chrome.storage.session.set({ [key]: serialized });
  },

  async removeTabState(tabId: number): Promise<void> {
    const key = `${STORAGE_KEYS.TAB_PREFIX}${tabId}`;
    await chrome.storage.session.remove(key);
  },

  async getAllTabStates(): Promise<TabState[]> {
    const all = await chrome.storage.session.get(null);
    return Object.entries(all)
      .filter(([k]) => k.startsWith(STORAGE_KEYS.TAB_PREFIX))
      .map(([, v]) => deserializeTabState(v as SerializedTabState));
  },

  async getAuthBaseline(origin: string): Promise<import('./types').AuthBaseline | null> {
    if (!origin) return null;
    const key = `${STORAGE_KEYS.AUTH_BASELINE_PREFIX}${origin}`;
    const result = await chrome.storage.session.get(key);
    return (result[key] as import('./types').AuthBaseline | undefined) ?? null;
  },

  async setAuthBaseline(origin: string, baseline: import('./types').AuthBaseline): Promise<void> {
    if (!origin) return;
    const key = `${STORAGE_KEYS.AUTH_BASELINE_PREFIX}${origin}`;
    await chrome.storage.session.set({ [key]: baseline });
  },

  async getAllAuthBaselines(): Promise<Map<string, import('./types').AuthBaseline>> {
    const all = await chrome.storage.session.get(null);
    const map = new Map<string, import('./types').AuthBaseline>();
    for (const [k, v] of Object.entries(all)) {
      if (k.startsWith(STORAGE_KEYS.AUTH_BASELINE_PREFIX)) {
        const origin = k.slice(STORAGE_KEYS.AUTH_BASELINE_PREFIX.length);
        map.set(origin, v as import('./types').AuthBaseline);
      }
    }
    return map;
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

  async getAuthDiffHistory(origin: string): Promise<import('./types').AuthDiffRecord[]> {
    if (!origin) return [];
    const key = `${STORAGE_KEYS.AUTH_DIFF_PREFIX}${origin}`;
    const result = await chrome.storage.local.get(key);
    return (result[key] as import('./types').AuthDiffRecord[] | undefined) ?? [];
  },

  async getLatestAuthDiff(origin: string): Promise<import('./types').AuthDiffRecord | null> {
    const list = await this.getAuthDiffHistory(origin);
    return list.length > 0 ? (list[list.length - 1] ?? null) : null;
  },

  async recordAuthDiff(origin: string, diff: import('./types').AuthDiffRecord): Promise<void> {
    if (!origin) return;
    const history = await this.getAuthDiffHistory(origin);
    const updated = [...history, diff].slice(-MAX_HISTORY_PER_ORIGIN);
    const key = `${STORAGE_KEYS.AUTH_DIFF_PREFIX}${origin}`;
    await chrome.storage.local.set({ [key]: updated });
  },

  async getGraph(apexDomain: string): Promise<import('./types').AttackSurfaceGraph | null> {
    if (!apexDomain) return null;
    const key = `${STORAGE_KEYS.GRAPH_PREFIX}${apexDomain}`;
    const result = await chrome.storage.local.get(key);
    return (result[key] as import('./types').AttackSurfaceGraph | undefined) ?? null;
  },

  async saveGraph(graph: import('./types').AttackSurfaceGraph): Promise<void> {
    if (!graph.apexDomain) return;
    const key = `${STORAGE_KEYS.GRAPH_PREFIX}${graph.apexDomain}`;
    await chrome.storage.local.set({ [key]: graph });
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
