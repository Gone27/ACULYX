import type { TabState, SettingsV2, OriginHistoryItem } from './types';
import { STORAGE_KEYS } from './constants';
import { SettingsService } from './settings';
import { registrableDomain } from '../rules/headers/subdomain-trust';

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

export function hasUnredactedCookieValue(headerStr: string, isSetCookie: boolean = false): boolean {
  if (!headerStr) return false;
  if (isSetCookie) {
    const lines = headerStr.split(/\r?\n/);
    for (const line of lines) {
      const semiIdx = line.indexOf(';');
      const firstPart = semiIdx !== -1 ? line.slice(0, semiIdx) : line;
      const eqIdx = firstPart.indexOf('=');
      if (eqIdx !== -1) {
        const val = firstPart.slice(eqIdx + 1).trim();
        if (val !== '' && val !== '[REDACTED]' && val !== '[redacted]') {
          return true;
        }
      }
    }
    return false;
  }

  const parts = headerStr.split(';');
  for (const part of parts) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx !== -1) {
      const val = trimmed.slice(eqIdx + 1).trim();
      if (val !== '' && val !== '[REDACTED]' && val !== '[redacted]') {
        return true;
      }
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
          if (hasUnredactedCookieValue(v, lower === 'set-cookie')) {
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
          if (hasUnredactedCookieValue(h.value, lower === 'set-cookie')) {
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

  async clearAllTabStates(): Promise<void> {
    if (
      typeof chrome === 'undefined' ||
      typeof chrome.storage === 'undefined' ||
      typeof chrome.storage.session === 'undefined'
    ) {
      return;
    }
    const all = await chrome.storage.session.get(null);
    const tabKeys = Object.keys(all).filter((k) => k.startsWith(STORAGE_KEYS.TAB_PREFIX));
    if (tabKeys.length > 0) {
      await chrome.storage.session.remove(tabKeys);
    }
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

const DEFAULT_MAX_HISTORY_PER_ORIGIN = 10;

/**
 * Pure function to prune origin history items according to age and count policies.
 *
 * Precedence (Contract Section 5.1):
 * 1. Age pruning (retainHistoryDays): if > 0, prune items older than retainHistoryDays * 86,400,000 ms.
 *    If 0, keep forever (age pruning disabled).
 * 2. Count cap (maxHistoryPerOrigin): keep at most maxHistoryPerOrigin newest items (default 10, range 1..50).
 */
export function pruneHistoryItems(
  items: readonly OriginHistoryItem[],
  now: number,
  retainHistoryDays: number,
  maxHistoryPerOrigin: number = DEFAULT_MAX_HISTORY_PER_ORIGIN,
): OriginHistoryItem[] {
  let filtered = [...items];

  // 1. Age pruning
  if (retainHistoryDays > 0) {
    const maxAgeMs = retainHistoryDays * 24 * 60 * 60 * 1000;
    const cutoff = now - maxAgeMs;
    filtered = filtered.filter((item) => item.timestamp >= cutoff);
  }

  // 2. Count cap (clamped between 1 and 50)
  const rawCap = typeof maxHistoryPerOrigin === 'number' && !Number.isNaN(maxHistoryPerOrigin)
    ? maxHistoryPerOrigin
    : DEFAULT_MAX_HISTORY_PER_ORIGIN;
  const cap = Math.max(1, Math.min(50, Math.floor(rawCap)));
  if (filtered.length > cap) {
    filtered = filtered.slice(-cap);
  }

  return filtered;
}

export const LocalStorage = {
  async getSettings(): Promise<SettingsV2> {
    return await SettingsService.getSettings();
  },

  async setSettings(settings: SettingsV2): Promise<void> {
    await SettingsService.updateSettings(settings);
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
    const settings = await this.getSettings();
    const updated = pruneHistoryItems(
      [...history, item],
      item.timestamp,
      settings.retainHistoryDays,
      settings.maxHistoryPerOrigin,
    );
    const key = `${STORAGE_KEYS.HISTORY_PREFIX}${origin}`;
    await chrome.storage.local.set({ [key]: updated });
  },

  async pruneAllHistory(now: number = Date.now(), settings?: SettingsV2): Promise<void> {
    if (typeof chrome === 'undefined' || chrome.storage?.local === undefined) {
      return;
    }
    const currentSettings = settings ?? (await this.getSettings());
    const all = await chrome.storage.local.get(null);
    const updates: Record<string, OriginHistoryItem[]> = {};
    const toRemove: string[] = [];

    for (const [key, value] of Object.entries(all)) {
      if (key.startsWith(STORAGE_KEYS.HISTORY_PREFIX) || key.startsWith('history:')) {
        if (Array.isArray(value)) {
          const pruned = pruneHistoryItems(
            value as OriginHistoryItem[],
            now,
            currentSettings.retainHistoryDays,
            currentSettings.maxHistoryPerOrigin,
          );
          if (pruned.length === 0) {
            toRemove.push(key);
          } else {
            updates[key] = pruned;
          }
        }
      }
    }

    if (Object.keys(updates).length > 0) {
      await chrome.storage.local.set(updates);
    }
    if (toRemove.length > 0) {
      await chrome.storage.local.remove(toRemove);
    }
  },

  async purgeOriginData(origin: string): Promise<void> {
    if (!origin || typeof chrome === 'undefined' || chrome.storage?.local === undefined) return;
    const keysToRemove = [
      `${STORAGE_KEYS.HISTORY_PREFIX}${origin}`,
      `history:${origin}`,
      `${STORAGE_KEYS.AUTH_DIFF_PREFIX}${origin}`,
      `${STORAGE_KEYS.AUTH_BASELINE_PREFIX}${origin}`,
    ];

    let hostname = origin;
    try {
      hostname = new URL(origin).hostname;
    } catch {
      // not a parseable URL
    }

    const apex = registrableDomain(hostname) ?? hostname;

    if (apex) {
      if (hostname === apex) {
        keysToRemove.push(`${STORAGE_KEYS.GRAPH_PREFIX}${apex}`);
      } else {
        const graph = await this.getGraph(apex);
        if (graph) {
          graph.nodes = graph.nodes.filter((n) => n.hostname !== hostname);
          graph.edges = graph.edges.filter((e) => e.source !== hostname && e.target !== hostname);
          if (graph.nodes.length <= 1 && graph.nodes.every((n) => n.isApex)) {
            keysToRemove.push(`${STORAGE_KEYS.GRAPH_PREFIX}${apex}`);
          } else {
            await this.saveGraph(graph);
          }
        }
      }
    }

    if (hostname && hostname !== apex) {
      keysToRemove.push(`${STORAGE_KEYS.GRAPH_PREFIX}${hostname}`);
    }

    await chrome.storage.local.remove(keysToRemove);
    if (typeof chrome !== 'undefined' && chrome.storage?.session !== undefined) {
      await chrome.storage.session.remove(`${STORAGE_KEYS.AUTH_BASELINE_PREFIX}${origin}`).catch(() => {});
    }
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
    const updated = [...history, diff].slice(-DEFAULT_MAX_HISTORY_PER_ORIGIN);
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
