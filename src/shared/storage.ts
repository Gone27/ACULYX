import type { TabState, SettingsV2, OriginHistoryItem } from './types';
import { STORAGE_KEYS } from './constants';
import { SettingsService } from './settings';
import { registrableDomain } from '../rules/headers/subdomain-trust';

// ─── Keyed Asynchronous Mutex ────────────────────────────────────────────────
// Serializes read-modify-write operations per tab, origin, or apex domain
// to eliminate lost history records, auth baselines, and graph updates.

export class KeyedAsyncMutex {
  private locks = new Map<string, Promise<void>>();

  async runExclusive<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const currentLock = this.locks.get(key) ?? Promise.resolve();
    let release!: () => void;
    const nextLock = new Promise<void>((resolve) => {
      release = resolve;
    });
    const tail = currentLock.then(() => nextLock, () => nextLock);
    this.locks.set(key, tail);

    try {
      await currentLock;
      return await fn();
    } finally {
      release();
      if (this.locks.get(key) === tail) {
        this.locks.delete(key);
      }
    }
  }

  isLocked(key: string): boolean {
    return this.locks.has(key);
  }
}

export const storageMutex = new KeyedAsyncMutex();

// ─── Storage Write Barrier & Reset Epoch ────────────────────────────────────
// Linearizes all in-flight and future storage mutations against full reset.
// Ensures that pre-reset writes cannot finish after storage clear and recreate data.

export class StorageWriteBarrier {
  private activeWrites = new Set<Promise<unknown>>();
  private barrierPromise: Promise<void> | null = null;
  private releaseBarrier: (() => void) | null = null;

  async enter(): Promise<void> {
    if (this.barrierPromise !== null) {
      await this.barrierPromise;
    }
  }

  track<T>(promise: Promise<T>): Promise<T> {
    this.activeWrites.add(promise);
    const cleanup = () => {
      this.activeWrites.delete(promise);
    };
    promise.then(cleanup, cleanup);
    return promise;
  }

  async closeBarrierAndDrain(): Promise<void> {
    if (this.barrierPromise === null) {
      let release!: () => void;
      this.barrierPromise = new Promise<void>((resolve) => {
        release = resolve;
      });
      this.releaseBarrier = release;
    }
    while (this.activeWrites.size > 0) {
      await Promise.allSettled(Array.from(this.activeWrites));
    }
  }

  openBarrier(): void {
    if (this.releaseBarrier !== null) {
      const release = this.releaseBarrier;
      this.releaseBarrier = null;
      this.barrierPromise = null;
      release();
    }
  }

  isClosed(): boolean {
    return this.barrierPromise !== null;
  }

  getActiveCount(): number {
    return this.activeWrites.size;
  }
}

export const storageWriteBarrier = new StorageWriteBarrier();

let storageResetEpoch = 0;

export function getStorageResetEpoch(): number {
  return storageResetEpoch;
}

export function setStorageResetEpoch(epoch: number): void {
  storageResetEpoch = epoch;
}

export function incrementStorageResetEpoch(): number {
  storageResetEpoch++;
  return storageResetEpoch;
}

export function isStorageEpochStale(epoch?: number): boolean {
  if (epoch === undefined) return false;
  return epoch !== storageResetEpoch;
}

// ─── Storage Health & Degraded State Tracking ────────────────────────────────

export interface StorageHealth {
  isDegraded: boolean;
  lastError: string | null;
  lastErrorTimestamp: number | null;
}

const storageHealth: StorageHealth = {
  isDegraded: false,
  lastError: null,
  lastErrorTimestamp: null,
};

export function getStorageHealth(): Readonly<StorageHealth> {
  return { ...storageHealth };
}

export function resetStorageHealth(): void {
  storageHealth.isDegraded = false;
  storageHealth.lastError = null;
  storageHealth.lastErrorTimestamp = null;
}

export function recordStorageFailure(error: unknown): void {
  storageHealth.isDegraded = true;
  storageHealth.lastError = error instanceof Error ? error.message : String(error);
  storageHealth.lastErrorTimestamp = Date.now();
}

// ─── Graph Bounding Constants ────────────────────────────────────────────────

export const MAX_GRAPH_NODES = 100;
export const MAX_GRAPH_EDGES = 150;
export const GRAPH_NODE_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

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

function deserializeTabState(raw: unknown): TabState {
  if (typeof raw !== 'object' || raw === null) {
    throw new Error('Invalid serialized TabState: not an object');
  }
  const candidate = raw as Record<string, unknown>;
  if (typeof candidate.tabId !== 'number' || typeof candidate.origin !== 'string') {
    throw new Error('Invalid serialized TabState: missing required tabId or origin');
  }
  const { apiEndpoints, ...rest } = candidate as unknown as SerializedTabState;
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
  if (Array.isArray(state.cookies)) {
    for (const cookie of state.cookies) {
      if ('value' in cookie) {
        throw new Error(
          `[SecCheck] Cookie value detected on ${cookie.name} — storage aborted.`
        );
      }
    }
  }

  const checkUrlStr = (urlStr: string | null | undefined, context: string): void => {
    if (urlStr === null || urlStr === undefined || urlStr === '') return;
    if (urlStr.includes('?')) {
      throw new Error(`[SecCheck] Unredacted query string detected in ${context} — storage aborted.`);
    }
    const match = urlStr.match(/:\/\/[^@/]+@/);
    if (match !== null) {
      throw new Error(`[SecCheck] Unredacted credentials detected in ${context} — storage aborted.`);
    }

    const checkSegments = (segments: string[]): void => {
      for (const seg of segments) {
        if (!seg || seg === '[id]' || seg === '[token]' || seg === '[redacted]') continue;
        const stem = seg.replace(/\.[a-zA-Z0-9]+$/, '');
        if (stem === '[id]' || stem === '[token]' || stem === '[redacted]') continue;

        const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg) ||
                       /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(stem) ||
                       /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i.test(seg);
        const isJwt = /^eyJ/.test(seg) || /^eyJ/.test(stem);
        const isLongOpaque = seg.length >= 20 || stem.length >= 20 || /^[0-9a-f]{16,}$/i.test(stem);
        const isEmail = /@/.test(seg);

        if (isUuid || isJwt || isLongOpaque || isEmail) {
          throw new Error(`[SecCheck] Unredacted sensitive token/path detected in ${context} — storage aborted.`);
        }
      }
    };

    if (urlStr.includes('#')) {
      throw new Error(`[SecCheck] Unredacted URL fragment detected in ${context} — storage aborted.`);
    }

    const tokens = urlStr.split(/[\s;]+/).filter(Boolean);
    for (const token of tokens) {
      if (token.includes('/')) {
        try {
          const u = new URL(token);
          checkSegments(u.pathname.split('/'));
        } catch {
          const pathOnly = token.replace(/^[a-zA-Z0-9+.-]+:\/\/[^/]+/, '');
          checkSegments(pathOnly.split('/'));
        }
      } else if (context === 'serviceWorkerUrl') {
        checkSegments([token]);
      }
    }
  };

  // Guard state top-level URL
  checkUrlStr(state.url, 'state.url');

  if (state.coverage !== undefined && state.coverage !== null) {
    checkUrlStr(state.coverage.serviceWorkerUrl, 'serviceWorkerUrl');
    if (Array.isArray(state.coverage.metaCspPolicies)) {
      for (const policy of state.coverage.metaCspPolicies) {
        checkUrlStr(policy, 'metaCspPolicies');
      }
    }
    if (Array.isArray(state.coverage.ledger)) {
      for (const entry of state.coverage.ledger) {
        checkUrlStr(entry.url, `ledger.url (${entry.type})`);
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
        checkUrlStr(hop.url, `hop[${i}].url`);
        checkHeaders(hop.headers, hop.rawHeaders, `hop[${i}]`);
      }
    }
  }

  // 3. Guard API endpoints
  if (state.apiEndpoints instanceof Map) {
    for (const [path, endpoint] of state.apiEndpoints.entries()) {
      checkUrlStr(path, `apiEndpoint[${path}].path`);
      checkUrlStr(endpoint.normalizedPath, `apiEndpoint[${path}].normalizedPath`);
      checkUrlStr(endpoint.lastHop.url, `apiEndpoint[${path}].lastHop.url`);
      checkHeaders(endpoint.lastHop.headers, endpoint.lastHop.rawHeaders, `apiEndpoint[${path}]`);
    }
  }

  // 4. Guard finding source URLs
  if (Array.isArray(state.findings)) {
    for (const f of state.findings) {
      if (f.sourceUrl !== undefined && f.sourceUrl !== '') {
        checkUrlStr(f.sourceUrl, `finding.sourceUrl (${f.ruleId})`);
      }
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

  async setTabState(state: TabState, epoch?: number): Promise<void> {
    assertNoSensitiveSecrets(state);
    const opEpoch = epoch ?? getStorageResetEpoch();
    if (isStorageEpochStale(opEpoch)) return;
    await storageWriteBarrier.enter();
    if (isStorageEpochStale(opEpoch)) return;

    const opPromise = storageMutex.runExclusive(`tab:${state.tabId}`, async () => {
      if (isStorageEpochStale(opEpoch)) return;
      const serialized = serializeTabState(state);
      const key = `${STORAGE_KEYS.TAB_PREFIX}${state.tabId}`;
      try {
        if (isStorageEpochStale(opEpoch)) return;
        const writePromise = chrome.storage.session.set({ [key]: serialized });
        await storageWriteBarrier.track(writePromise);
      } catch (err) {
        recordStorageFailure(err);
        throw err;
      }
    });

    return storageWriteBarrier.track(opPromise);
  },

  async removeTabState(tabId: number, epoch?: number): Promise<void> {
    const opEpoch = epoch ?? getStorageResetEpoch();
    if (isStorageEpochStale(opEpoch)) return;
    await storageWriteBarrier.enter();
    if (isStorageEpochStale(opEpoch)) return;

    const opPromise = storageMutex.runExclusive(`tab:${tabId}`, async () => {
      if (isStorageEpochStale(opEpoch)) return;
      const key = `${STORAGE_KEYS.TAB_PREFIX}${tabId}`;
      try {
        if (isStorageEpochStale(opEpoch)) return;
        const removePromise = chrome.storage.session.remove(key);
        await storageWriteBarrier.track(removePromise);
      } catch (err) {
        recordStorageFailure(err);
        throw err;
      }
    });

    return storageWriteBarrier.track(opPromise);
  },

  async clearAllTabStates(): Promise<void> {
    if (
      typeof chrome === 'undefined' ||
      typeof chrome.storage === 'undefined' ||
      typeof chrome.storage.session === 'undefined'
    ) {
      return;
    }
    await storageWriteBarrier.enter();
    try {
      const all = await chrome.storage.session.get(null);
      const tabKeys = Object.keys(all).filter((k) => k.startsWith(STORAGE_KEYS.TAB_PREFIX));
      if (tabKeys.length > 0) {
        const removePromise = chrome.storage.session.remove(tabKeys);
        await storageWriteBarrier.track(removePromise);
      }
    } catch (err) {
      recordStorageFailure(err);
      throw err;
    }
  },

  async getAllTabStates(): Promise<TabState[]> {
    const all = await chrome.storage.session.get(null);
    const results: TabState[] = [];
    for (const [k, v] of Object.entries(all)) {
      if (k.startsWith(STORAGE_KEYS.TAB_PREFIX)) {
        try {
          results.push(deserializeTabState(v as SerializedTabState));
        } catch {
          // Corrupt record — skip to avoid crashing hydration
        }
      }
    }
    return results;
  },

  getAuthBaselineKey(origin: string, tabId?: number): string {
    if (typeof tabId === 'number' && Number.isInteger(tabId) && tabId >= 0) {
      return `${origin}#tab:${tabId}`;
    }
    return origin;
  },

  async getAuthBaseline(origin: string, tabId?: number): Promise<import('./types').AuthBaseline | null> {
    if (!origin) return null;
    const baselineKey = this.getAuthBaselineKey(origin, tabId);
    const key = `${STORAGE_KEYS.AUTH_BASELINE_PREFIX}${baselineKey}`;
    const result = await chrome.storage.session.get(key);
    return (result[key] as import('./types').AuthBaseline | undefined) ?? null;
  },

  async setAuthBaseline(
    origin: string,
    baseline: import('./types').AuthBaseline,
    tabId?: number,
    epoch?: number,
  ): Promise<void> {
    if (!origin) return;
    const opEpoch = epoch ?? getStorageResetEpoch();
    if (isStorageEpochStale(opEpoch)) return;
    await storageWriteBarrier.enter();
    if (isStorageEpochStale(opEpoch)) return;

    const resolvedTabId = tabId ?? baseline.tabId;
    const baselineKey = this.getAuthBaselineKey(origin, resolvedTabId);
    const opPromise = storageMutex.runExclusive(`auth_baseline:${baselineKey}`, async () => {
      if (isStorageEpochStale(opEpoch)) return;
      const key = `${STORAGE_KEYS.AUTH_BASELINE_PREFIX}${baselineKey}`;
      try {
        if (isStorageEpochStale(opEpoch)) return;
        const writePromise = chrome.storage.session.set({ [key]: baseline });
        await storageWriteBarrier.track(writePromise);
      } catch (err) {
        recordStorageFailure(err);
        throw err;
      }
    });

    return storageWriteBarrier.track(opPromise);
  },

  async removeAuthBaseline(origin: string, tabId?: number, epoch?: number): Promise<void> {
    if (!origin) return;
    const opEpoch = epoch ?? getStorageResetEpoch();
    if (isStorageEpochStale(opEpoch)) return;
    await storageWriteBarrier.enter();
    if (isStorageEpochStale(opEpoch)) return;

    const baselineKey = this.getAuthBaselineKey(origin, tabId);
    const key = `${STORAGE_KEYS.AUTH_BASELINE_PREFIX}${baselineKey}`;
    try {
      if (isStorageEpochStale(opEpoch)) return;
      const removePromise = chrome.storage.session.remove(key);
      await storageWriteBarrier.track(removePromise);
    } catch (err) {
      recordStorageFailure(err);
      throw err;
    }
  },

  async getAllAuthBaselines(): Promise<Map<string, import('./types').AuthBaseline>> {
    const all = await chrome.storage.session.get(null);
    const map = new Map<string, import('./types').AuthBaseline>();
    for (const [k, v] of Object.entries(all)) {
      if (k.startsWith(STORAGE_KEYS.AUTH_BASELINE_PREFIX)) {
        const baselineKey = k.slice(STORAGE_KEYS.AUTH_BASELINE_PREFIX.length);
        map.set(baselineKey, v as import('./types').AuthBaseline);
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

/**
 * Pure function to prune auth diff items according to age and count policies.
 */
export function pruneAuthDiffItems(
  items: readonly import('./types').AuthDiffRecord[],
  now: number,
  retainHistoryDays: number,
  maxHistoryPerOrigin: number = DEFAULT_MAX_HISTORY_PER_ORIGIN,
): import('./types').AuthDiffRecord[] {
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

  async recordOriginHistory(origin: string, item: OriginHistoryItem, epoch?: number): Promise<void> {
    if (!origin) return;
    const opEpoch = epoch ?? getStorageResetEpoch();
    if (isStorageEpochStale(opEpoch)) return;
    await storageWriteBarrier.enter();
    if (isStorageEpochStale(opEpoch)) return;

    const opPromise = storageMutex.runExclusive(`origin:${origin}`, async () => {
      try {
        if (isStorageEpochStale(opEpoch)) return;
        const history = await this.getOriginHistory(origin);
        if (isStorageEpochStale(opEpoch)) return;
        // Avoid spamming history if the score and grade haven't changed in the last 60 seconds
        const last = history[history.length - 1];
        if (last && last.score === item.score && last.grade === item.grade && (item.timestamp - last.timestamp) < 60_000) {
          return;
        }
        const settings = await this.getSettings();
        if (isStorageEpochStale(opEpoch)) return;
        const updated = pruneHistoryItems(
          [...history, item],
          item.timestamp,
          settings.retainHistoryDays,
          settings.maxHistoryPerOrigin,
        );
        const key = `${STORAGE_KEYS.HISTORY_PREFIX}${origin}`;
        if (isStorageEpochStale(opEpoch)) return;
        const writePromise = chrome.storage.local.set({ [key]: updated });
        await storageWriteBarrier.track(writePromise);
      } catch (err) {
        recordStorageFailure(err);
        throw err;
      }
    });

    return storageWriteBarrier.track(opPromise);
  },

  async pruneAllHistory(now: number = Date.now(), settings?: SettingsV2, epoch?: number): Promise<void> {
    if (typeof chrome === 'undefined' || chrome.storage?.local === undefined) {
      return;
    }
    const opEpoch = epoch ?? getStorageResetEpoch();
    if (isStorageEpochStale(opEpoch)) return;
    await storageWriteBarrier.enter();
    if (isStorageEpochStale(opEpoch)) return;

    try {
      const currentSettings = settings ?? (await this.getSettings());
      if (isStorageEpochStale(opEpoch)) return;
      const all = await chrome.storage.local.get(null);
      if (isStorageEpochStale(opEpoch)) return;
      const updates: Record<string, unknown> = {};
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
        } else if (key.startsWith(STORAGE_KEYS.AUTH_DIFF_PREFIX)) {
          if (Array.isArray(value)) {
            const pruned = pruneAuthDiffItems(
              value as import('./types').AuthDiffRecord[],
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
        } else if (key.startsWith(STORAGE_KEYS.GRAPH_PREFIX)) {
          if (typeof value === 'object' && value !== null && 'nodes' in value && Array.isArray((value as { nodes?: unknown }).nodes)) {
            const graph = value as import('./types').AttackSurfaceGraph;
            const maxAgeMs = currentSettings.retainHistoryDays > 0
              ? currentSettings.retainHistoryDays * 24 * 60 * 60 * 1000
              : GRAPH_NODE_TTL_MS;
            const cutoff = now - maxAgeMs;
            const filteredNodes = graph.nodes.filter(
              (n) => n.isApex || !n.lastSeen || n.lastSeen >= cutoff,
            );
            const validHosts = new Set(filteredNodes.map((n) => n.hostname));
            const filteredEdges = graph.edges.filter(
              (e) => validHosts.has(e.source) && validHosts.has(e.target),
            );
            if (filteredNodes.length <= 1 && filteredEdges.length === 0 && (graph.lastUpdated || 0) < cutoff) {
              toRemove.push(key);
            } else if (filteredNodes.length !== graph.nodes.length || filteredEdges.length !== graph.edges.length) {
              updates[key] = {
                ...graph,
                nodes: filteredNodes,
                edges: filteredEdges,
                lastUpdated: now,
              };
            }
          }
        }
      }

      if (isStorageEpochStale(opEpoch)) return;
      if (Object.keys(updates).length > 0) {
        const p1 = chrome.storage.local.set(updates);
        await storageWriteBarrier.track(p1);
      }
      if (toRemove.length > 0) {
        const p2 = chrome.storage.local.remove(toRemove);
        await storageWriteBarrier.track(p2);
      }
    } catch (err) {
      recordStorageFailure(err);
      throw err;
    }
  },

  async purgeOriginData(origin: string, epoch?: number): Promise<void> {
    if (!origin || typeof chrome === 'undefined' || chrome.storage?.local === undefined) return;
    const opEpoch = epoch ?? getStorageResetEpoch();
    if (isStorageEpochStale(opEpoch)) return;
    await storageWriteBarrier.enter();
    if (isStorageEpochStale(opEpoch)) return;

    const opPromise = storageMutex.runExclusive(`origin:${origin}`, async () => {
      try {
        if (isStorageEpochStale(opEpoch)) return;
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
            if (isStorageEpochStale(opEpoch)) return;
            if (graph) {
              graph.nodes = graph.nodes.filter((n) => n.hostname !== hostname);
              graph.edges = graph.edges.filter((e) => e.source !== hostname && e.target !== hostname);
              if (graph.nodes.length <= 1 && graph.nodes.every((n) => n.isApex)) {
                keysToRemove.push(`${STORAGE_KEYS.GRAPH_PREFIX}${apex}`);
              } else {
                await this.saveGraph(graph, opEpoch);
              }
            }
          }
        }

        if (hostname && hostname !== apex) {
          keysToRemove.push(`${STORAGE_KEYS.GRAPH_PREFIX}${hostname}`);
        }

        if (isStorageEpochStale(opEpoch)) return;
        const p1 = chrome.storage.local.remove(keysToRemove);
        await storageWriteBarrier.track(p1);

        if (typeof chrome !== 'undefined' && chrome.storage?.session !== undefined) {
          try {
            const allSession = await chrome.storage.session.get(null);
            if (isStorageEpochStale(opEpoch)) return;
            const baselinePrefix = `${STORAGE_KEYS.AUTH_BASELINE_PREFIX}${origin}`;
            const sessionKeysToRemove = Object.keys(allSession).filter(
              (k) => k === baselinePrefix || k.startsWith(`${baselinePrefix}#tab:`),
            );
            if (sessionKeysToRemove.length > 0) {
              const p2 = chrome.storage.session.remove(sessionKeysToRemove);
              await storageWriteBarrier.track(p2);
            }
          } catch {
            // Ignore session storage removal errors
          }
        }
      } catch (err) {
        recordStorageFailure(err);
        throw err;
      }
    });

    return storageWriteBarrier.track(opPromise);
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

  async recordAuthDiff(origin: string, diff: import('./types').AuthDiffRecord, epoch?: number): Promise<void> {
    if (!origin) return;
    const opEpoch = epoch ?? getStorageResetEpoch();
    if (isStorageEpochStale(opEpoch)) return;
    await storageWriteBarrier.enter();
    if (isStorageEpochStale(opEpoch)) return;

    const opPromise = storageMutex.runExclusive(`auth_diff:${origin}`, async () => {
      try {
        if (isStorageEpochStale(opEpoch)) return;
        const history = await this.getAuthDiffHistory(origin);
        if (isStorageEpochStale(opEpoch)) return;
        const settings = await this.getSettings();
        if (isStorageEpochStale(opEpoch)) return;
        const updated = pruneAuthDiffItems(
          [...history, diff],
          diff.timestamp || Date.now(),
          settings.retainHistoryDays,
          settings.maxHistoryPerOrigin,
        );
        const key = `${STORAGE_KEYS.AUTH_DIFF_PREFIX}${origin}`;
        if (isStorageEpochStale(opEpoch)) return;
        const writePromise = chrome.storage.local.set({ [key]: updated });
        await storageWriteBarrier.track(writePromise);
      } catch (err) {
        recordStorageFailure(err);
        throw err;
      }
    });

    return storageWriteBarrier.track(opPromise);
  },

  async getGraph(apexDomain: string): Promise<import('./types').AttackSurfaceGraph | null> {
    if (!apexDomain) return null;
    const key = `${STORAGE_KEYS.GRAPH_PREFIX}${apexDomain}`;
    const result = await chrome.storage.local.get(key);
    return (result[key] as import('./types').AttackSurfaceGraph | undefined) ?? null;
  },

  async saveGraph(graph: import('./types').AttackSurfaceGraph, epoch?: number): Promise<void> {
    if (!graph.apexDomain) return;
    const opEpoch = epoch ?? getStorageResetEpoch();
    if (isStorageEpochStale(opEpoch)) return;
    await storageWriteBarrier.enter();
    if (isStorageEpochStale(opEpoch)) return;

    const opPromise = storageMutex.runExclusive(`graph:${graph.apexDomain}`, async () => {
      try {
        if (isStorageEpochStale(opEpoch)) return;
        const now = Date.now();
        const maxLastSeen = Math.max(0, ...graph.nodes.map((n) => n.lastSeen || 0));
        const refTime = maxLastSeen > 0 ? maxLastSeen : now;
        let nodes = graph.nodes.filter(
          (n) => n.isApex || !n.lastSeen || Math.abs(refTime - n.lastSeen) <= GRAPH_NODE_TTL_MS,
        );
        if (nodes.length > MAX_GRAPH_NODES) {
          const apex = nodes.find((n) => n.isApex);
          const nonApex = nodes.filter((n) => !n.isApex).sort((a, b) => b.lastSeen - a.lastSeen);
          nodes = apex ? [apex, ...nonApex.slice(0, MAX_GRAPH_NODES - 1)] : nonApex.slice(0, MAX_GRAPH_NODES);
        }
        const validHosts = new Set(nodes.map((n) => n.hostname));
        let edges = graph.edges.filter(
          (e) => validHosts.has(e.source) && validHosts.has(e.target),
        );
        if (edges.length > MAX_GRAPH_EDGES) {
          edges = edges.slice(0, MAX_GRAPH_EDGES);
        }
        const boundedGraph: import('./types').AttackSurfaceGraph = {
          ...graph,
          nodes,
          edges,
          lastUpdated: now,
        };
        const key = `${STORAGE_KEYS.GRAPH_PREFIX}${graph.apexDomain}`;
        if (isStorageEpochStale(opEpoch)) return;
        const writePromise = chrome.storage.local.set({ [key]: boundedGraph });
        await storageWriteBarrier.track(writePromise);
      } catch (err) {
        recordStorageFailure(err);
        throw err;
      }
    });

    return storageWriteBarrier.track(opPromise);
  },

  /**
   * Atomically mutates the attack surface graph for an apex domain within a mutex.
   * Guarantees read-modify-write safety without lost updates.
   */
  async mutateGraph(
    apexDomain: string,
    mutator: (current: import('./types').AttackSurfaceGraph | null) => import('./types').AttackSurfaceGraph,
    epoch?: number,
  ): Promise<import('./types').AttackSurfaceGraph | null> {
    if (!apexDomain) return null;
    const opEpoch = epoch ?? getStorageResetEpoch();
    if (isStorageEpochStale(opEpoch)) return null;
    await storageWriteBarrier.enter();
    if (isStorageEpochStale(opEpoch)) return null;

    const opPromise = storageMutex.runExclusive(`graph:${apexDomain}`, async () => {
      try {
        if (isStorageEpochStale(opEpoch)) return null;
        const current = await this.getGraph(apexDomain);
        if (isStorageEpochStale(opEpoch)) return null;
        const updated = mutator(current);
        const now = Date.now();
        const maxLastSeen = Math.max(0, ...updated.nodes.map((n) => n.lastSeen || 0));
        const refTime = maxLastSeen > 0 ? maxLastSeen : now;
        let nodes = updated.nodes.filter(
          (n) => n.isApex || !n.lastSeen || Math.abs(refTime - n.lastSeen) <= GRAPH_NODE_TTL_MS,
        );
        if (nodes.length > MAX_GRAPH_NODES) {
          const apex = nodes.find((n) => n.isApex);
          const nonApex = nodes.filter((n) => !n.isApex).sort((a, b) => b.lastSeen - a.lastSeen);
          nodes = apex ? [apex, ...nonApex.slice(0, MAX_GRAPH_NODES - 1)] : nonApex.slice(0, MAX_GRAPH_NODES);
        }
        const validHosts = new Set(nodes.map((n) => n.hostname));
        let edges = updated.edges.filter(
          (e) => validHosts.has(e.source) && validHosts.has(e.target),
        );
        if (edges.length > MAX_GRAPH_EDGES) {
          edges = edges.slice(0, MAX_GRAPH_EDGES);
        }
        const boundedGraph: import('./types').AttackSurfaceGraph = {
          ...updated,
          nodes,
          edges,
          lastUpdated: now,
        };
        const key = `${STORAGE_KEYS.GRAPH_PREFIX}${apexDomain}`;
        if (isStorageEpochStale(opEpoch)) return null;
        const writePromise = chrome.storage.local.set({ [key]: boundedGraph });
        await storageWriteBarrier.track(writePromise);
        return boundedGraph;
      } catch (err) {
        recordStorageFailure(err);
        throw err;
      }
    });

    return storageWriteBarrier.track(opPromise);
  },

  async isOnboardingDismissed(): Promise<boolean> {
    const result = await chrome.storage.local.get(STORAGE_KEYS.ONBOARDING_DISMISSED);
    return Boolean(result[STORAGE_KEYS.ONBOARDING_DISMISSED]);
  },

  async setOnboardingDismissed(dismissed: boolean): Promise<void> {
    await chrome.storage.local.set({ [STORAGE_KEYS.ONBOARDING_DISMISSED]: dismissed });
  },

  async deleteOriginData(origin: string): Promise<void> {
    await this.purgeOriginData(origin);
  },

  async deleteAllHistory(epoch?: number): Promise<void> {
    const opEpoch = epoch ?? getStorageResetEpoch();
    if (isStorageEpochStale(opEpoch)) return;
    await storageWriteBarrier.enter();
    if (isStorageEpochStale(opEpoch)) return;
    try {
      const all = await chrome.storage.local.get(null);
      if (isStorageEpochStale(opEpoch)) return;
      const histKeys = Object.keys(all).filter(k => k.startsWith(STORAGE_KEYS.HISTORY_PREFIX) || k.startsWith('history:'));
      if (histKeys.length > 0) {
        const p = chrome.storage.local.remove(histKeys);
        await storageWriteBarrier.track(p);
      }
    } catch (err) {
      recordStorageFailure(err);
      throw err;
    }
  },

  async deletePrivateRecords(epoch?: number): Promise<void> {
    const opEpoch = epoch ?? getStorageResetEpoch();
    if (isStorageEpochStale(opEpoch)) return;
    await storageWriteBarrier.enter();
    if (isStorageEpochStale(opEpoch)) return;
    try {
      const all = await chrome.storage.session.get(null);
      if (isStorageEpochStale(opEpoch)) return;
      const toRemove = Object.entries(all)
        .filter(([k, v]) => k.startsWith(STORAGE_KEYS.TAB_PREFIX) && typeof v === 'object' && v !== null && (v as { isIncognito?: boolean }).isIncognito === true)
        .map(([k]) => k);
      if (toRemove.length > 0) {
        const p = chrome.storage.session.remove(toRemove);
        await storageWriteBarrier.track(p);
      }
    } catch (err) {
      recordStorageFailure(err);
      throw err;
    }
  },

  async resetAllData(): Promise<void> {
    incrementStorageResetEpoch();
    await storageWriteBarrier.closeBarrierAndDrain();
    try {
      await chrome.storage.local.clear();
      if (typeof chrome.storage.session !== 'undefined') {
        await chrome.storage.session.clear();
      }
    } catch (err) {
      recordStorageFailure(err);
      throw err;
    } finally {
      storageWriteBarrier.openBarrier();
    }
  },

  async clearAll(): Promise<void> {
    incrementStorageResetEpoch();
    await storageWriteBarrier.closeBarrierAndDrain();
    try {
      await chrome.storage.local.clear();
    } catch (err) {
      recordStorageFailure(err);
      throw err;
    } finally {
      storageWriteBarrier.openBarrier();
    }
  },
};
