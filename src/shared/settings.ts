/**
 * settings.ts
 *
 * Single settings service and authoritative read/write path for extension settings.
 * Enforces schema v2 validation, idempotent migration from legacy v1 shapes,
 * in-memory caching with storage.onChanged invalidation, and change subscriptions.
 *
 * WS1: Implements atomic settings transitions via SettingsTransitionPipeline with
 * lastAppliedSettings snapshot and delta detection for cookie list changes and mode transitions.
 */

import { DEFAULT_SETTINGS, STORAGE_KEYS } from './constants';
import type { Severity, SettingsV2 } from './types';
import {
  storageWriteBarrier,
  getStorageResetEpoch,
  isStorageEpochStale,
} from './write-barrier';

// ---------------------------------------------------------------------------
// Helpers: normalization and validation
// ---------------------------------------------------------------------------

const VALID_MODES = new Set<SettingsV2['monitoringMode']>(['per-site', 'all-sites', 'off']);
const VALID_SEVERITIES = new Set<Severity>(['critical', 'high', 'medium', 'low', 'info', 'pass']);

/**
 * Normalizes a list of cookie names: trims whitespace, lowercases, and deduplicates.
 */
export function normalizeCookieList(names: unknown): string[] {
  if (!Array.isArray(names)) return [];
  const set = new Set<string>();
  for (const item of names) {
    if (typeof item === 'string') {
      const trimmed = item.trim().toLowerCase();
      if (trimmed.length > 0) {
        set.add(trimmed);
      }
    }
  }
  return Array.from(set);
}

/**
 * Resolves overlaps between sensitive and ignored cookie lists.
 * Invariant: if a cookie name is in both lists, "ignored" wins.
 */
export function resolveCookieOverlaps(
  sensitive: string[],
  ignored: string[]
): { sensitive: string[]; ignored: string[]; overlaps: string[] } {
  const ignoredSet = new Set(ignored);
  const overlaps: string[] = [];
  const filteredSensitive: string[] = [];

  for (const name of sensitive) {
    if (ignoredSet.has(name)) {
      overlaps.push(name);
    } else {
      filteredSensitive.push(name);
    }
  }

  return {
    sensitive: filteredSensitive,
    ignored,
    overlaps,
  };
}

/**
 * Detects whether cookie lists (sensitive or ignored) have changed between two settings versions.
 */
export function haveCookieListsChanged(prev: SettingsV2, next: SettingsV2): boolean {
  const prevSens = prev.sensitiveCookieNames ?? prev.alwaysSensitiveCookies ?? [];
  const nextSens = next.sensitiveCookieNames ?? next.alwaysSensitiveCookies ?? [];
  const prevIgn = prev.ignoredCookieNames ?? prev.alwaysIgnoreCookies ?? [];
  const nextIgn = next.ignoredCookieNames ?? next.alwaysIgnoreCookies ?? [];

  if (prevSens.length !== nextSens.length || prevIgn.length !== nextIgn.length) {
    return true;
  }
  const prevSensSet = new Set(prevSens);
  if (nextSens.some((s) => !prevSensSet.has(s))) return true;

  const prevIgnSet = new Set(prevIgn);
  if (nextIgn.some((s) => !prevIgnSet.has(s))) return true;

  return false;
}

/**
 * Clamps an integer value to [min, max]. Falls back to defaultValue if invalid.
 */
function clampNumber(val: unknown, min: number, max: number, defaultValue: number): number {
  if (typeof val !== 'number' || !Number.isFinite(val)) {
    if (typeof val === 'string') {
      const parsed = parseInt(val, 10);
      if (Number.isFinite(parsed)) return Math.max(min, Math.min(max, parsed));
    }
    return defaultValue;
  }
  return Math.max(min, Math.min(max, Math.round(val)));
}

/**
 * Sanitizes and validates a severity filter array.
 */
function sanitizeSeverityFilter(raw: unknown): Severity[] {
  if (!Array.isArray(raw)) return [...DEFAULT_SETTINGS.severityFilter];
  const filtered = raw.filter((s): s is Severity => typeof s === 'string' && VALID_SEVERITIES.has(s as Severity));
  return filtered.length > 0 ? Array.from(new Set(filtered)) : [...DEFAULT_SETTINGS.severityFilter];
}

// ---------------------------------------------------------------------------
// Migration logic (v1 → v2)
// ---------------------------------------------------------------------------

export class UnsupportedSchemaError extends Error {
  constructor(public readonly version: number) {
    super(`Unsupported settings schema version: ${version}`);
    this.name = 'UnsupportedSchemaError';
  }
}

/**
 * Idempotently migrates any raw/legacy settings object to canonical SettingsV2.
 * Preserves all valid existing v1 settings without dropping user preferences.
 * Throws UnsupportedSchemaError if given a future schema version (> 2).
 */
export function migrateSettings(raw: unknown): SettingsV2 {
  if (raw == null || typeof raw !== 'object') {
    return { ...DEFAULT_SETTINGS };
  }

  const obj = raw as Record<string, unknown>;

  // Check if raw is a future unsupported schema
  if (typeof obj.schemaVersion === 'number' && obj.schemaVersion > 2) {
    throw new UnsupportedSchemaError(obj.schemaVersion);
  }

  // Detect mode
  let monitoringMode: SettingsV2['monitoringMode'] = DEFAULT_SETTINGS.monitoringMode;
  if (typeof obj.monitoringMode === 'string' && VALID_MODES.has(obj.monitoringMode as SettingsV2['monitoringMode'])) {
    monitoringMode = obj.monitoringMode as SettingsV2['monitoringMode'];
  }

  // Detect severity filter
  const severityFilter = sanitizeSeverityFilter(obj.severityFilter);

  // Detect retention
  const retainHistoryDays = clampNumber(obj.retainHistoryDays, 0, 365, DEFAULT_SETTINGS.retainHistoryDays);
  const maxHistoryPerOrigin = clampNumber(obj.maxHistoryPerOrigin, 1, 50, DEFAULT_SETTINGS.maxHistoryPerOrigin);

  // Map cookie lists: prefer v2 names, fallback to legacy v1 names
  const rawSensitive = obj.sensitiveCookieNames ?? obj.alwaysSensitiveCookies;
  const rawIgnored = obj.ignoredCookieNames ?? obj.alwaysIgnoreCookies;

  const normalizedSensitive = normalizeCookieList(rawSensitive);
  const normalizedIgnored = normalizeCookieList(rawIgnored);
  const { sensitive, ignored } = resolveCookieOverlaps(normalizedSensitive, normalizedIgnored);

  // Map evaluation mode: prefer v2 evaluationMode, fallback to legacy isPro
  const evaluationMode = typeof obj.evaluationMode === 'boolean'
    ? obj.evaluationMode
    : typeof obj.isPro === 'boolean'
      ? obj.isPro
      : DEFAULT_SETTINGS.evaluationMode;

  // Preserve legacy allowedOrigins as a read-only hint if present
  let legacyAllowedOrigins: string[] | undefined;
  if (Array.isArray(obj.allowedOrigins) && obj.allowedOrigins.length > 0) {
    legacyAllowedOrigins = obj.allowedOrigins
      .filter((o): o is string => typeof o === 'string' && o.trim().length > 0)
      .map((o) => o.trim());
  } else if (Array.isArray(obj.legacyAllowedOrigins) && obj.legacyAllowedOrigins.length > 0) {
    legacyAllowedOrigins = obj.legacyAllowedOrigins
      .filter((o): o is string => typeof o === 'string' && o.trim().length > 0)
      .map((o) => o.trim());
  }

  const VALID_THEMES = new Set(['system', 'dark', 'light']);
  const VALID_DENSITIES = new Set(['comfortable', 'compact']);
  const VALID_MOTIONS = new Set(['system', 'always', 'never']);

  const theme: NonNullable<SettingsV2['theme']> =
    typeof obj.theme === 'string' && VALID_THEMES.has(obj.theme)
      ? (obj.theme as NonNullable<SettingsV2['theme']>)
      : 'system';

  const density: NonNullable<SettingsV2['density']> =
    typeof obj.density === 'string' && VALID_DENSITIES.has(obj.density)
      ? (obj.density as NonNullable<SettingsV2['density']>)
      : 'comfortable';

  const reducedMotion: NonNullable<SettingsV2['reducedMotion']> =
    typeof obj.reducedMotion === 'string' && VALID_MOTIONS.has(obj.reducedMotion)
      ? (obj.reducedMotion as NonNullable<SettingsV2['reducedMotion']>)
      : 'system';

  const result: SettingsV2 = {
    schemaVersion: 2,
    monitoringMode,
    severityFilter,
    retainHistoryDays,
    maxHistoryPerOrigin,
    sensitiveCookieNames: sensitive,
    ignoredCookieNames: ignored,
    evaluationMode,
    theme,
    density,
    reducedMotion,
  };

  if (legacyAllowedOrigins !== undefined && legacyAllowedOrigins.length > 0) {
    result.legacyAllowedOrigins = legacyAllowedOrigins;
  }

  return result;
}

// ---------------------------------------------------------------------------
// Transition Pipeline (WS1 1C)
// ---------------------------------------------------------------------------

export interface SettingsTransitionHooks {
  onRescoreTabs?: (previous: SettingsV2, next: SettingsV2) => Promise<void> | void;
  onModeChange?: (previousMode: SettingsV2['monitoringMode'], newMode: SettingsV2['monitoringMode']) => Promise<void> | void;
  onSettingsApplied?: (settings: SettingsV2) => Promise<void> | void;
}

export class SettingsTransitionPipeline {
  private lastAppliedSettings: SettingsV2 | null = null;
  private hooks: SettingsTransitionHooks = {};

  public registerHooks(hooks: SettingsTransitionHooks): void {
    this.hooks = { ...this.hooks, ...hooks };
  }

  public getLastAppliedSettings(): SettingsV2 | null {
    return this.lastAppliedSettings !== null ? { ...this.lastAppliedSettings } : null;
  }

  public setLastAppliedSettings(settings: SettingsV2 | null): void {
    this.lastAppliedSettings = settings !== null ? { ...settings } : null;
  }

  public areEqual(a: SettingsV2, b: SettingsV2): boolean {
    if (a.schemaVersion !== b.schemaVersion) return false;
    if (a.monitoringMode !== b.monitoringMode) return false;
    if (a.evaluationMode !== b.evaluationMode) return false;
    if (a.retainHistoryDays !== b.retainHistoryDays) return false;
    if (a.maxHistoryPerOrigin !== b.maxHistoryPerOrigin) return false;

    if (a.severityFilter.length !== b.severityFilter.length) return false;
    const aSev = new Set(a.severityFilter);
    if (b.severityFilter.some((s) => !aSev.has(s))) return false;

    if (a.sensitiveCookieNames.length !== b.sensitiveCookieNames.length) return false;
    const aSens = new Set(a.sensitiveCookieNames);
    if (b.sensitiveCookieNames.some((s) => !aSens.has(s))) return false;

    if (a.ignoredCookieNames.length !== b.ignoredCookieNames.length) return false;
    const aIgn = new Set(a.ignoredCookieNames);
    if (b.ignoredCookieNames.some((s) => !aIgn.has(s))) return false;

    if (a.theme !== b.theme) return false;
    if (a.density !== b.density) return false;
    if (a.reducedMotion !== b.reducedMotion) return false;

    return true;
  }

  public async transition(
    incoming: unknown,
    _source: 'storage' | 'message' = 'storage'
  ): Promise<SettingsV2> {
    // 1. Validation & Version Check:
    if (
      typeof incoming === 'object' &&
      incoming !== null &&
      typeof (incoming as Record<string, unknown>).schemaVersion === 'number' &&
      ((incoming as Record<string, unknown>).schemaVersion as number) > 2
    ) {
      throw new UnsupportedSchemaError((incoming as Record<string, unknown>).schemaVersion as number);
    }

    const validated = migrateSettings(incoming);

    // 2. Deduplication against lastAppliedSettings
    if (this.lastAppliedSettings !== null && this.areEqual(this.lastAppliedSettings, validated)) {
      return { ...this.lastAppliedSettings };
    }

    const previous = this.lastAppliedSettings ?? { ...DEFAULT_SETTINGS, monitoringMode: 'off' };

    // 3. Delta Detection
    const cookieListsChanged = haveCookieListsChanged(previous, validated);
    const modeChanged = previous.monitoringMode !== validated.monitoringMode;

    // 4. Update state atomically
    this.lastAppliedSettings = { ...validated };
    cachedSettings = { ...validated };

    // 5. Execution of Side Effects
    if (modeChanged && this.hooks.onModeChange) {
      await this.hooks.onModeChange(previous.monitoringMode, validated.monitoringMode);
    }

    if (cookieListsChanged && this.hooks.onRescoreTabs) {
      await this.hooks.onRescoreTabs(previous, validated);
    }

    if (this.hooks.onSettingsApplied) {
      await this.hooks.onSettingsApplied(validated);
    }

    // 6. Notify subscribers
    for (const cb of listeners) {
      try {
        cb(validated);
      } catch {
        // Ignore listener errors
      }
    }

    return { ...validated };
  }
}

export const settingsTransitionPipeline = new SettingsTransitionPipeline();

// ---------------------------------------------------------------------------
// Settings Service
// ---------------------------------------------------------------------------

let cachedSettings: SettingsV2 | null = null;
let hydrationPromise: Promise<SettingsV2> | null = null;
const listeners = new Set<(settings: SettingsV2) => void>();
let storageListenerRegistered = false;

function ensureStorageListener(): void {
  if (
    storageListenerRegistered ||
    typeof chrome === 'undefined' ||
    typeof chrome.storage === 'undefined' ||
    typeof chrome.storage.onChanged === 'undefined'
  ) {
    return;
  }
  chrome.storage.onChanged.addListener((changes, areaName) => {
    const change = changes[STORAGE_KEYS.SETTINGS];
    if (areaName === 'local' && change !== undefined) {
      const newRaw: unknown = change.newValue;
      void settingsTransitionPipeline.transition(newRaw, 'storage').catch(() => {
        // If unsupported future schema or invalid data is written, fail closed
        cachedSettings = { ...DEFAULT_SETTINGS, monitoringMode: 'off' };
      });
    }
  });
  storageListenerRegistered = true;
}

export const SettingsService = {
  /**
   * Reads settings from memory cache or chrome.storage.local.
   * Auto-migrates and writes back if legacy schema is detected.
   * Fails closed if storage read throws or future schema version is encountered.
   */
  async getSettings(): Promise<SettingsV2> {
    ensureStorageListener();
    if (cachedSettings !== null) {
      return { ...cachedSettings };
    }
    if (hydrationPromise !== null) {
      return hydrationPromise.then((s) => ({ ...s }));
    }

    if (
      typeof chrome === 'undefined' ||
      typeof chrome.storage === 'undefined' ||
      typeof chrome.storage.local === 'undefined'
    ) {
      cachedSettings = { ...DEFAULT_SETTINGS };
      settingsTransitionPipeline.setLastAppliedSettings(cachedSettings);
      return { ...cachedSettings };
    }

    hydrationPromise = (async (): Promise<SettingsV2> => {
      try {
        const data = await chrome.storage.local.get(STORAGE_KEYS.SETTINGS);
        const raw: unknown = data[STORAGE_KEYS.SETTINGS];

        if (
          typeof raw === 'object' &&
          raw !== null &&
          typeof (raw as Record<string, unknown>)['schemaVersion'] === 'number' &&
          ((raw as Record<string, unknown>)['schemaVersion'] as number) > 2
        ) {
          throw new UnsupportedSchemaError((raw as Record<string, unknown>)['schemaVersion'] as number);
        }

        const migrated = migrateSettings(raw);

        // If storage was missing schemaVersion 2, persist the migrated v2 record
        const hasSchemaV2 =
          typeof raw === 'object' &&
          raw !== null &&
          (raw as Record<string, unknown>)['schemaVersion'] === 2;
        if (!hasSchemaV2) {
          const opEpoch = getStorageResetEpoch();
          if (!isStorageEpochStale(opEpoch)) {
            await storageWriteBarrier.enter();
            if (!isStorageEpochStale(opEpoch)) {
              const writePromise = chrome.storage.local.set({ [STORAGE_KEYS.SETTINGS]: migrated });
              await storageWriteBarrier.track(writePromise);
            }
          }
        }

        cachedSettings = migrated;
        settingsTransitionPipeline.setLastAppliedSettings(migrated);
        return { ...migrated };
      } catch (err) {
        // Fail closed on storage read error or unsupported schema
        cachedSettings = { ...DEFAULT_SETTINGS, monitoringMode: 'off' };
        throw err;
      } finally {
        hydrationPromise = null;
      }
    })();

    return hydrationPromise.then((s) => ({ ...s }));
  },

  /**
   * Returns a promise that resolves to valid hydrated settings, failing closed to Off mode.
   */
  async whenReady(): Promise<SettingsV2> {
    if (cachedSettings !== null) {
      return { ...cachedSettings };
    }
    try {
      return await this.getSettings();
    } catch {
      return this.getCachedSettings();
    }
  },

  /**
   * Checks whether settings have finished initial storage hydration.
   */
  isReady(): boolean {
    if (cachedSettings !== null) {
      return true;
    }
    if (
      typeof chrome === 'undefined' ||
      typeof chrome.storage === 'undefined' ||
      typeof chrome.storage.local === 'undefined'
    ) {
      return true;
    }
    return false;
  },

  /**
   * Routes an incoming settings update through the single atomic transition pipeline.
   */
  async transition(incoming: unknown, source: 'storage' | 'message' = 'storage'): Promise<SettingsV2> {
    ensureStorageListener();
    return settingsTransitionPipeline.transition(incoming, source);
  },

  /**
   * Validates and applies a patch to current settings, writes to storage, and returns updated settings.
   */
  async updateSettings(patch: Partial<SettingsV2>, epoch?: number): Promise<SettingsV2> {
    ensureStorageListener();
    const opEpoch = epoch ?? getStorageResetEpoch();
    if (isStorageEpochStale(opEpoch)) {
      return this.getCachedSettings();
    }
    await storageWriteBarrier.enter();
    if (isStorageEpochStale(opEpoch)) {
      return this.getCachedSettings();
    }

    if (
      typeof chrome !== 'undefined' &&
      typeof chrome.storage !== 'undefined' &&
      typeof chrome.storage.local !== 'undefined'
    ) {
      const data = await chrome.storage.local.get(STORAGE_KEYS.SETTINGS);
      if (isStorageEpochStale(opEpoch)) {
        return this.getCachedSettings();
      }
      const raw: unknown = data[STORAGE_KEYS.SETTINGS];
      if (
        typeof raw === 'object' &&
        raw !== null &&
        typeof (raw as Record<string, unknown>)['schemaVersion'] === 'number' &&
        ((raw as Record<string, unknown>)['schemaVersion'] as number) > 2
      ) {
        throw new UnsupportedSchemaError((raw as Record<string, unknown>)['schemaVersion'] as number);
      }
    }

    const current = await this.whenReady();
    if (isStorageEpochStale(opEpoch)) {
      return this.getCachedSettings();
    }
    const merged = migrateSettings({ ...current, ...patch, schemaVersion: 2 });

    if (
      typeof chrome !== 'undefined' &&
      typeof chrome.storage !== 'undefined' &&
      typeof chrome.storage.local !== 'undefined'
    ) {
      if (isStorageEpochStale(opEpoch)) {
        return this.getCachedSettings();
      }
      const setPromise = chrome.storage.local.set({ [STORAGE_KEYS.SETTINGS]: merged });
      await storageWriteBarrier.track(setPromise);
    }

    if (isStorageEpochStale(opEpoch)) {
      return this.getCachedSettings();
    }

    return await settingsTransitionPipeline.transition(merged, 'storage');
  },

  /**
   * Subscribes to settings updates. Returns an unsubscribe function.
   */
  onSettingsChanged(cb: (settings: SettingsV2) => void): () => void {
    ensureStorageListener();
    listeners.add(cb);
    return () => {
      listeners.delete(cb);
    };
  },

  /**
   * Returns in-memory cached settings synchronously, or fail-closed (mode off) if not yet loaded.
   */
  getCachedSettings(): SettingsV2 {
    if (cachedSettings !== null) {
      return { ...cachedSettings };
    }
    if (
      typeof chrome === 'undefined' ||
      typeof chrome.storage === 'undefined' ||
      typeof chrome.storage.local === 'undefined'
    ) {
      return { ...DEFAULT_SETTINGS };
    }
    return { ...DEFAULT_SETTINGS, monitoringMode: 'off' };
  },

  /**
   * Resets the in-memory cache and pipeline (primarily for unit tests).
   */
  clearCache(): void {
    cachedSettings = null;
    hydrationPromise = null;
    settingsTransitionPipeline.setLastAppliedSettings(null);
  },
};
