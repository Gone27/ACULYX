/**
 * settings.ts
 *
 * Single settings service and authoritative read/write path for extension settings.
 * Enforces schema v2 validation, idempotent migration from legacy v1 shapes,
 * in-memory caching with storage.onChanged invalidation, and change subscriptions.
 */

import { DEFAULT_SETTINGS, STORAGE_KEYS } from './constants';
import type { Severity, SettingsV2 } from './types';

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

/**
 * Idempotently migrates any raw/legacy settings object to canonical SettingsV2.
 * Preserves all valid existing v1 settings without dropping user preferences.
 */
export function migrateSettings(raw: unknown): SettingsV2 {
  if (raw == null || typeof raw !== 'object') {
    return { ...DEFAULT_SETTINGS };
  }

  const obj = raw as Record<string, unknown>;

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

  const result: SettingsV2 = {
    schemaVersion: 2,
    monitoringMode,
    severityFilter,
    retainHistoryDays,
    maxHistoryPerOrigin,
    sensitiveCookieNames: sensitive,
    ignoredCookieNames: ignored,
    evaluationMode,
  };

  if (legacyAllowedOrigins !== undefined && legacyAllowedOrigins.length > 0) {
    result.legacyAllowedOrigins = legacyAllowedOrigins;
  }

  return result;
}

// ---------------------------------------------------------------------------
// Settings Service
// ---------------------------------------------------------------------------

let cachedSettings: SettingsV2 | null = null;
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
      cachedSettings = migrateSettings(newRaw);
      for (const cb of listeners) {
        try {
          cb(cachedSettings);
        } catch {
          // Ignore listener errors
        }
      }
    }
  });
  storageListenerRegistered = true;
}

export const SettingsService = {
  /**
   * Reads settings from memory cache or chrome.storage.local.
   * Auto-migrates and writes back if legacy schema is detected.
   */
  async getSettings(): Promise<SettingsV2> {
    ensureStorageListener();
    if (cachedSettings !== null) {
      return { ...cachedSettings };
    }

    if (
      typeof chrome === 'undefined' ||
      typeof chrome.storage === 'undefined' ||
      typeof chrome.storage.local === 'undefined'
    ) {
      cachedSettings = { ...DEFAULT_SETTINGS };
      return { ...cachedSettings };
    }

    const data = await chrome.storage.local.get(STORAGE_KEYS.SETTINGS);
    const raw: unknown = data[STORAGE_KEYS.SETTINGS];
    const migrated = migrateSettings(raw);

    // If storage was missing schemaVersion 2, persist the migrated v2 record
    const hasSchemaV2 = typeof raw === 'object' && raw !== null && (raw as Record<string, unknown>)['schemaVersion'] === 2;
    if (!hasSchemaV2) {
      await chrome.storage.local.set({ [STORAGE_KEYS.SETTINGS]: migrated });
    }

    cachedSettings = migrated;
    return { ...migrated };
  },

  /**
   * Validates and applies a patch to current settings, writes to storage, and returns updated settings.
   */
  async updateSettings(patch: Partial<SettingsV2>): Promise<SettingsV2> {
    ensureStorageListener();
    const current = await this.getSettings();
    const merged = migrateSettings({ ...current, ...patch, schemaVersion: 2 });

    if (
      typeof chrome !== 'undefined' &&
      typeof chrome.storage !== 'undefined' &&
      typeof chrome.storage.local !== 'undefined'
    ) {
      await chrome.storage.local.set({ [STORAGE_KEYS.SETTINGS]: merged });
    }

    cachedSettings = merged;
    for (const cb of listeners) {
      try {
        cb(merged);
      } catch {
        // Ignore listener errors
      }
    }

    return { ...merged };
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
   * Resets the in-memory cache (primarily for unit tests).
   */
  clearCache(): void {
    cachedSettings = null;
  },
};
