/**
 * permissions.ts
 *
 * Single authority and synchronization layer for Chrome browser permissions.
 * Authoritative state is derived directly from chrome.permissions.getAll().
 * Handles host permission querying, broad grant detection, permission revocation,
 * and tab capture clearing with startup reconciliation.
 */

import type { TabState } from '../shared/types';
import type { ExtensionMessage } from '../shared/messaging';
import { SessionStorage } from '../shared/storage';
import { captureMap } from './capture';
import { tabStates } from './lifecycle';

// ---------------------------------------------------------------------------
// Patterns and Helpers
// ---------------------------------------------------------------------------

const BROAD_GRANT_PATTERNS = new Set([
  '<all_urls>',
  '*://*/*',
  '*://*',
  'http://*/*',
  'https://*/*',
  'http://*/',
  'https://*/',
]);

/**
 * Checks if a permission pattern represents a broad (all-urls) grant.
 */
export function isBroadGrant(pattern: string): boolean {
  if (!pattern) return false;
  const trimmed = pattern.trim();
  if (BROAD_GRANT_PATTERNS.has(trimmed)) return true;
  return trimmed.includes('://*/*') || trimmed.includes('://*/');
}

/**
 * Checks whether a collection of permission patterns satisfies complete "All-sites" coverage
 * across all supported web schemes (http://* and https://*, or <all_urls> / *://*).
 */
export function hasAllSitesCoverage(patterns: readonly string[]): boolean {
  if (patterns.length === 0) return false;
  let hasHttp = false;
  let hasHttps = false;

  for (const raw of patterns) {
    if (!raw) continue;
    const trimmed = raw.trim();
    if (trimmed === '<all_urls>' || trimmed === '*://*/*' || trimmed === '*://*') {
      return true;
    }
    if (
      trimmed === 'http://*/*' ||
      trimmed === 'http://*' ||
      trimmed === 'http://*/'
    ) {
      hasHttp = true;
    }
    if (
      trimmed === 'https://*/*' ||
      trimmed === 'https://*' ||
      trimmed === 'https://*/'
    ) {
      hasHttps = true;
    }
  }

  return hasHttp && hasHttps;
}

/**
 * Normalizes a Chrome permission origin pattern into an origin string (scheme + host[:port]).
 * E.g., "https://example.com/*" -> "https://example.com"
 */
export function normalizePermissionOrigin(pattern: string): string {
  if (!pattern) return '';
  const trimmed = pattern.trim();
  if (isBroadGrant(trimmed)) return trimmed;

  try {
    const withoutWildcard = trimmed.replace(/\/\*.*$/, '');
    const url = new URL(withoutWildcard.endsWith('/') ? withoutWildcard : `${withoutWildcard}/`);
    return url.origin;
  } catch {
    return trimmed.replace(/\/\*.*$/, '').replace(/\/+$/, '');
  }
}

/**
 * Generates a valid Chrome match pattern from an origin or URL string.
 * Chrome match patterns cannot specify ports.
 * E.g., "http://127.0.0.1:3464" -> "http://127.0.0.1/*"
 *       "https://example.com" -> "https://example.com/*"
 */
export function patternFromOrigin(originOrUrl: string): string {
  if (!originOrUrl) return '';
  const trimmed = originOrUrl.trim();
  if (isBroadGrant(trimmed)) return trimmed;

  try {
    const u = new URL(trimmed.endsWith('/') ? trimmed : `${trimmed}/`);
    return `${u.protocol}//${u.hostname}/*`;
  } catch {
    const cleaned = trimmed.replace(/\/\*.*$/, '').replace(/\/+$/, '');
    return `${cleaned}/*`;
  }
}

/**
 * Checks whether an origin is permitted by a list of permission patterns.
 */
export function isOriginPermitted(origin: string, grantedPatterns: readonly string[]): boolean {
  if (!origin) return false;
  const normOrigin = normalizePermissionOrigin(origin);
  let withoutPort = '';
  try {
    const u = new URL(origin.endsWith('/') ? origin : `${origin}/`);
    withoutPort = `${u.protocol}//${u.hostname}`;
  } catch {
    // ignore invalid URL
  }

  for (const pattern of grantedPatterns) {
    if (isBroadGrant(pattern)) return true;
    const normPattern = normalizePermissionOrigin(pattern);
    if (normPattern === normOrigin) return true;
    if (withoutPort.length > 0 && normPattern === withoutPort) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Authoritative Permission Queries (Single Source of Truth)
// ---------------------------------------------------------------------------

export const PermissionsService = {
  /**
   * Queries chrome.permissions.getAll() and returns true if any broad grant exists.
   */
  async isBroadGrantPresent(): Promise<boolean> {
    if (
      typeof chrome === 'undefined' ||
      typeof chrome.permissions === 'undefined' ||
      typeof chrome.permissions.getAll === 'undefined'
    ) {
      return false;
    }
    const perms = await chrome.permissions.getAll();
    const origins = perms.origins ?? [];
    return origins.some((o) => isBroadGrant(o));
  },

  /**
   * Authoritative query: returns true if the granted permissions satisfy complete
   * All-sites coverage across all supported web schemes.
   */
  async hasCompleteBroadGrant(): Promise<boolean> {
    if (
      typeof chrome === 'undefined' ||
      typeof chrome.permissions === 'undefined' ||
      typeof chrome.permissions.getAll === 'undefined'
    ) {
      return false;
    }
    const perms = await chrome.permissions.getAll();
    const origins = perms.origins ?? [];
    return hasAllSitesCoverage(origins);
  },

  /**
   * Authoritative query: returns all explicitly granted origins (excluding broad patterns).
   * Normalizes patterns to canonical origins (e.g., https://example.com).
   */
  async getAllGrantedOrigins(): Promise<string[]> {
    if (
      typeof chrome === 'undefined' ||
      typeof chrome.permissions === 'undefined' ||
      typeof chrome.permissions.getAll === 'undefined'
    ) {
      return [];
    }
    const perms = await chrome.permissions.getAll();
    const origins = perms.origins ?? [];
    const set = new Set<string>();

    for (const pattern of origins) {
      if (!isBroadGrant(pattern)) {
        const norm = normalizePermissionOrigin(pattern);
        if (norm.length > 0) {
          set.add(norm);
        }
      }
    }

    return Array.from(set);
  },

  /**
   * Checks whether the browser currently has permission for the specified origin.
   */
  async hasPermissionForOrigin(origin: string): Promise<boolean> {
    if (!origin || typeof chrome === 'undefined' || typeof chrome.permissions === 'undefined') {
      return false;
    }
    const pattern = patternFromOrigin(origin);
    const directCheck = await new Promise<boolean>((resolve) => {
      chrome.permissions.contains({ origins: [pattern] }, (result) => {
        if (chrome.runtime?.lastError) {
          resolve(false);
        } else {
          resolve(Boolean(result));
        }
      });
    });
    if (directCheck) return true;

    const norm = normalizePermissionOrigin(origin);
    if (`${norm}/*` !== pattern) {
      return new Promise<boolean>((resolve) => {
        chrome.permissions.contains({ origins: [`${norm}/*`] }, (result) => {
          if (chrome.runtime?.lastError) {
            resolve(false);
          } else {
            resolve(Boolean(result));
          }
        });
      });
    }
    return false;
  },

  /**
   * Revokes host permission for a specific origin.
   */
  async removeOriginPermission(origin: string): Promise<boolean> {
    if (!origin || typeof chrome === 'undefined' || typeof chrome.permissions === 'undefined') {
      return false;
    }
    const pattern = patternFromOrigin(origin);
    const directRemoved = await new Promise<boolean>((resolve) => {
      chrome.permissions.remove({ origins: [pattern] }, (result) => {
        if (chrome.runtime?.lastError) {
          resolve(false);
        } else {
          resolve(Boolean(result));
        }
      });
    });
    if (directRemoved) return true;

    const norm = normalizePermissionOrigin(origin);
    if (`${norm}/*` !== pattern) {
      return new Promise<boolean>((resolve) => {
        chrome.permissions.remove({ origins: [`${norm}/*`] }, (result) => {
          if (chrome.runtime?.lastError) {
            resolve(false);
          } else {
            resolve(Boolean(result));
          }
        });
      });
    }
    return false;
  },

  /**
   * Identifies all broad permission patterns currently granted in the browser,
   * requests removal from the browser, and verifies that no broad grants remain.
   * Returns true only if all broad patterns were successfully removed.
   */
  async removeAllBroadGrants(): Promise<boolean> {
    if (
      typeof chrome === 'undefined' ||
      typeof chrome.permissions === 'undefined' ||
      typeof chrome.permissions.getAll === 'undefined' ||
      typeof chrome.permissions.remove === 'undefined'
    ) {
      return false;
    }
    const perms = await chrome.permissions.getAll();
    const origins = perms.origins ?? [];
    const broadOrigins = origins.filter((o) => isBroadGrant(o));

    if (broadOrigins.length === 0) {
      return true; // Already no broad grants
    }

    const removed = await new Promise<boolean>((resolve) => {
      chrome.permissions.remove({ origins: broadOrigins }, (result) => {
        resolve(Boolean(result));
      });
    });

    if (!removed) {
      return false;
    }

    // Verify broad grants are truthfully absent
    const remainingPerms = await chrome.permissions.getAll();
    const remainingBroad = (remainingPerms.origins ?? []).filter((o) => isBroadGrant(o));
    return remainingBroad.length === 0;
  },

  /**
   * Revokes all optional host permissions granted to the extension.
   */
  async removeAllOptionalPermissions(): Promise<boolean> {
    if (typeof chrome === 'undefined' || typeof chrome.permissions === 'undefined') {
      return false;
    }
    const perms = await chrome.permissions.getAll();
    const origins = perms.origins ?? [];
    if (origins.length === 0) return true;

    return new Promise<boolean>((resolve) => {
      chrome.permissions.remove({ origins }, resolve);
    });
  },
};

// ---------------------------------------------------------------------------
// Revocation & Cleanup (clearTabCapture)
// ---------------------------------------------------------------------------

export interface ClearTabOptions {
  tabStates?: Map<number, TabState>;
  sessionStorage?: { removeTabState: (tabId: number) => Promise<void> };
  captureMap?: Map<string, { tabId: number }>;
  pendingServiceWorkerReports?: Map<number, unknown>;
  pendingMetaCspReports?: Set<number>;
  setBadge?: (tabId: number, text: string) => void;
  broadcast?: (tabId: number, msg: ExtensionMessage) => void;
}

/**
 * Idempotently clears all captured state, pending receipts, badges, and session storage
 * for a tab whose origin permission was revoked or reset.
 */
export async function clearTabCapture(
  tabId: number,
  options?: ClearTabOptions,
): Promise<void> {
  const targetTabStates = options?.tabStates ?? tabStates;
  const targetSessionStorage = options?.sessionStorage ?? SessionStorage;
  const targetCaptureMap = options?.captureMap ?? captureMap;

  // 1. Evict tab from in-memory state
  targetTabStates.delete(tabId);

  // 2. Remove persisted session state
  try {
    await targetSessionStorage.removeTabState(tabId);
  } catch {
    // Ignore storage deletion errors
  }

  // 3. Clear in-flight captures for this tab
  for (const [requestId, partial] of targetCaptureMap.entries()) {
    if (partial.tabId === tabId) {
      targetCaptureMap.delete(requestId);
    }
  }

  // 4. Clear pending page-signal receipts
  options?.pendingServiceWorkerReports?.delete(tabId);
  options?.pendingMetaCspReports?.delete(tabId);

  // 5. Clear action badge
  if (options?.setBadge !== undefined) {
    options.setBadge(tabId, '');
  } else if (typeof chrome !== 'undefined' && typeof chrome.action !== 'undefined') {
    void chrome.action.setBadgeText({ tabId, text: '' }).catch(() => undefined);
  }

  // 6. Broadcast empty state to open ports
  if (options?.broadcast !== undefined) {
    options.broadcast(tabId, { type: 'STATE_RESPONSE', state: null });
  }
}

/**
 * Handles permission revocation when chrome.permissions.onRemoved fires.
 * Identifies tabs whose origin permission was revoked and clears their capture.
 * Preserves tabs whose origin remains permitted even after a broad grant is removed.
 */
export async function reconcilePermissionsOnRemoved(
  _removedOrigins: readonly string[],
  options?: ClearTabOptions & {
    getActiveOrigins?: () => Promise<string[]>;
    isBroadGrantActive?: () => Promise<boolean>;
  },
): Promise<number[]> {
  const clearedTabIds: number[] = [];

  const targetTabStates = options?.tabStates ?? tabStates;
  const isBroadActive = options?.isBroadGrantActive !== undefined
    ? await options.isBroadGrantActive()
    : await PermissionsService.isBroadGrantPresent();

  // If a broad grant is still active, all origins are still permitted
  if (isBroadActive) {
    return clearedTabIds;
  }

  const activeOrigins = options?.getActiveOrigins !== undefined
    ? await options.getActiveOrigins()
    : await PermissionsService.getAllGrantedOrigins();

  const activeOriginSet = new Set(activeOrigins.map(normalizePermissionOrigin));

  for (const [tabId, state] of Array.from(targetTabStates.entries())) {
    const tabOrigin = normalizePermissionOrigin(state.origin);
    let tabOriginWithoutPort = '';
    try {
      const u = new URL(state.origin.endsWith('/') ? state.origin : `${state.origin}/`);
      tabOriginWithoutPort = `${u.protocol}//${u.hostname}`;
    } catch {
      // ignore invalid URL
    }
    const stillPermitted =
      activeOriginSet.has(tabOrigin) ||
      (tabOriginWithoutPort.length > 0 && activeOriginSet.has(tabOriginWithoutPort));

    if (!stillPermitted) {
      await clearTabCapture(tabId, options);
      clearedTabIds.push(tabId);
    }
  }

  return clearedTabIds;
}

/**
 * Service worker startup reconciliation: inspects all hydrated tabs and evicts
 * any tabs whose origin permission was revoked while the SW was inactive.
 */
export async function reconcilePermissionsOnStartup(
  options?: ClearTabOptions & {
    getActiveOrigins?: () => Promise<string[]>;
    isBroadGrantActive?: () => Promise<boolean>;
  },
): Promise<number[]> {
  const isBroadActive = options?.isBroadGrantActive !== undefined
    ? await options.isBroadGrantActive()
    : await PermissionsService.isBroadGrantPresent();

  const activeOrigins = options?.getActiveOrigins !== undefined
    ? await options.getActiveOrigins()
    : await PermissionsService.getAllGrantedOrigins();

  const activeOriginSet = new Set(activeOrigins.map(normalizePermissionOrigin));
  const targetTabStates = options?.tabStates ?? tabStates;
  const clearedTabIds: number[] = [];

  for (const [tabId, state] of Array.from(targetTabStates.entries())) {
    const tabOrigin = normalizePermissionOrigin(state.origin);
    let tabOriginWithoutPort = '';
    try {
      const u = new URL(state.origin.endsWith('/') ? state.origin : `${state.origin}/`);
      tabOriginWithoutPort = `${u.protocol}//${u.hostname}`;
    } catch {
      // ignore invalid URL
    }
    const hasPermission =
      isBroadActive ||
      activeOriginSet.has(tabOrigin) ||
      (tabOriginWithoutPort.length > 0 && activeOriginSet.has(tabOriginWithoutPort));

    if (!hasPermission) {
      await clearTabCapture(tabId, options);
      clearedTabIds.push(tabId);
    }
  }

  return clearedTabIds;
}
