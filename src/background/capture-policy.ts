/**
 * capture-policy.ts
 *
 * Single authoritative fail-closed capture policy across navigation, API,
 * and page-signal paths.
 */

import { isRestrictedUrl } from '../shared/gating';
import { originFromUrl } from '../rules/utils';
import { SettingsService } from '../shared/settings';
import { PermissionsService, normalizePermissionOrigin } from './permissions';
import type { SettingsV2 } from '../shared/types';

export interface CapturePolicySnapshot {
  readonly ready: boolean;
  readonly revision: number;
  readonly mode: SettingsV2['monitoringMode'];
  readonly broadGrantActive: boolean;
  readonly grantedOrigins: Set<string>;
}

export interface CapturePolicyResult {
  allowed: boolean;
  reason?:
    | 'off'
    | 'broad-access-conflict'
    | 'restricted-url'
    | 'not-permitted'
    | 'invalid-url'
    | 'settings-error'
    | 'all-sites-missing-grant';
  monitoringState?: string;
}

let currentSnapshot: CapturePolicySnapshot = {
  ready: false,
  revision: 0,
  mode: 'off',
  broadGrantActive: false,
  grantedOrigins: new Set(),
};

let currentRevision = 0;
let latestCompletedRevision = 0;

/**
 * Pure synchronous evaluation of whether traffic for a URL qualifies for capture
 * at the earliest listener boundary, using an immutable policy snapshot.
 */
export function isCaptureAllowedAtBoundary(
  url: string,
  snapshot: CapturePolicySnapshot,
): boolean {
  if (!snapshot.ready) return false;
  if (!url || isRestrictedUrl(url)) return false;
  if (snapshot.mode === 'off') return false;

  if (snapshot.mode === 'per-site') {
    if (snapshot.broadGrantActive) return false; // Broad conflict
    const origin = originFromUrl(url);
    if (origin === null) return false;
    const normalized = normalizePermissionOrigin(origin);
    if (snapshot.grantedOrigins.has(normalized)) return true;
    try {
      const u = new URL(url);
      const withoutPort = `${u.protocol}//${u.hostname}`;
      if (snapshot.grantedOrigins.has(withoutPort)) return true;
    } catch {
      // ignore invalid URL
    }
    return false;
  }

  if (snapshot.mode === 'all-sites') {
    return snapshot.broadGrantActive; // Fail-closed if broad grant missing
  }

  return false;
}

/**
 * Hydrates the snapshot from SettingsService + PermissionsService.
 * Uses monotonic revision tracking so older async responses cannot overwrite newer state.
 */
export async function refreshCapturePolicySnapshot(): Promise<CapturePolicySnapshot> {
  const revision = ++currentRevision;
  try {
    const settings = await SettingsService.getSettings();
    const broadActive = await PermissionsService.isBroadGrantPresent();
    const hasAllSites = await PermissionsService.hasCompleteBroadGrant();
    const grantedOriginsList = await PermissionsService.getAllGrantedOrigins();

    if (revision >= latestCompletedRevision) {
      latestCompletedRevision = revision;
      const broadGrantActive =
        settings.monitoringMode === 'all-sites'
          ? hasAllSites
          : settings.monitoringMode === 'per-site'
            ? broadActive
            : false;

      currentSnapshot = {
        ready: true,
        revision,
        mode: settings.monitoringMode,
        broadGrantActive,
        grantedOrigins: new Set(grantedOriginsList.map(normalizePermissionOrigin)),
      };
    }
  } catch {
    if (revision >= latestCompletedRevision) {
      latestCompletedRevision = revision;
      currentSnapshot = {
        ready: false,
        revision,
        mode: 'off',
        broadGrantActive: false,
        grantedOrigins: new Set(),
      };
    }
  }
  return currentSnapshot;
}

// Auto-subscribe to settings updates
SettingsService.onSettingsChanged(() => {
  void refreshCapturePolicySnapshot();
});

// Auto-subscribe to browser permission lifecycle events if available
if (typeof chrome !== 'undefined' && typeof chrome.permissions !== 'undefined') {
  try {
    chrome.permissions.onAdded?.addListener?.(() => {
      void refreshCapturePolicySnapshot();
    });
    chrome.permissions.onRemoved?.addListener?.(() => {
      void refreshCapturePolicySnapshot();
    });
  } catch {
    // Non-extension test environments
  }
}

export const CapturePolicy = {
  /**
   * Returns current synchronous snapshot.
   */
  getSnapshot(): CapturePolicySnapshot {
    return currentSnapshot;
  },

  /**
   * Evaluates boundary allowance using current snapshot or passed snapshot.
   */
  isCaptureAllowedAtBoundary(url: string, snapshot?: CapturePolicySnapshot): boolean {
    return isCaptureAllowedAtBoundary(url, snapshot ?? currentSnapshot);
  },

  /**
   * Sets snapshot for testing purposes.
   */
  setSnapshotForTesting(snapshot: CapturePolicySnapshot): void {
    currentSnapshot = snapshot;
  },

  /**
   * Resets snapshot to initial unhydrated state (for tests).
   */
  resetSnapshotForTesting(): void {
    currentSnapshot = {
      ready: false,
      revision: 0,
      mode: 'off',
      broadGrantActive: false,
      grantedOrigins: new Set(),
    };
    currentRevision = 0;
    latestCompletedRevision = 0;
  },

  /**
   * Triggers an idempotent snapshot refresh.
   */
  async refreshSnapshot(): Promise<CapturePolicySnapshot> {
    return refreshCapturePolicySnapshot();
  },

  /**
   * Returns truthful human-readable monitoring state.
   */
  async getMonitoringState(): Promise<string> {
    let settings: SettingsV2;
    try {
      settings = await SettingsService.getSettings();
    } catch {
      return 'Error loading settings';
    }

    if (settings.monitoringMode === 'off') {
      return 'Off';
    }

    if (settings.monitoringMode === 'all-sites') {
      const hasAllSites = await PermissionsService.hasCompleteBroadGrant();
      if (!hasAllSites) {
        return 'Paused — All-sites permission missing';
      }
      return 'Active — All sites';
    }

    if (settings.monitoringMode === 'per-site') {
      const broadActive = await PermissionsService.isBroadGrantPresent();
      if (broadActive) {
        return 'Paused — Broad access conflict';
      }
      return 'Active — Per-site';
    }

    return 'Unknown';
  },

  /**
   * Authoritative fail-closed evaluation of whether capture is permitted for a URL.
   * Awaits settings hydration and evaluates mode, broad grants, and origin permissions.
   */
  async evaluate(url: string): Promise<CapturePolicyResult> {
    if (url.length === 0 || isRestrictedUrl(url)) {
      return { allowed: false, reason: 'restricted-url' };
    }

    const origin = originFromUrl(url);
    if (origin === null || origin.length === 0) {
      return { allowed: false, reason: 'invalid-url' };
    }

    let settings: SettingsV2;
    try {
      settings = await SettingsService.getSettings();
    } catch {
      // Fail closed on any storage read error or unsupported schema
      return { allowed: false, reason: 'settings-error' };
    }

    if (settings.monitoringMode === 'off') {
      return { allowed: false, reason: 'off' };
    }

    if (settings.monitoringMode === 'all-sites') {
      const hasAllSites = await PermissionsService.hasCompleteBroadGrant();
      if (!hasAllSites) {
        return {
          allowed: false,
          reason: 'all-sites-missing-grant',
          monitoringState: 'Paused — All-sites permission missing',
        };
      }
      return { allowed: true };
    }

    if (settings.monitoringMode === 'per-site') {
      const broadActive = await PermissionsService.isBroadGrantPresent();
      if (broadActive) {
        return { allowed: false, reason: 'broad-access-conflict' };
      }

      const permitted = await PermissionsService.hasPermissionForOrigin(origin);
      if (!permitted) {
        return { allowed: false, reason: 'not-permitted' };
      }

      return { allowed: true };
    }

    return { allowed: false };
  },

  /**
   * Helper returning boolean allowed status.
   */
  async isAllowed(url: string): Promise<boolean> {
    const res = await this.evaluate(url);
    return res.allowed;
  },
};
