/**
 * capture-policy.ts
 *
 * Single authoritative fail-closed capture policy across navigation, API,
 * and page-signal paths.
 */

import { isModeCaptureAllowed, isRestrictedUrl } from '../shared/gating';
import { originFromUrl } from '../rules/utils';
import { SettingsService } from '../shared/settings';
import { PermissionsService } from './permissions';
import type { SettingsV2 } from '../shared/types';

export interface CapturePolicyResult {
  allowed: boolean;
  reason?: 'off' | 'broad-access-conflict' | 'restricted-url' | 'not-permitted' | 'invalid-url' | 'settings-error';
}

export const CapturePolicy = {
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

    const broadActive = await PermissionsService.isBroadGrantPresent();
    const gate = isModeCaptureAllowed(url, settings, broadActive);
    if (!gate.allowed) {
      if (gate.reason === 'off' || gate.reason === 'broad-access-conflict' || gate.reason === 'restricted-url') {
        return { allowed: false, reason: gate.reason };
      }
      return { allowed: false };
    }

    // In all-sites mode with broad grant active, origin is permitted
    if (broadActive) {
      return { allowed: true };
    }

    // In per-site mode, verify specific origin permission
    const permitted = await PermissionsService.hasPermissionForOrigin(origin);
    if (!permitted) {
      return { allowed: false, reason: 'not-permitted' };
    }

    return { allowed: true };
  },

  /**
   * Helper returning boolean allowed status.
   */
  async isAllowed(url: string): Promise<boolean> {
    const res = await this.evaluate(url);
    return res.allowed;
  },
};
