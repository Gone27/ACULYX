/**
 * gating.ts
 *
 * Pure capture gating decision logic and monitoring mode enforcement.
 * Enforces the behavior contract defined in docs/BEHAVIOR_CONTRACT.md:
 * - per-site, all-sites, and off modes
 * - broad grant conflict detection
 * - restricted scheme and store URL prevention
 */

import type { SettingsV2 } from './types';

export interface CaptureGateResult {
  allowed: boolean;
  reason: 'ok' | 'off' | 'broad-access-conflict' | 'restricted-url';
}

const RESTRICTED_SCHEME_PREFIXES = [
  'chrome://',
  'chrome-extension://',
  'edge://',
  'devtools://',
  'about:',
  'data:',
  'blob:',
  'view-source:',
] as const;

/**
 * Checks whether a URL is restricted from inspection (browser internals, extensions, web stores).
 */
export function isRestrictedUrl(url: string, options?: { fileAccessAllowed?: boolean }): boolean {
  if (!url || url.trim().length === 0) return true;
  const lower = url.trim().toLowerCase();

  for (const prefix of RESTRICTED_SCHEME_PREFIXES) {
    if (lower.startsWith(prefix)) return true;
  }

  if (lower.startsWith('file://')) {
    return options?.fileAccessAllowed !== true;
  }

  try {
    const parsed = new URL(lower);
    const host = parsed.hostname;
    if (host === 'chromewebstore.google.com' || host === 'addons.mozilla.org') {
      return true;
    }
    if (host === 'chrome.google.com' && parsed.pathname.startsWith('/webstore')) {
      return true;
    }
  } catch {
    // If URL cannot be parsed and doesn't match standard web schemes, treat as restricted
    if (!lower.startsWith('http://') && !lower.startsWith('https://')) {
      return true;
    }
  }

  return false;
}

/**
 * Pure synchronous function to evaluate whether traffic for a URL qualifies for capture.
 *
 * Invariant: Evaluation mode or presentation settings NEVER affect this decision.
 */
export function isModeCaptureAllowed(
  url: string,
  settings: SettingsV2,
  broadGrantPresent: boolean,
  options?: { fileAccessAllowed?: boolean },
): CaptureGateResult {
  // 1. URL validity and restricted scheme check
  if (isRestrictedUrl(url, options)) {
    return { allowed: false, reason: 'restricted-url' };
  }

  // 2. Off mode: completely inactive
  if (settings.monitoringMode === 'off') {
    return { allowed: false, reason: 'off' };
  }

  // 3. Broad grant conflict: configured for per-site but broad access is active in browser
  if (settings.monitoringMode === 'per-site' && broadGrantPresent) {
    return { allowed: false, reason: 'broad-access-conflict' };
  }

  // 4. Allowed for capture
  return { allowed: true, reason: 'ok' };
}
