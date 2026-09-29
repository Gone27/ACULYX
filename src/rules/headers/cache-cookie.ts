/**
 * Cache-Control + Cookie Rule.
 *
 * Rules:
 *   CACHE-001 (medium) — a response that sets a cookie lacks Cache-Control: no-store,
 *                        meaning sensitive cookie data could be stored in shared caches.
 *
 * This rule only fires when at least one Set-Cookie header is present in the response.
 */

import type { Finding, Hop } from '../../shared/types';
import { sanitizeEvidence, isSensitiveCookie } from '../utils';

const REFERENCE =
  'https://owasp.org/www-project-secure-headers/#cache-control';

const CACHE_CONTROL_HEADER = 'cache-control';

/**
 * Check that responses setting sensitive session/auth cookies include
 * Cache-Control: no-store.
 *
 * Responses setting purely non-sensitive cookies (consent, theme, language,
 * client-side analytics) are intentionally exempt so as not to penalize
 * standard Back-Forward Cache (bfcache) optimizations.
 *
 * @param finalHop - The last hop in the redirect chain.
 * @returns An array of zero or one finding.
 */
export function checkCacheCookie(
  finalHop: Hop,
  alwaysSensitive: string[] = [],
  alwaysIgnore: string[] = []
): Finding[] {
  // Extract all Set-Cookie header values.
  const setCookieHeaders = finalHop.rawHeaders
    .filter((h) => h.name.toLowerCase() === 'set-cookie')
    .map((h) => h.value);

  if (setCookieHeaders.length === 0) {
    return [];
  }

  // Check if any cookie being set is sensitive (auth/session name or HttpOnly flag).
  const sensitiveCookies = setCookieHeaders.filter((headerVal) => {
    const name = headerVal.split('=')[0]?.trim() ?? '';
    const hasHttpOnly = /;\s*httponly/i.test(headerVal);
    return hasHttpOnly || isSensitiveCookie(name, alwaysSensitive, alwaysIgnore).isSensitive;
  });

  // Exemption: If only harmless tracking/preference cookies are set, skip no-store requirement.
  if (sensitiveCookies.length === 0) {
    return [];
  }

  const cacheControlValue = finalHop.headers[CACHE_CONTROL_HEADER];

  // Absent header — no cache directive at all on a response setting sensitive cookies.
  if (cacheControlValue === undefined) {
    return [
      {
        ruleId: 'CACHE-001',
        category: 'header',
        severity: 'medium',
        title: 'Cache-Control: no-store missing on a response that sets sensitive cookies',
        impact:
          'Responses setting authentication cookies may be stored by intermediate web caches or proxy servers, exposing user session tokens to unauthorized parties.',
        evidence: sanitizeEvidence('(header absent)'),
        recommendation:
          'Add "Cache-Control: no-store" to responses that set authentication or session cookies.',
        reference: REFERENCE,
      },
    ];
  }

  const normalised = cacheControlValue.toLowerCase();

  // Full compliance: no-store present.
  if (normalised.includes('no-store')) {
    return [];
  }

  // Mitigated: 'private' or 'no-cache' prevents intermediate proxies/CDNs from caching.
  if (normalised.includes('private') || normalised.includes('no-cache')) {
    return [
      {
        ruleId: 'CACHE-001',
        category: 'header',
        severity: 'info',
        title: 'Cache-Control allows local caching for response with sensitive cookies (mitigated by private/no-cache)',
        impact:
          'Intermediate proxy/CDN caching is prevented by "private", but local browser storage persists the response, which could be exposed on shared kiosk computers.',
        evidence: sanitizeEvidence(cacheControlValue),
        recommendation:
          'Shared CDN caching is prevented by "private", but consider "no-store" if shared/public computers are in scope.',
        reference: REFERENCE,
      },
    ];
  }

  // Header present but public or lacking non-caching directives.
  return [
    {
      ruleId: 'CACHE-001',
      category: 'header',
      severity: 'medium',
      title: 'Cache-Control: no-store missing on a response that sets sensitive cookies',
      impact:
        'Sensitive authentication tokens and responses can be cached by shared CDN or proxy servers, allowing other users to retrieve session data.',
      evidence: sanitizeEvidence(cacheControlValue),
      recommendation:
        'Add "Cache-Control: no-store" to responses setting sensitive session cookies.',
      reference: REFERENCE,
    },
  ];
}

