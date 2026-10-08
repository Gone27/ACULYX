/** Cache-Control + Cookie Rule with Bounded Precision. */

import type { Finding, Hop } from '../../shared/types';
import { sanitizeEvidence, isSensitiveCookie } from '../utils';

const REFERENCE = 'https://owasp.org/www-project-secure-headers/#cache-control';
const CACHE_CONTROL_HEADER = 'cache-control';

export function checkCacheCookie(
  finalHop: Hop,
  alwaysSensitive: string[] = [],
  alwaysIgnore: string[] = []
): Finding[] {
  const setCookieHeaders = finalHop.rawHeaders
    .filter((h) => h.name.toLowerCase() === 'set-cookie')
    .map((h) => h.value);

  if (setCookieHeaders.length === 0) {
    return [];
  }

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
  const fromCache = finalHop.fromCache === true;

  if (cacheControlValue === undefined) {
    return [{
      ruleId: 'CACHE-001',
      category: 'header',
      severity: 'medium',
      confidence: 'deterministic',
      provenance: 'response-header',
      outcome: fromCache ? 'partial-coverage' : 'fail',
      title: 'Cache-Control: no-store missing on a response that sets sensitive cookies',
      impact: 'Responses setting authentication cookies may be stored by intermediate web caches, exposing session tokens.',
      evidence: sanitizeEvidence('(header absent)'),
      recommendation: 'Add "Cache-Control: no-store" to responses that set authentication or session cookies.',
      reference: REFERENCE,
      limitations: fromCache
        ? ['Response served from browser cache; Cache-Control presence cannot be verified from cached hop.']
        : ['Passive response inspection; did not test intermediary proxy behavior.'],
    }];
  }

  const normalised = cacheControlValue.toLowerCase();

  // Full compliance: no-store present (known-safe).
  if (normalised.includes('no-store')) {
    return [];
  }

  // Mitigated: 'private' or 'no-cache'
  if (normalised.includes('private') || normalised.includes('no-cache')) {
    return [{
      ruleId: 'CACHE-001',
      category: 'header',
      severity: 'info',
      confidence: 'deterministic',
      provenance: 'response-header',
      outcome: 'pass',
      title: 'Cache-Control allows local caching for response with sensitive cookies (mitigated by private/no-cache)',
      impact: 'Intermediate proxy/CDN caching is prevented by "private", but local browser storage persists the response.',
      evidence: sanitizeEvidence(cacheControlValue),
      recommendation: 'Shared CDN caching is prevented by "private", but consider "no-store" if shared computers are in scope.',
      reference: REFERENCE,
      limitations: ['Passive inspection; intermediate caching blocked by private/no-cache.'],
    }];
  }

  return [{
    ruleId: 'CACHE-001',
    category: 'header',
    severity: 'medium',
    confidence: 'deterministic',
    provenance: 'response-header',
    outcome: fromCache ? 'partial-coverage' : 'fail',
    title: 'Cache-Control: no-store missing on a response that sets sensitive cookies',
    impact: 'Sensitive authentication tokens can be cached by shared CDN or proxy servers.',
    evidence: sanitizeEvidence(cacheControlValue),
    recommendation: 'Add "Cache-Control: no-store" to responses setting sensitive session cookies.',
    reference: REFERENCE,
    limitations: fromCache ? ['Response served from browser cache.'] : ['Passive analysis.'],
  }];
}
