/**
 * Referrer-Policy Rule.
 *
 * Rules:
 *   REF-001 (low) — header absent or set to a weak/privacy-leaking policy
 *
 * Weak policies (including the browser default 'no-referrer-when-downgrade'
 * and the empty string) trigger a finding.
 */

import type { Finding, Hop } from '../../shared/types';
import { sanitizeEvidence } from '../utils';

const REFERENCE =
  'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy';

const REFERRER_HEADER = 'referrer-policy';

/**
 * Policies considered weak because they expose the full URL to cross-origin
 * destinations, or because they are the unsafe browser default.
 */
const WEAK_POLICIES = new Set<string>([
  'unsafe-url',
  'no-referrer-when-downgrade', // browser default — effectively "no policy set"
  '',                            // explicit empty value
]);

/**
 * Evaluate the Referrer-Policy header for the final response hop.
 * This function is pure — no browser APIs are used.
 *
 * @param finalHop - The last hop in the redirect chain.
 * @returns An array of zero or one finding.
 */
export function checkReferrer(finalHop: Hop): Finding[] {
  const rawValue = finalHop.headers[REFERRER_HEADER];

  // Header is absent entirely.
  if (rawValue === undefined) {
    return [
      {
        ruleId: 'REF-001',
        category: 'header',
        severity: 'low',
        title: 'Referrer-Policy header is missing',
        impact:
          'Modern browsers default to strict-origin-when-cross-origin, but older browsers may leak full URL query parameters (tokens, IDs, search terms) to external sites in the Referer header.',
        evidence: sanitizeEvidence('(header absent)'),
        recommendation:
          'Set Referrer-Policy to "strict-origin-when-cross-origin" or stricter ' +
          'to limit referrer leakage to third-party sites.',
        reference: REFERENCE,
      },
    ];
  }

  // Header is present but the policy is weak.
  // The spec allows multiple comma-separated values (fallback list); we check
  // the first recognised token, which browsers use, but also catch single-value
  // weak policies as-written.
  const trimmedValue = rawValue.trim().toLowerCase();
  if (WEAK_POLICIES.has(trimmedValue)) {
    return [
      {
        ruleId: 'REF-001',
        category: 'header',
        severity: 'low',
        title: 'Referrer-Policy is set to a weak or privacy-leaking value',
        impact:
          'Transmits the full URL path and sensitive query parameters to third-party destinations when links are clicked.',
        evidence: sanitizeEvidence(rawValue),
        recommendation:
          'Replace the current value with "strict-origin-when-cross-origin" or ' +
          '"no-referrer" to minimise referrer leakage.',
        reference: REFERENCE,
      },
    ];
  }

  // Acceptable policy — no finding.
  return [];
}
