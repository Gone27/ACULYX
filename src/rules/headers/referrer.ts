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
import { sanitizeEvidence, getRawHeaderValues } from '../utils';

const REFERENCE =
  'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy';

const REFERRER_HEADER = 'referrer-policy';

/**
 * Standard recognized referrer policy tokens per W3C Referrer Policy §8.1.
 */
const KNOWN_REFERRER_POLICIES = new Set<string>([
  'no-referrer',
  'no-referrer-when-downgrade',
  'origin',
  'origin-when-cross-origin',
  'same-origin',
  'strict-origin',
  'strict-origin-when-cross-origin',
  'unsafe-url',
]);

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
 * Parses Referrer-Policy header instances into the effective policy using W3C §8.1/8.2 algorithm:
 * The tokens are processed left-to-right; the last recognized valid token wins.
 * Unrecognized tokens are ignored.
 */
export function parseReferrerPolicy(rawValues: string[]): {
  effectivePolicy: string | null;
  tokens: string[];
} {
  const allTokens: string[] = [];
  let effectivePolicy: string | null = null;

  for (const raw of rawValues) {
    for (const part of raw.split(',')) {
      const token = part.trim().toLowerCase();
      if (token.length > 0) {
        allTokens.push(token);
        if (KNOWN_REFERRER_POLICIES.has(token)) {
          effectivePolicy = token;
        }
      }
    }
  }

  return { effectivePolicy, tokens: allTokens };
}

/**
 * Evaluate the Referrer-Policy header for the final response hop.
 * This function is pure — no browser APIs are used.
 *
 * @param finalHop - The last hop in the redirect chain.
 * @returns An array of zero or one finding.
 */
export function checkReferrer(finalHop: Hop): Finding[] {
  const rawValues = getRawHeaderValues(finalHop, REFERRER_HEADER);

  // Header is absent entirely.
  if (rawValues.length === 0) {
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

  const { effectivePolicy } = parseReferrerPolicy(rawValues);

  // Header was present but contained only empty or unrecognized tokens.
  if (effectivePolicy === null) {
    return [
      {
        ruleId: 'REF-001',
        category: 'header',
        severity: 'low',
        title: 'Referrer-Policy is set to an unrecognised value',
        impact:
          'Unrecognized values are ignored by modern browsers, falling back to browser default behavior.',
        evidence: sanitizeEvidence(rawValues.join(', ')),
        recommendation:
          'Set Referrer-Policy to "strict-origin-when-cross-origin" or "no-referrer".',
        reference: REFERENCE,
      },
    ];
  }

  // If the effective policy (last recognized token in fallback list) is weak.
  if (WEAK_POLICIES.has(effectivePolicy)) {
    return [
      {
        ruleId: 'REF-001',
        category: 'header',
        severity: 'low',
        title: 'Referrer-Policy is set to a weak or privacy-leaking value',
        impact:
          'Transmits the full URL path and sensitive query parameters to third-party destinations when links are clicked.',
        evidence: sanitizeEvidence(rawValues.join(', ')),
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
