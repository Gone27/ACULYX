/**
 * X-Content-Type-Options Rule.
 *
 * Rules:
 *   XCTO-001 (medium) — header absent or value is not exactly 'nosniff'
 */

import type { Finding, Hop } from '../../shared/types';
import { sanitizeEvidence } from '../utils';

const REFERENCE =
  'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options';

const XCTO_HEADER = 'x-content-type-options';

/**
 * Evaluate the X-Content-Type-Options header for the final response hop.
 * This function is pure — no browser APIs are used.
 *
 * @param finalHop - The last hop in the redirect chain.
 * @returns An array of zero or one finding.
 */
export function checkXcto(finalHop: Hop): Finding[] {
  const rawValue = finalHop.headers[XCTO_HEADER];

  // Header is absent.
  if (rawValue === undefined) {
    return [
      {
        ruleId: 'XCTO-001',
        category: 'header',
        severity: 'medium',
        title: 'X-Content-Type-Options header is missing',
        impact:
          'Browsers may guess ("sniff") response types, executing user-uploaded text or image files as malicious JavaScript (MIME-confusion XSS).',
        evidence: sanitizeEvidence('(header absent)'),
        recommendation:
          'Add "X-Content-Type-Options: nosniff" to prevent MIME-type sniffing attacks.',
        reference: REFERENCE,
      },
    ];
  }

  // Header is present but the value is not 'nosniff'.
  if (rawValue.trim().toLowerCase() !== 'nosniff') {
    return [
      {
        ruleId: 'XCTO-001',
        category: 'header',
        severity: 'medium',
        title: 'X-Content-Type-Options header has an invalid value',
        impact:
          'Browsers do not recognize invalid values and fall back to content sniffing, re-opening MIME confusion attack vectors.',
        evidence: sanitizeEvidence(rawValue),
        recommendation:
          'Set X-Content-Type-Options to exactly "nosniff". No other values are recognised by browsers.',
        reference: REFERENCE,
      },
    ];
  }

  // Header is present and correct — no finding.
  return [];
}
