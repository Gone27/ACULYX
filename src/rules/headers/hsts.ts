/**
 * HSTS Rule — checks the Strict-Transport-Security header.
 *
 * Rules:
 *   HSTS-001 (high)   — header absent on an HTTPS origin
 *   HSTS-002 (medium) — max-age below the recommended minimum (1 year)
 *   HSTS-003 (low)    — includeSubDomains directive missing
 */

import type { Finding, Hop } from '../../shared/types';
import { sanitizeEvidence } from '../utils';

const REFERENCE =
  'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security';

const HSTS_HEADER = 'strict-transport-security';
const HSTS_MIN_MAX_AGE = 31_536_000; // 1 year in seconds

/**
 * Evaluate HSTS posture for the final response hop.
 * This function is pure — no browser APIs are used.
 *
 * @param finalHop - The last hop in the redirect chain.
 * @returns An array of zero or more findings.
 */
export function checkHsts(finalHop: Hop): Finding[] {
  // HSTS is only meaningful (and only sent) over HTTPS.
  if (!finalHop.url.startsWith('https://')) {
    return [];
  }

  const findings: Finding[] = [];
  const headerValue = finalHop.headers[HSTS_HEADER];

  if (headerValue === undefined) {
    // HSTS-001: Header is completely absent.
    findings.push({
      ruleId: 'HSTS-001',
      category: 'transport',
      severity: 'high',
      title: 'Strict-Transport-Security header is missing',
      impact:
        'An attacker on the same network (e.g. public Wi-Fi) can downgrade the connection to unencrypted HTTP and intercept passwords or session cookies (SSL Stripping).',
      evidence: sanitizeEvidence('(header absent)'),
      recommendation:
        'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" to all HTTPS responses.',
      reference: REFERENCE,
    });
    // Without the header there is nothing further to evaluate.
    return findings;
  }

  // HSTS-002: max-age present but below the recommended minimum.
  // Also fires when max-age directive cannot be parsed (treated as 0).
  const maxAgeMatch = /max-age\s*=\s*(\d+)/i.exec(headerValue);
  const maxAge = maxAgeMatch !== null ? parseInt(maxAgeMatch[1] ?? '0', 10) : 0;

  if (maxAge < HSTS_MIN_MAX_AGE) {
    findings.push({
      ruleId: 'HSTS-002',
      category: 'transport',
      severity: 'medium',
      title: 'Strict-Transport-Security max-age is below the recommended minimum (1 year)',
      impact:
        'A short expiration allows browsers to silently revert to unencrypted HTTP if a user revisits after the window expires.',
      evidence: sanitizeEvidence(headerValue),
      recommendation: `Increase max-age to at least ${HSTS_MIN_MAX_AGE} (1 year). Current value: ${maxAge}.`,
      reference: REFERENCE,
    });
  }

  // HSTS-003: includeSubDomains directive is absent.
  if (!/includeSubDomains/i.test(headerValue)) {
    findings.push({
      ruleId: 'HSTS-003',
      category: 'transport',
      severity: 'low',
      title: 'Strict-Transport-Security is missing the includeSubDomains directive',
      impact:
        'Subdomains are not forced to HTTPS, leaving them vulnerable to unencrypted network eavesdropping and cookie injection.',
      evidence: sanitizeEvidence(headerValue),
      recommendation:
        'Add the "includeSubDomains" directive to ensure all subdomains are protected.',
      reference: REFERENCE,
    });
  }

  return findings;
}
