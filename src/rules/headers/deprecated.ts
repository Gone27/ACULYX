/**
 * Deprecated Headers Rule.
 *
 * Rules:
 *   DEP-001 (info) — X-XSS-Protection is present (deprecated, potentially harmful)
 *
 * X-XSS-Protection was an IE/Chrome auditor feature that is now removed from
 * modern browsers.  Its presence is confusing and on some configurations it can
 * actually introduce XSS vectors.  Sites should remove it and rely on CSP.
 */

import type { Finding, Hop } from '../../shared/types';
import { sanitizeEvidence } from '../utils';

const REFERENCE =
  'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection';

/**
 * Detect deprecated security-related response headers.
 * This function is pure — no browser APIs are used.
 *
 * @param finalHop - The last hop in the redirect chain.
 * @returns An array of zero or one finding.
 */
export function checkDeprecated(finalHop: Hop): Finding[] {
  const findings: Finding[] = [];

  const xssProtection = finalHop.headers['x-xss-protection'];
  if (xssProtection !== undefined) {
    findings.push({
      ruleId: 'DEP-001',
      category: 'header',
      severity: 'info',
      title: 'X-XSS-Protection is deprecated and should be removed',
      impact:
        'This legacy browser auditor is obsolete and can introduce client-side side-channel leaks or bypasses in older browsers. Modern security relies on CSP.',
      evidence: sanitizeEvidence(xssProtection),
      recommendation:
        'Remove this header and rely on Content-Security-Policy instead.',
      reference: REFERENCE,
    });
  }

  return findings;
}
