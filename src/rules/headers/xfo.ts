/**
 * X-Frame-Options Rule.
 *
 * Rules:
 *   XFO-001 (medium) — header absent or has an invalid value
 *
 * If the CSP already contains a 'frame-ancestors' directive the XFO check is
 * skipped, since frame-ancestors supersedes X-Frame-Options in modern browsers.
 */

import type { Finding, Hop } from '../../shared/types';
import { sanitizeEvidence } from '../utils';

const REFERENCE =
  'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options';

const XFO_HEADER = 'x-frame-options';

/** Valid X-Frame-Options directive values (case-insensitive comparison done via uppercase). */
const VALID_VALUES = new Set<string>(['DENY', 'SAMEORIGIN']);

/**
 * Evaluate the X-Frame-Options header for the final response hop.
 * This function is pure — no browser APIs are used.
 *
 * @param finalHop       - The last hop in the redirect chain.
 * @param cspDirectives  - Already-parsed CSP directives from checkCsp().
 * @returns An array of zero or one finding.
 */
export function checkXfo(
  finalHop: Hop,
  cspDirectives: Map<string, string>,
): Finding[] {
  // If CSP provides frame-ancestors, XFO is redundant — skip.
  if (cspDirectives.has('frame-ancestors')) {
    return [];
  }

  const rawValue = finalHop.headers[XFO_HEADER];

  // Header is absent.
  if (rawValue === undefined) {
    return [
      {
        ruleId: 'XFO-001',
        category: 'header',
        severity: 'medium',
        title: 'X-Frame-Options header is missing',
        impact:
          'Attackers can frame your site in an invisible iframe and overlay malicious decoy elements to hijack clicks and actions (Clickjacking).',
        evidence: sanitizeEvidence('(header absent)'),
        recommendation:
          'Add "X-Frame-Options: DENY" (or SAMEORIGIN) to prevent clickjacking. ' +
          'Alternatively, use CSP frame-ancestors.',
        reference: REFERENCE,
      },
    ];
  }

  // Header is present but not a recognised value.
  const normalised = rawValue.trim().toUpperCase();
  if (!VALID_VALUES.has(normalised)) {
    return [
      {
        ruleId: 'XFO-001',
        category: 'header',
        severity: 'medium',
        title: 'X-Frame-Options header has an unrecognised value',
        impact:
          'Unrecognized values (such as deprecated ALLOW-FROM) are ignored by modern browsers, leaving the site vulnerable to iframe embedding and Clickjacking.',
        evidence: sanitizeEvidence(rawValue),
        recommendation:
          'Set X-Frame-Options to either "DENY" or "SAMEORIGIN". ' +
          'The value "ALLOW-FROM" is deprecated and not supported in most browsers.',
        reference: REFERENCE,
      },
    ];
  }

  // Valid header — no finding.
  return [];
}
