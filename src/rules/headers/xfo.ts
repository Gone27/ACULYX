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
import { sanitizeEvidence, getRawHeaderValues } from '../utils';

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

  const rawValues = getRawHeaderValues(finalHop, XFO_HEADER);

  // Header is absent.
  if (rawValues.length === 0) {
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

  const tokens: string[] = [];
  for (const raw of rawValues) {
    for (const part of raw.split(',')) {
      const trimmed = part.trim().toUpperCase();
      if (trimmed.length > 0) {
        tokens.push(trimmed);
      }
    }
  }

  if (tokens.length === 0) {
    return [
      {
        ruleId: 'XFO-001',
        category: 'header',
        severity: 'medium',
        title: 'X-Frame-Options header has an unrecognised value',
        impact:
          'Empty values are ignored by modern browsers, leaving the site vulnerable to iframe embedding and Clickjacking.',
        evidence: sanitizeEvidence(rawValues.join(', ')),
        recommendation:
          'Set X-Frame-Options to either "DENY" or "SAMEORIGIN".',
        reference: REFERENCE,
      },
    ];
  }

  const invalidTokens = tokens.filter((t) => !VALID_VALUES.has(t));
  if (invalidTokens.length > 0) {
    return [
      {
        ruleId: 'XFO-001',
        category: 'header',
        severity: 'medium',
        title: 'X-Frame-Options header has an unrecognised value',
        impact:
          'Unrecognized values (such as deprecated ALLOW-FROM or ALLOWALL) are ignored by modern browsers, leaving the site vulnerable to iframe embedding and Clickjacking.',
        evidence: sanitizeEvidence(rawValues.join(', ')),
        recommendation:
          'Set X-Frame-Options to either "DENY" or "SAMEORIGIN". ' +
          'The value "ALLOW-FROM" is deprecated and not supported in most browsers.',
        reference: REFERENCE,
      },
    ];
  }

  const uniqueTokens = new Set(tokens);
  if (uniqueTokens.size > 1) {
    return [
      {
        ruleId: 'XFO-001',
        category: 'header',
        severity: 'medium',
        title: 'X-Frame-Options header has conflicting values',
        impact:
          'Conflicting values (such as DENY and SAMEORIGIN) are handled inconsistently across browsers and intermediaries.',
        evidence: sanitizeEvidence(rawValues.join(', ')),
        recommendation:
          'Specify a single authoritative X-Frame-Options directive (either DENY or SAMEORIGIN).',
        reference: REFERENCE,
      },
    ];
  }

  // Valid header — no finding.
  return [];
}
