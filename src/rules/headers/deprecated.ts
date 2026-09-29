/**
 * Deprecated Headers Rule.
 *
 * Rules:
 *   DEP-001..008 (info) — obsolete response headers are present
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

  const deprecatedHeaders = [
    { name: 'public-key-pins', ruleId: 'DEP-002', title: 'Public-Key-Pins (HPKP) is obsolete', note: 'HPKP was removed from major browsers and can cause sites to become inaccessible when pins expire or are misconfigured.' },
    { name: 'p3p', ruleId: 'DEP-003', title: 'P3P privacy header is obsolete', note: 'Modern browsers ignore P3P; it does not provide enforceable privacy protection.' },
    { name: 'feature-policy', ruleId: 'DEP-004', title: 'Feature-Policy has been superseded by Permissions-Policy', note: 'Use the standardized Permissions-Policy header; legacy Feature-Policy syntax is not consistently supported.' },
    { name: 'x-ua-compatible', ruleId: 'DEP-005', title: 'X-UA-Compatible is obsolete', note: 'The header only targeted legacy Internet Explorer document modes and is ignored by modern browsers.' },
    { name: 'expect-ct', ruleId: 'DEP-006', title: 'Expect-CT is obsolete', note: 'Certificate Transparency enforcement is built into modern browsers; the Expect-CT header is no longer needed.' },
    { name: 'x-content-security-policy', ruleId: 'DEP-007', title: 'X-Content-Security-Policy is a legacy non-standard header', note: 'Use the standardized Content-Security-Policy response header.' },
    { name: 'x-webkit-csp', ruleId: 'DEP-008', title: 'X-WebKit-CSP is a legacy non-standard header', note: 'Use the standardized Content-Security-Policy response header.' },
    { name: 'public-key-pins-report-only', ruleId: 'DEP-009', title: 'Public-Key-Pins-Report-Only (HPKP) is obsolete', note: 'HPKP reporting was removed from major browsers and is no longer useful.' },
    { name: 'x-content-security-policy-report-only', ruleId: 'DEP-010', title: 'X-Content-Security-Policy-Report-Only is a legacy non-standard header', note: 'Use the standardized Content-Security-Policy-Report-Only response header.' },
    { name: 'x-webkit-csp-report-only', ruleId: 'DEP-011', title: 'X-WebKit-CSP-Report-Only is a legacy non-standard header', note: 'Use the standardized Content-Security-Policy-Report-Only response header.' },
    { name: 'x-download-options', ruleId: 'DEP-012', title: 'X-Download-Options is a legacy browser-specific header', note: 'This header only affects legacy Internet Explorer download behavior and is ignored by modern browsers.' },
  ] as const;

  for (const deprecated of deprecatedHeaders) {
    const value = finalHop.headers[deprecated.name];
    if (value === undefined) continue;
    findings.push({
      ruleId: deprecated.ruleId,
      category: 'header',
      severity: 'info',
      title: deprecated.title,
      impact: deprecated.note,
      evidence: sanitizeEvidence(value),
      recommendation: `Remove ${deprecated.name} unless a documented legacy-client requirement still depends on it.`,
      reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers',
    });
  }

  return findings;
}
