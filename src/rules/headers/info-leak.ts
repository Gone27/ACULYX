/**
 * Information-Leakage Rule.
 *
 * Rules:
 *   LEAK-001 (low) — a response header exposes a version string or known
 *                    server/framework fingerprint.
 *
 * Checked headers: server, x-powered-by, x-aspnet-version,
 *                  x-aspnetmvc-version, x-generator
 */

import type { Finding, Hop } from '../../shared/types';
import { sanitizeEvidence } from '../utils';

const REFERENCE =
  'https://owasp.org/www-project-secure-headers/#server';

/**
 * Headers that may inadvertently reveal server/framework version information.
 * All values must be lowercase (matching the normalised keys in Hop.headers).
 */
const LEAKY_HEADERS: readonly string[] = [
  'server',
  'x-powered-by',
  'x-aspnet-version',
  'x-aspnetmvc-version',
  'x-generator',
];

/**
 * Matches explicit version numbers (e.g. "1.2", "14.0.3").
 */
const VERSION_PATTERN = /[0-9]+\.[0-9]+/;

/**
 * Returns true when the header value contains a version number string.
 * A technology name alone (e.g. "nginx", "Apache") is not enough —
 * we require an explicit version (e.g. "nginx/1.24.0", "Apache/2.4") to
 * avoid false positives on minimal server headers.
 */
function isLeaky(value: string): boolean {
  return VERSION_PATTERN.test(value);
}

/**
 * Detect version strings or technology fingerprints in common response headers.
 * This function is pure — no browser APIs are used.
 *
 * @param finalHop - The last hop in the redirect chain.
 * @returns An array of findings, one per leaking header.
 */
export function checkInfoLeak(finalHop: Hop): Finding[] {
  const findings: Finding[] = [];

  for (const headerName of LEAKY_HEADERS) {
    const value = finalHop.headers[headerName];
    if (value !== undefined && isLeaky(value)) {
      findings.push({
        ruleId: 'LEAK-001',
        category: 'header',
        severity: 'low',
        title: `Version string in ${headerName} response header`,
        impact:
          'Broadcasting software and framework versions assists attackers in looking up known CVE exploits targeted specifically at your technology stack.',
        evidence: sanitizeEvidence(value),
        recommendation:
          'Remove or redact this header at your web server / reverse proxy.',
        reference: REFERENCE,
      });
    }
  }

  return findings;
}
