/**
 * Information-Leakage Rule.
 *
 * Rules:
 *   LEAK-001 (low) — a response header exposes a version string or known
 *                    server/framework fingerprint.
 *
 * Checked headers include common server/framework/version and runtime markers.
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
 * Matches explicit version numbers prefixed by a product or technology name
 * (e.g. "nginx/1.24.0", "Apache/2.4", "PHP/8.1", "Express 4.x")
 * or bare versions if the header implies it (e.g. X-AspNet-Version: 4.0.30319).
 */
const VERSION_PATTERN = /[0-9]+\.[0-9]+/;
const PRODUCT_VERSION_PATTERN = /(?:microsoft-iis|apache|nginx|php|express|rails|django|laravel|node|openresty|litespeed|envoy|caddy|haproxy|tomcat|jetty|glassfish|jboss|weblogic|websphere)[\/\s-]*v?[0-9]+\.[0-9x]+/i;

/**
 * Returns true when the header value exposes a specific technology version.
 * Tightened to require product/version pairs, avoiding
 * false positives on simple numeric headers, UNLESS the header name explicitly implies a version.
 */
function isLeaky(value: string, headerName: string): boolean {
  if (headerName.includes('-version')) {
    return VERSION_PATTERN.test(value);
  }
  return PRODUCT_VERSION_PATTERN.test(value);
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
    if (value !== undefined && isLeaky(value, headerName)) {
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
