/**
 * HSTS Rule — checks the Strict-Transport-Security header.
 *
 * Rules:
 *   HSTS-001 (high)   — header absent on an HTTPS origin
 *   HSTS-002 (medium) — max-age below the recommended minimum (1 year)
 *   HSTS-003 (low)    — includeSubDomains directive missing
 *   HSTS-004 (info)   — preload token supplied without basic eligibility directives
 *   HSTS-005 (info)   — header meets basic preload directives; list membership is not checked
 */

import type { Finding, Hop } from '../../shared/types';
import { sanitizeEvidence, getRawHeaderValues } from '../utils';

const REFERENCE =
  'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security';

const HSTS_HEADER = 'strict-transport-security';
const HSTS_MIN_MAX_AGE = 31_536_000; // 1 year in seconds
const HSTS_PRELOAD_MAX_AGE = 31_536_000; // hstspreload.org minimum: 1 year (https://hstspreload.org/)

interface HstsDirectives {
  maxAge: number;
  includeSubDomains: boolean;
  preload: boolean;
}

/** Tolerant RFC 6797 directive parser (quoted values, any case, first max-age wins). */
export function parseHstsDirectives(value: string): HstsDirectives {
  let maxAge: number | null = null;
  let includeSubDomains = false;
  let preload = false;
  for (const part of value.split(';')) {
    const token = part.trim();
    if (token.length === 0) continue;
    const eq = token.indexOf('=');
    const name = (eq === -1 ? token : token.slice(0, eq)).trim().toLowerCase();
    const raw = eq === -1 ? '' : token.slice(eq + 1).trim().replace(/^"(.*)"$/, '$1');
    if (name === 'max-age' && maxAge === null && /^\d+$/.test(raw)) maxAge = parseInt(raw, 10);
    else if (name === 'includesubdomains') includeSubDomains = true;
    else if (name === 'preload') preload = true;
  }
  return { maxAge: maxAge ?? 0, includeSubDomains, preload };
}

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
  const rawValues = getRawHeaderValues(finalHop, HSTS_HEADER);

  if (rawValues.length === 0) {
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

  // Parse directives per RFC 6797 §6.1 across all supplied STS header instances.
  // Evaluate the active / worst-case posture across headers so invalid/zero max-age is not hidden by duplicates.
  const allParsed = rawValues.map((v) => ({ raw: v, directives: parseHstsDirectives(v) }));
  const minMaxAge = Math.min(...allParsed.map((p) => p.directives.maxAge));
  const hasIncludeSubdomains = allParsed.every((p) => p.directives.includeSubDomains);
  const hasPreload = allParsed.some((p) => p.directives.preload);
  const combinedEvidence = rawValues.join(' | ');

  // HSTS-002: max-age present but below the recommended minimum (or missing/unparseable => 0).
  if (minMaxAge < HSTS_MIN_MAX_AGE) {
    findings.push({
      ruleId: 'HSTS-002',
      category: 'transport',
      severity: 'medium',
      title: 'Strict-Transport-Security max-age is below the recommended minimum (1 year)',
      impact:
        'A short expiration allows browsers to silently revert to unencrypted HTTP if a user revisits after the window expires.',
      evidence: sanitizeEvidence(combinedEvidence),
      recommendation: `Increase max-age to at least ${HSTS_MIN_MAX_AGE} (1 year). Current value: ${minMaxAge}.`,
      reference: REFERENCE,
    });
  }

  // HSTS-003: includeSubDomains directive is absent in any header instance.
  if (!hasIncludeSubdomains) {
    findings.push({
      ruleId: 'HSTS-003',
      category: 'transport',
      severity: 'low',
      title: 'Strict-Transport-Security is missing the includeSubDomains directive',
      impact:
        'Subdomains are not forced to HTTPS, leaving them vulnerable to unencrypted network eavesdropping and cookie injection.',
      evidence: sanitizeEvidence(combinedEvidence),
      recommendation:
        'Add the "includeSubDomains" directive to ensure all subdomains are protected.',
      reference: REFERENCE,
    });
  }

  const meetsBasicPreloadRequirements = minMaxAge >= HSTS_PRELOAD_MAX_AGE && hasIncludeSubdomains;

  if (hasPreload && !meetsBasicPreloadRequirements) {
    findings.push({
      ruleId: 'HSTS-004',
      category: 'transport',
      severity: 'info',
      title: 'HSTS preload token is present but basic preload directives are incomplete',
      evidence: sanitizeEvidence(combinedEvidence),
      recommendation: 'HSTS preload submissions require max-age of at least 31536000 (1 year) and includeSubDomains. Verify all subdomains support HTTPS before submitting.',
      reference: 'https://hstspreload.org/',
    });
  } else if (!hasPreload && meetsBasicPreloadRequirements) {
    findings.push({
      ruleId: 'HSTS-005',
      category: 'transport',
      severity: 'info',
      title: 'HSTS header meets basic preload directives; preload-list membership is not checked',
      evidence: sanitizeEvidence(combinedEvidence),
      recommendation: 'If preload is desired, review all hstspreload.org requirements and submit the domain; these header checks do not verify certificate, redirect, subdomain, or list status.',
      reference: 'https://hstspreload.org/',
    });
  }

  return findings;
}
