/**
 * Cookie Security Rules.
 *
 * Rules:
 *   COOK-001 (high)   — Secure flag absent on an HTTPS-served cookie
 *   COOK-002 (medium) — HttpOnly flag absent (cookie accessible via JS)
 *   COOK-003 (high)   — SameSite=None without Secure (RFC 6265bis violation)
 *   COOK-004 (info)   — SameSite absent or empty (defaults to Lax)
 *   COOK-005 (high)   — __Host- prefix requirements violated
 *   COOK-006 (high)   — __Secure- prefix used without Secure flag
 *   COOK-007 (high)   — __Http- / __Host-Http- prefix requirements violated
 */

import type { CookieRecord, Finding } from '../../shared/types';
import { sanitizeEvidence, isSensitiveCookie } from '../utils';

const REF_COOKIES = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies';
const REF_PREFIX = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#cookie_prefixes';
const REF_SAMESITE = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite';

function checkSecure(
  cookie: CookieRecord,
  isHttps: boolean,
  alwaysSensitive: string[] = [],
  alwaysIgnore: string[] = []
): Finding | null {
  if (!isHttps) return null;
  if (cookie.secure) return null;

  const { isSensitive, reason } = isSensitiveCookie(cookie.name, alwaysSensitive, alwaysIgnore);
  const isRegexHeuristic = reason === 'regex';
  const hasStrongSignal = cookie.httpOnly || reason === 'override' || reason === 'prefix';

  const effectiveSeverity = isSensitive
    ? (isRegexHeuristic && !hasStrongSignal ? 'medium' : 'high')
    : 'low';

  const heuristicLabel = isSensitive && isRegexHeuristic && !hasStrongSignal ? ' (name-based heuristic)' : '';

  return {
    ruleId: 'COOK-001',
    category: 'cookie',
    severity: effectiveSeverity,
    confidence: isRegexHeuristic ? 'heuristic' : 'deterministic',
    provenance: 'cookie-metadata',
    outcome: 'fail',
    title: `${isSensitive ? 'Sensitive cookie' : 'Cookie'} "${sanitizeEvidence(cookie.name)}" is missing the Secure flag${heuristicLabel}`,
    impact: 'The cookie can be transmitted across unencrypted HTTP links, allowing network eavesdroppers to intercept session tokens or user data in cleartext.',
    evidence: sanitizeEvidence(cookie.name),
    recommendation: 'Add the Secure attribute so the cookie is never sent over plain HTTP.',
    reference: REF_COOKIES,
    limitations: ['Passive metadata inspection of cookie attributes.'],
  };
}

function checkHttpOnly(
  cookie: CookieRecord,
  alwaysSensitive: string[] = [],
  alwaysIgnore: string[] = []
): Finding | null {
  if (cookie.httpOnly) return null;
  if (cookie.setByJs === true) return null;

  const { isSensitive, reason } = isSensitiveCookie(cookie.name, alwaysSensitive, alwaysIgnore);
  if (!isSensitive) return null;

  const isRegexHeuristic = reason === 'regex';
  const hasStrongSignal = cookie.secure || reason === 'override' || reason === 'prefix';
  const heuristicLabel = isRegexHeuristic && !hasStrongSignal ? ' (name-based heuristic)' : '';

  return {
    ruleId: 'COOK-002',
    category: 'cookie',
    severity: 'medium',
    confidence: isRegexHeuristic ? 'heuristic' : 'deterministic',
    provenance: 'cookie-metadata',
    outcome: 'fail',
    title: `Sensitive cookie "${sanitizeEvidence(cookie.name)}" is missing the HttpOnly flag${heuristicLabel}`,
    impact: 'This sensitive session cookie is readable by JavaScript via document.cookie, meaning any Cross-Site Scripting (XSS) attack can immediately steal it.',
    evidence: sanitizeEvidence(cookie.name),
    recommendation: 'Add HttpOnly so this sensitive session/auth cookie cannot be read by JavaScript (mitigates XSS cookie theft).',
    reference: REF_COOKIES,
    limitations: ['Passive metadata inspection; sensitivity inferred from cookie name pattern.'],
  };
}

function checkSameSiteNone(cookie: CookieRecord): Finding | null {
  if (cookie.sameSite !== 'none') return null;
  if (cookie.secure) return null;
  return {
    ruleId: 'COOK-003',
    category: 'cookie',
    severity: 'high',
    confidence: 'deterministic',
    provenance: 'cookie-metadata',
    outcome: 'fail',
    title: `Cookie "${sanitizeEvidence(cookie.name)}" uses SameSite=None without Secure`,
    impact: 'SameSite=None permits cross-site requests to send this cookie, but omitting Secure allows it to travel unencrypted, violating modern browser security standards.',
    evidence: sanitizeEvidence(cookie.name),
    recommendation: 'Add the Secure attribute or change SameSite to Strict or Lax.',
    reference: REF_SAMESITE,
    limitations: ['RFC 6265bis mandates Secure attribute when SameSite=None is set.'],
  };
}

function checkSameSiteMissing(
  cookie: CookieRecord,
  alwaysSensitive: string[] = [],
  alwaysIgnore: string[] = []
): Finding | null {
  if (cookie.sameSite !== '') return null;
  const { isSensitive } = isSensitiveCookie(cookie.name, alwaysSensitive, alwaysIgnore);
  const effectiveSeverity: Finding['severity'] = isSensitive ? 'medium' : 'info';
  const effectiveOutcome: Finding['outcome'] = isSensitive ? 'fail' : 'pass';
  return {
    ruleId: 'COOK-004',
    category: 'cookie',
    severity: effectiveSeverity,
    confidence: isSensitive ? 'heuristic' : 'deterministic',
    provenance: 'cookie-metadata',
    outcome: effectiveOutcome,
    title: isSensitive
      ? `Sensitive cookie "${sanitizeEvidence(cookie.name)}" has no explicit SameSite attribute — cross-site request exposure on Safari, Firefox, and legacy browsers`
      : `Cookie "${sanitizeEvidence(cookie.name)}" has no explicit SameSite attribute (Lax in Chromium; None in Safari and standard Firefox)`,
    impact: isSensitive
      ? 'Without an explicit SameSite attribute, only Chromium-based browsers apply Lax-by-default. Browsers such as Apple Safari, iOS WebKit, and standard Firefox configurations do NOT default to Lax and continue to send unlabelled cookies with cross-site requests, leaving sensitive actions vulnerable to CSRF.'
      : 'While Chromium defaults unlabelled cookies to SameSite=Lax, Safari and default Firefox installations do not enforce Lax-by-default and may attach the cookie to cross-site contexts.',
    evidence: sanitizeEvidence(cookie.name),
    recommendation: isSensitive
      ? 'Explicitly set SameSite=Strict or SameSite=Lax. Prefer SameSite=Strict for authentication and session management cookies, or SameSite=Lax for top-level navigation flows.'
      : 'Explicitly declare SameSite=Lax or SameSite=Strict for defense-in-depth across non-Chromium browsers (Safari, Firefox) and legacy clients.',
    reference: REF_SAMESITE,
    limitations: isSensitive
      ? ['Passive metadata inspection; cross-browser default handling differs between Chromium (Lax) and Safari/Firefox (None).']
      : ['Informational observation; cross-browser default handling differs between Chromium (Lax) and Safari/Firefox (None).'],
  };
}

function checkHostPrefix(cookie: CookieRecord): Finding | null {
  const lowerName = cookie.name.toLowerCase();
  if (!lowerName.startsWith('__host-')) return null;
  const violations: string[] = [];
  if (!cookie.secure) violations.push('Secure flag missing');
  if (cookie.path !== '/') violations.push(`Path is "${cookie.path}" (must be /)`);
  if (cookie.domainAttributePresent === true) {
    violations.push('Domain attribute must be absent');
  }
  if (violations.length === 0) return null;
  return {
    ruleId: 'COOK-005',
    category: 'cookie',
    severity: 'high',
    confidence: 'deterministic',
    provenance: 'cookie-metadata',
    outcome: 'fail',
    title: `Cookie "${sanitizeEvidence(cookie.name)}" violates __Host- prefix requirements`,
    impact: 'Failing __Host- prefix requirements breaks browser isolation guarantees, allowing subdomains or subpaths to overwrite or shadow the main session cookie.',
    evidence: sanitizeEvidence(violations.join('; ')),
    recommendation: 'Fix the cookie so it has Secure=true, Path=/, and no Domain attribute.',
    reference: REF_PREFIX,
    limitations: ['Passive metadata inspection; Domain attribute verified from Set-Cookie when observed.'],
  };
}

function checkSecurePrefix(cookie: CookieRecord): Finding | null {
  const lowerName = cookie.name.toLowerCase();
  if (!lowerName.startsWith('__secure-')) return null;
  if (cookie.secure) return null;
  return {
    ruleId: 'COOK-006',
    category: 'cookie',
    severity: 'high',
    confidence: 'deterministic',
    provenance: 'cookie-metadata',
    outcome: 'fail',
    title: `Cookie "${sanitizeEvidence(cookie.name)}" violates __Secure- prefix requirements`,
    impact: 'The __Secure- prefix explicitly promises the cookie will only be sent over HTTPS. Omitting Secure causes browsers to reject the cookie or allow plaintext transmission.',
    evidence: sanitizeEvidence(cookie.name),
    recommendation: 'Add the Secure attribute — the __Secure- prefix requires it.',
    reference: REF_PREFIX,
    limitations: ['Passive metadata inspection of cookie flags.'],
  };
}

function checkHttpPrefix(cookie: CookieRecord): Finding | null {
  const lowerName = cookie.name.toLowerCase();
  const hostHttp = lowerName.startsWith('__host-http-');
  const http = hostHttp || lowerName.startsWith('__http-');
  if (!http) return null;
  const violations: string[] = [];
  if (!cookie.secure) violations.push('Secure flag missing');
  if (!cookie.httpOnly) violations.push('HttpOnly flag missing');
  if (hostHttp) {
    if (cookie.path !== '/') violations.push(`Path is "${cookie.path}" (must be /)`);
    if (cookie.domainAttributePresent === true) violations.push('Domain attribute must be absent');
  }
  if (violations.length === 0) return null;
  return {
    ruleId: 'COOK-007',
    category: 'cookie',
    severity: 'high',
    confidence: 'deterministic',
    provenance: 'cookie-metadata',
    outcome: 'fail',
    title: `Cookie "${sanitizeEvidence(cookie.name)}" violates ${hostHttp ? '__Host-Http-' : '__Http-'} prefix requirements`,
    impact: 'The browser-enforced prefix requirements are not met, so the cookie may be rejected or lose the server-only and host-bound protections its name claims.',
    evidence: sanitizeEvidence(violations.join('; ')),
    recommendation: hostHttp
      ? 'Use Secure, HttpOnly, Path=/, and omit Domain.'
      : 'Use both Secure and HttpOnly.',
    reference: REF_PREFIX,
    limitations: ['Passive metadata inspection.'],
  };
}

function checkLongLivedSessionCookie(
  cookie: CookieRecord,
  alwaysSensitive: string[] = [],
  alwaysIgnore: string[] = []
): Finding | null {
  const { isSensitive } = isSensitiveCookie(cookie.name, alwaysSensitive, alwaysIgnore);
  if (!isSensitive) return null;
  if (cookie.session || cookie.expiresAt === null) return null;

  // Excessively long duration (> 1 year = 31536000s)
  const maxSessionDurationMs = 365 * 24 * 60 * 60 * 1000;
  const now = Date.now();
  if (cookie.expiresAt - now > maxSessionDurationMs) {
    return {
      ruleId: 'COOK-008',
      category: 'cookie',
      severity: 'low',
      confidence: 'heuristic',
      provenance: 'cookie-metadata',
      outcome: 'fail',
      title: `Sensitive session cookie "${sanitizeEvidence(cookie.name)}" has excessively long expiration`,
      impact: 'Persistent authentication tokens valid for more than 1 year increase the window of opportunity for stolen session reuse and token harvesting.',
      evidence: sanitizeEvidence(`Expiry: ${new Date(cookie.expiresAt).toISOString()}`),
      recommendation: 'Configure reasonable session expirations (e.g. 1-30 days) with explicit idle timeouts and token rotation.',
      reference: REF_COOKIES,
      limitations: ['Passive metadata inspection; sensitivity inferred from cookie name.'],
    };
  }
  return null;
}

function checkSameSiteNoneOnSensitive(
  cookie: CookieRecord,
  alwaysSensitive: string[] = [],
  alwaysIgnore: string[] = []
): Finding | null {
  if (cookie.sameSite !== 'none') return null;
  const { isSensitive } = isSensitiveCookie(cookie.name, alwaysSensitive, alwaysIgnore);
  if (!isSensitive) return null;
  if (!cookie.secure) return null; // Already caught with high severity by COOK-003

  return {
    ruleId: 'COOK-009',
    category: 'cookie',
    severity: 'medium',
    confidence: 'heuristic',
    provenance: 'cookie-metadata',
    outcome: 'fail',
    title: `Sensitive authentication cookie "${sanitizeEvidence(cookie.name)}" uses SameSite=None`,
    impact: 'SameSite=None causes the browser to send this sensitive authentication cookie with every third-party cross-site request, exposing authenticated endpoints to Cross-Site Request Forgery (CSRF).',
    evidence: sanitizeEvidence(`SameSite=None; Secure=${cookie.secure}`),
    recommendation: 'Change SameSite to Strict or Lax for sensitive authentication and session cookies. Use Partitioned (CHIPS) if cross-site iframe embedding is legitimate.',
    reference: REF_SAMESITE,
    limitations: ['Passive metadata inspection.'],
  };
}

export function checkCookies(
  cookies: CookieRecord[],
  isHttps: boolean,
  alwaysSensitive: string[] = [],
  alwaysIgnore: string[] = []
): Finding[] {
  const findings: Finding[] = [];

  for (const cookie of cookies) {
    const secure    = checkSecure(cookie, isHttps, alwaysSensitive, alwaysIgnore);
    const httpOnly  = checkHttpOnly(cookie, alwaysSensitive, alwaysIgnore);
    const sameNone  = checkSameSiteNone(cookie);
    const sameMiss  = checkSameSiteMissing(cookie, alwaysSensitive, alwaysIgnore);
    const host      = checkHostPrefix(cookie);
    const secPfx    = checkSecurePrefix(cookie);
    const httpPfx   = checkHttpPrefix(cookie);
    const longLived = checkLongLivedSessionCookie(cookie, alwaysSensitive, alwaysIgnore);
    const ssNoneSens = checkSameSiteNoneOnSensitive(cookie, alwaysSensitive, alwaysIgnore);

    if (secure    !== null) findings.push(secure);
    if (httpOnly  !== null) findings.push(httpOnly);
    if (sameNone  !== null) findings.push(sameNone);
    if (sameMiss  !== null) findings.push(sameMiss);
    if (host      !== null) findings.push(host);
    if (secPfx    !== null) findings.push(secPfx);
    if (httpPfx   !== null) findings.push(httpPfx);
    if (longLived !== null) findings.push(longLived);
    if (ssNoneSens !== null) findings.push(ssNoneSens);
  }

  return findings;
}
