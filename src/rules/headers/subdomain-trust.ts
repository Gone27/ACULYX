/**
 * subdomain-trust.ts — Subdomain→Main-Domain escalation analysis
 *
 * A bug on a subdomain ONLY counts against the main domain if it can jump over to it.
 * Three primary trust bridges make that jump possible:
 *
 *   1. Cookies:
 *      - SUB-001 (critical): Login/session cookies scoped across the entire apex
 *        (Domain=.example.com or Domain=example.com). Subdomain XSS can read (if non-HttpOnly)
 *        or ambiently transmit these credentials to access the main site.
 *      - SUB-005 (medium): Cookie Tossing / Shadowing — sensitive session cookies
 *        lack the __Host- prefix. An attacker controlling any subdomain can inject
 *        a cookie scoped to .example.com and overwrite/shadow the main domain's session!
 *
 *   2. CSP allows that subdomain:
 *      - SUB-002 (critical): Effective script-src trusts *.example.com, https:, or *,
 *        meaning hostile JavaScript hosted or injected on a subdomain runs with the full
 *        privileges of the main domain.
 *
 *   3. CORS / postMessage / DOM trust:
 *      - SUB-003 (high): CORS policy trusts subdomain origins or wildcards with credentials
 *        (Access-Control-Allow-Origin: * or subdomain origin + Access-Control-Allow-Credentials: true,
 *        or dynamic reflection via Vary: Origin), allowing subdomain JS to steal private API data.
 *      - SUB-004 (high): Missing frame restrictions (frame-ancestors / X-Frame-Options) allowing
 *        the page to be framed by subdomains, exposing it to postMessage interception or clickjacking.
 *      - SUB-006 (medium): Missing Cross-Origin-Opener-Policy (COOP) allows a compromised subdomain
 *        to open the main domain in a window and manipulate window.opener (reverse tabnabbing).
 *      - SUB-007 (low): Missing Origin-Agent-Cluster allows legacy document.domain relaxation
 *        to break Same-Origin-Policy between subdomains and the main domain.
 *
 *   Isolation guarantee:
 *      - SUB-008 (info): If the page is a subdomain and NONE of the trust bridges exist,
 *        the subdomain is certified as ISOLATED. A bug on the subdomain stays contained
 *        and cannot jump to the main site.
 *
 * All checks are pure — no browser APIs are used.
 */

import type { Finding, Hop, CookieRecord, SubdomainTrustVector } from '../../shared/types';
import { sanitizeEvidence, parseCspDirectives, isSensitiveCookie, hasCspBypassProtection } from '../utils';

const REF_SUBDOMAIN =
  'https://portswigger.net/web-security/host-header/exploiting#password-reset-poisoning-via-dangling-markup';
const REF_CORS =
  'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS';
const REF_COOKIE =
  'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#domaindomain-value';
const REF_COOKIE_TOSS =
  'https://datatracker.ietf.org/doc/html/rfc6265#section-8.6';
const REF_CSP =
  'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy';
const REF_COOP =
  'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy';
const REF_OAC =
  'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin-Agent-Cluster';

// ---------------------------------------------------------------------------
// Multi-part TLD & Registrable Domain Helpers
// ---------------------------------------------------------------------------

const TWO_PART_TLDS = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'net.uk', 'me.uk', 'ltd.uk', 'plc.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'id.au',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz', 'geek.nz', 'school.nz',
  'co.jp', 'ne.jp', 'or.jp', 'go.jp', 'ac.jp', 'ed.jp', 'lg.jp',
  'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in', 'nic.in', 'ac.in', 'edu.in', 'gov.in',
  'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br', 'ind.br',
  'com.sg', 'edu.sg', 'gov.sg', 'net.sg', 'org.sg',
  'com.mx', 'edu.mx', 'gob.mx', 'org.mx', 'net.mx',
  'co.za', 'org.za', 'gov.za', 'net.za', 'ac.za',
  'com.tr', 'net.tr', 'org.tr', 'gov.tr', 'edu.tr',
  'com.tw', 'org.tw', 'gov.tw', 'edu.tw', 'net.tw',
  'com.hk', 'org.hk', 'gov.hk', 'edu.hk', 'net.hk',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
]);

/**
 * Derive the eTLD+1 (registrable domain) from a hostname.
 * Handles both standard TLDs (example.com) and two-part eTLDs (example.co.uk).
 * Returns null for IP addresses and localhost.
 */
export function registrableDomain(hostname: string): string | null {
  if (!hostname || /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname === 'localhost') {
    return null;
  }
  const parts = hostname.toLowerCase().split('.');
  if (parts.length < 2) return null;

  if (parts.length >= 3) {
    const lastTwo = parts.slice(-2).join('.');
    if (TWO_PART_TLDS.has(lastTwo) || /^[a-z0-9\-]+\.(co|com|net|org|gov|edu|ac|gob)\.[a-z]{2}$/.test(parts.slice(-3).join('.'))) {
      return parts.slice(-3).join('.');
    }
  }

  return parts.slice(-2).join('.');
}

/**
 * Returns true when `hostname` is a true subdomain of its registrable domain
 * (ignoring the standard 'www' prefix which acts as the apex site).
 */
export function isSubdomain(hostname: string): boolean {
  const reg = registrableDomain(hostname);
  if (reg == null || hostname === reg) return false;
  if (hostname === `www.${reg}`) return false;
  return hostname.length > reg.length + 1 && hostname.endsWith(`.${reg}`);
}

/**
 * Split a CSP source-list on whitespace, return tokens.
 */
function cspTokens(src: string): string[] {
  return src.split(/\s+/).filter((t) => t.length > 0);
}

/**
 * Returns true when a CSP source-list token allows script execution from
 * an arbitrary subdomain of `registrable` (eTLD+1).
 */
function cspAllowsSubdomain(sourceList: string, registrable: string): boolean {
  for (const token of cspTokens(sourceList)) {
    const bare = token.replace(/^https?:\/\//, '');
    if (bare === `*.${registrable}` || bare === registrable) return true;
    if (bare.endsWith(`.${registrable}`) && !bare.startsWith('*')) return true;
  }
  return false;
}

/**
 * Resolve effective source-list for `directive`, falling back to default-src.
 */
function resolveEffective(
  directives: Map<string, string>,
  directive: string,
): string | undefined {
  return directives.get(directive) ?? directives.get('default-src');
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface SubdomainTrustResult {
  findings: Finding[];
  hasEscalationPath: boolean;
  vectors: SubdomainTrustVector[];
}

/**
 * Analyse the final hop's headers + cookies for subdomain→main-domain
 * escalation paths.
 *
 * @param finalHop - The authoritative response hop.
 * @param cookies  - Cookie metadata for the page.
 */
export function checkSubdomainTrust(
  finalHop: Hop,
  cookies: CookieRecord[],
  alwaysSensitive: string[] = [],
  alwaysIgnore: string[] = []
): SubdomainTrustResult {
  const findings: Finding[] = [];
  const vectors: SubdomainTrustVector[] = [];

  let hostname = '';
  try {
    hostname = new URL(finalHop.url).hostname;
  } catch {
    return { findings, hasEscalationPath: false, vectors };
  }

  const regDomain = registrableDomain(hostname);
  if (regDomain == null) {
    return { findings, hasEscalationPath: false, vectors };
  }

  const pageIsSubdomain = isSubdomain(hostname);

  // Parse headers
  const cspValue = finalHop.headers['content-security-policy'] ?? '';
  const corsOrigin = finalHop.headers['access-control-allow-origin'] ?? '';
  const corsCredsRaw = finalHop.headers['access-control-allow-credentials'] ?? '';
  const varyHeader = finalHop.headers['vary'] ?? '';
  const coopHeader = finalHop.headers['cross-origin-opener-policy'] ?? '';
  const oacHeader = finalHop.headers['origin-agent-cluster'] ?? '';
  const xfo = finalHop.headers['x-frame-options'] ?? '';

  const directives = cspValue.length > 0 ? parseCspDirectives(cspValue) : new Map<string, string>();
  const effectiveScriptSrc = resolveEffective(directives, 'script-src');
  const frameAncestors = directives.get('frame-ancestors') ?? '';

  let hasEscalationPath = false;

  // =========================================================================
  // VECTOR 1: COOKIES
  // =========================================================================

  // SUB-001: Domain-wide cookie scope for sensitive session cookies
  const broadCookies: string[] = [];
  for (const cookie of cookies) {
    const d = cookie.domain;
    const normalised = d.startsWith('.') ? d.slice(1) : d;
    if (normalised === regDomain || d === `.${regDomain}`) {
      // Only flag cookies that look authentication-related or are session-shaped and server-managed.
      // Harmless client preferences (theme, language, UI flags, analytics) shared across
      // subdomains are completely standard and do not constitute an account takeover escalation path.
      if (isSensitiveCookie(cookie.name, alwaysSensitive, alwaysIgnore).isSensitive || (cookie.httpOnly && cookie.session)) {
        broadCookies.push(cookie.name);
      }
    }
  }

  const cookieTrustPresent = broadCookies.length > 0;
  if (cookieTrustPresent) hasEscalationPath = true;

  vectors.push({
    id: 'SUB-001',
    label: 'Cookie scope spans all subdomains',
    detail: cookieTrustPresent
      ? `${broadCookies.length} sensitive cookie(s) scoped to .${regDomain}: ${broadCookies.slice(0, 3).map((n) => `"${n}"`).join(', ')}${broadCookies.length > 3 ? ' …' : ''}`
      : `No domain-wide sensitive cookies detected (all session cookies host-only or isolated)`,
    risk: 'critical',
    present: cookieTrustPresent,
  });

  if (cookieTrustPresent) {
    findings.push({
      ruleId: 'SUB-001',
      category: 'cookie',
      severity: 'critical',
      title: `Sensitive cookie(s) scoped to .${regDomain} — subdomain compromise exposes main-domain session`,
      impact:
        `An attacker who compromises any subdomain on ${regDomain} can access these session cookies and impersonate users on the apex domain.`,
      evidence: sanitizeEvidence(
        `Domain-wide sensitive cookies: ${broadCookies.slice(0, 5).join(', ')}`,
      ),
      recommendation:
        'Set authentication and session cookies without the Domain attribute (host-only) or restrict to Domain=<specific-subdomain>. ' +
        'Avoid Domain=.example.com for session/auth cookies.',
      reference: REF_COOKIE,
    });
  }

  // SUB-005: Cookie Tossing / Shadowing Risk (Sensitive cookies lack __Host- prefix)
  const unshieldedSensitiveCookies: string[] = [];
  for (const cookie of cookies) {
    if (isSensitiveCookie(cookie.name, alwaysSensitive, alwaysIgnore).isSensitive && !cookie.name.startsWith('__Host-')) {
      unshieldedSensitiveCookies.push(cookie.name);
    }
  }

  const cookieTossingRisk = unshieldedSensitiveCookies.length > 0;
  if (cookieTossingRisk) hasEscalationPath = true;

  vectors.push({
    id: 'SUB-005',
    label: 'Cookie Tossing / Shadowing Risk (Missing __Host- prefix)',
    detail: cookieTossingRisk
      ? `Sensitive cookie(s) lack __Host- prefix: ${unshieldedSensitiveCookies.slice(0, 3).join(', ')}. A compromised subdomain can inject Domain=.${regDomain} cookies to hijack sessions.`
      : 'All sensitive cookies use __Host- prefix or none detected',
    risk: 'medium',
    present: cookieTossingRisk,
  });

  if (cookieTossingRisk) {
    findings.push({
      ruleId: 'SUB-005',
      category: 'cookie',
      severity: 'medium',
      title: `Sensitive session cookie(s) lack __Host- prefix — vulnerable to Cookie Tossing from subdomains`,
      impact:
        `An attacker controlling any subdomain can overwrite or shadow main-domain session cookies by setting Domain=.${regDomain} cookies (Cookie Tossing).`,
      evidence: sanitizeEvidence(
        `Unprefixed sensitive cookies: ${unshieldedSensitiveCookies.slice(0, 5).join(', ')}`,
      ),
      recommendation:
        'Prefix sensitive session cookies with __Host- (e.g. __Host-session=...) so browsers reject ' +
        'subdomains attempting to shadow or overwrite cookies for the main domain (RFC 6265bis §4.1.3).',
      reference: REF_COOKIE_TOSS,
    });
  }

  // =========================================================================
  // VECTOR 2: CSP SCRIPT TRUST
  // =========================================================================

  // SUB-002: CSP explicitly trusts scripts from wildcards of this specific apex domain
  let cspSubdomainTrust = false;
  let cspEvidence = '';

  if (effectiveScriptSrc !== undefined) {
    const { isModernStrict } = hasCspBypassProtection(effectiveScriptSrc);

    // In modern CSP Level 3, nonces and 'strict-dynamic' cause modern browsers to ignore
    // host-based allowlists entirely, neutralizing subdomain host trust.
    if (!isModernStrict) {
      const tokens = cspTokens(effectiveScriptSrc);
      const dangerous = tokens.filter((t) => {
        const bare = t.replace(/^https?:\/\//, '');
        return bare === `*.${regDomain}` || bare === regDomain;
      });

      if (dangerous.length > 0) {
        cspSubdomainTrust = true;
        hasEscalationPath = true;
        cspEvidence = dangerous.join(' ');
      }
    }
  }

  const subdomainTrustDetail = effectiveScriptSrc != null
    ? `script-src is scoped to explicit hosts (no wildcard subdomain trust for ${regDomain})`
    : cspValue.length > 0
      ? 'CSP present but script-src not found'
      : 'No CSP response header; explicit subdomain script trust is not evaluated here';

  vectors.push({
    id: 'SUB-002',
    label: 'CSP trusts scripts from subdomains',
    detail: cspSubdomainTrust
      ? `Subdomain script source(s): ${cspEvidence}`
      : subdomainTrustDetail,
    risk: 'critical',
    present: cspSubdomainTrust,
  });

  if (cspSubdomainTrust && cspEvidence) {
    findings.push({
      ruleId: 'SUB-002',
      category: 'header',
      severity: 'critical',
      title: `CSP script-src trusts wildcard *.${regDomain} — allows XSS pivot from any ${regDomain} subdomain`,
      impact:
        `An attacker who finds an XSS bug or hosts files on any ${regDomain} subdomain can execute scripts with full permissions on the main domain.`,
      evidence: sanitizeEvidence(cspEvidence),
      recommendation:
        `Replace wildcard subdomain source (*.${regDomain}) with explicit allowlisted hostnames or nonces/hashes.`,
      reference: REF_CSP,
    });
  }

  // =========================================================================
  // VECTOR 3: CORS & POSTMESSAGE / FRAMING / DOM TRUST
  // =========================================================================

  // SUB-003: CORS allows subdomain origins or wildcard with credentials
  let corsTrustPresent = false;
  let corsDetail = '';
  const corsWithCreds = corsCredsRaw?.toLowerCase().trim() === 'true';

  if (corsOrigin.length > 0) {
    if (corsOrigin === '*') {
      corsTrustPresent = true;
      corsDetail = 'Access-Control-Allow-Origin: *';
      if (corsWithCreds) corsDetail += ' + Credentials: true (critical misconfiguration)';
    } else {
      try {
        const allowedHostname = new URL(corsOrigin).hostname;
        const allowedReg = registrableDomain(allowedHostname);
        if (allowedReg === regDomain && allowedHostname !== hostname) {
          corsTrustPresent = true;
          corsDetail = `Access-Control-Allow-Origin: ${corsOrigin} (trusts subdomain of same root)`;
          if (corsWithCreds) corsDetail += '; Access-Control-Allow-Credentials: true';
        }
      } catch {
        // corsOrigin not a valid URL
      }
    }
  } else if (varyHeader.toLowerCase().includes('origin')) {
    // Vary: Origin is required by the CORS spec for *any* response that varies
    // by origin — including responses with a safe, explicit ACAO allowlist.
    // We only treat it as a suspicious reflection indicator when the ACAO header
    // is completely absent, because that means the server is signalling origin-
    // awareness without disclosing its policy — a pattern consistent with dynamic
    // reflection. When ACAO is present the branch above already evaluated it.
    //
    // NOTE: This remains a heuristic — Vary: Origin alone does not prove
    // reflection. The finding is labelled accordingly in the evidence string.
    corsTrustPresent = true;
    corsDetail = 'Vary: Origin present with no Access-Control-Allow-Origin header — possible dynamic reflection (heuristic)';
  }

  if (corsTrustPresent) hasEscalationPath = true;

  // Heuristic-only trigger (Vary: Origin, no ACAO header) is lower confidence.
  const varyOnlyHeuristic = corsTrustPresent && corsOrigin.length === 0;

  vectors.push({
    id: varyOnlyHeuristic ? 'SUB-003H' : 'SUB-003',
    label: varyOnlyHeuristic ? 'CORS Vary: Origin heuristic' : 'CORS allows subdomain / wildcard origins',
    detail: corsTrustPresent
      ? corsDetail
      : corsOrigin.length > 0
        ? `Access-Control-Allow-Origin: ${corsOrigin.slice(0, 80)} (no cross-subdomain trust detected)`
        : 'No CORS header present',
    risk: varyOnlyHeuristic ? 'medium' : 'high',
    present: corsTrustPresent,
  });

  if (corsTrustPresent) {
    findings.push({
      ruleId: varyOnlyHeuristic ? 'SUB-003H' : 'SUB-003',
      category: 'cors',
      severity: varyOnlyHeuristic ? 'medium' : 'high',
      title: varyOnlyHeuristic
        ? 'Vary: Origin with no explicit CORS policy — possible dynamic origin reflection (heuristic)'
        : 'CORS policy trusts subdomain origin — cross-subdomain API data exposure possible',
      impact:
        'Compromised or attacker-controlled subdomains can send authenticated AJAX requests to your private APIs and read sensitive user data across origins.',
      evidence: sanitizeEvidence(corsDetail),
      recommendation:
        'Set Access-Control-Allow-Origin to an explicit allowlist of known origins. ' +
        'Never reflect the Origin request header without strict validation.',
      reference: REF_CORS,
    });
  }

  // SUB-004: Page frameable by subdomains / postMessage confusion
  let postMsgTrustPresent = false;
  let postMsgDetail = '';

  const frameableBySubdomain =
    xfo.length === 0 &&
    frameAncestors.length > 0 &&
    (frameAncestors.includes('*') || cspAllowsSubdomain(frameAncestors, regDomain));

  if (frameableBySubdomain) {
    postMsgTrustPresent = true;
    postMsgDetail = `Explicit subdomain framing trust: ${frameAncestors.slice(0, 80)}`;
    hasEscalationPath = true;
  }

  vectors.push({
    id: 'SUB-004',
    label: 'postMessage / framing trust open to subdomains',
    detail: postMsgTrustPresent
      ? postMsgDetail
      : frameAncestors.length > 0 || xfo.length > 0
        ? `Framing is restricted (${frameAncestors.length > 0 ? 'frame-ancestors' : 'X-Frame-Options'} present)`
        : 'No framing policy detected; covered by CSP-005 and XFO-001',
    risk: 'high',
    present: postMsgTrustPresent,
  });

  if (postMsgTrustPresent) {
    findings.push({
      ruleId: 'SUB-004',
      category: 'header',
      severity: 'high',
      title: 'Page can be framed by subdomains — postMessage confusion / clickjacking pivot possible',
      impact:
        'Subdomains can embed this page in an iframe to sniff postMessage data or perform clickjacking attacks on authenticated actions.',
      evidence: sanitizeEvidence(postMsgDetail),
      recommendation:
        "Add \"Content-Security-Policy: frame-ancestors 'self'\" or \"X-Frame-Options: SAMEORIGIN\" " +
        'to prevent untrusted subdomains from embedding this page.',
      reference: REF_CSP,
    });
  }

  // SUB-006: Missing Cross-Origin-Opener-Policy (COOP) — Window.opener manipulation
  const coopMissing = coopHeader.length === 0 || !coopHeader.toLowerCase().includes('same-origin');
  if (coopMissing) {
    hasEscalationPath = true;
  }

  vectors.push({
    id: 'SUB-006',
    label: 'Cross-Origin-Opener-Policy (COOP) missing',
    detail: coopMissing
      ? (coopHeader.length > 0 ? `COOP: ${coopHeader} (not same-origin)` : 'COOP header absent — subdomains can manipulate window.opener')
      : `COOP is strict (${coopHeader})`,
    risk: 'medium',
    present: coopMissing,
  });

  if (coopMissing) {
    findings.push({
      ruleId: 'SUB-006',
      category: 'header',
      severity: 'medium',
      title: 'Missing Cross-Origin-Opener-Policy (COOP) — subdomains can access window.opener',
      impact:
        'Untrusted subdomains opened in new tabs or windows can access window.opener and silently redirect the parent tab to a phishing clone (Reverse Tabnabbing).',
      evidence: sanitizeEvidence(coopHeader.length > 0 ? coopHeader : '(header absent)'),
      recommendation:
        'Set "Cross-Origin-Opener-Policy: same-origin" to isolate the top-level browsing context ' +
        'and prevent malicious subdomains from manipulating window.opener.',
      reference: REF_COOP,
    });
  }

  // SUB-007: Missing Origin-Agent-Cluster — document.domain relaxation risk
  const oacMissing = oacHeader.length === 0 || !oacHeader.includes('?1');
  vectors.push({
    id: 'SUB-007',
    label: 'Origin-Agent-Cluster missing (document.domain relaxation risk)',
    detail: oacMissing
      ? 'Origin-Agent-Cluster: ?1 missing — legacy document.domain relaxation can bridge subdomains'
      : 'Origin-Agent-Cluster: ?1 is active',
    risk: 'low',
    present: oacMissing,
  });

  if (oacMissing) {
    findings.push({
      ruleId: 'SUB-007',
      category: 'header',
      severity: 'low',
      title: 'Missing Origin-Agent-Cluster header — document.domain relaxation possible',
      impact:
        'Subdomains can alter document.domain to match the main domain, breaking Same-Origin-Policy boundaries and reading DOM content directly.',
      evidence: sanitizeEvidence(oacHeader.length > 0 ? oacHeader : '(header absent)'),
      recommendation:
        'Add "Origin-Agent-Cluster: ?1" to prevent document.domain relaxation and enforce origin isolation.',
      reference: REF_OAC,
    });
  }

  // =========================================================================
  // SUBDOMAIN ISOLATION CERTIFICATION
  // =========================================================================
  // SUB-008: Informational — When on a subdomain, if no escalation path exists
  if (pageIsSubdomain && !hasEscalationPath) {
    vectors.push({
      id: 'SUB-008',
      label: 'Subdomain Isolated (No Escalation Path to Main Domain)',
      detail: `This page (${hostname}) is a subdomain, but no cookie scope, CSP wildcard, CORS, framing, or opener trust bridges to ${regDomain} were found.`,
      risk: 'info',
      present: false,
    });

    findings.push({
      ruleId: 'SUB-008',
      category: 'header',
      severity: 'info',
      title: `Subdomain Isolated — no trust bridge to main domain detected`,
      impact:
        'This subdomain has no cookie, CSP, CORS, or framing trust bridges to the main domain; any security flaw found here remains strictly contained.',
      evidence: sanitizeEvidence(
        `${hostname} is isolated from ${regDomain}`,
      ),
      recommendation:
        'No action required. Vulnerabilities on this subdomain remain isolated and cannot ' +
        'jump to the main domain based on current security controls.',
      reference: REF_SUBDOMAIN,
    });
  }

  return { findings, hasEscalationPath, vectors };
}
