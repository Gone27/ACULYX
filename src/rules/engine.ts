/**
 * Rule engine — orchestrates all header and cookie security rules.
 *
 * This is the single entry-point called by the background service worker.
 * It accepts raw capture data and returns a fully-evaluated RuleOutput that
 * the popup can render directly.
 *
 * All functions invoked here are pure — no browser APIs are used.
 */

import type {
  CookieRecord,
  Finding,
  Grade,
  Hop,
  ScoreBreakdown,
  SubdomainTrustAnalysis,
} from '../shared/types';

import { checkHsts } from './headers/hsts';
import { checkCsp } from './headers/csp';
import { checkXfo } from './headers/xfo';
import { checkXcto } from './headers/xcto';
import { checkReferrer } from './headers/referrer';
import { checkDeprecated } from './headers/deprecated';
import { checkInfoLeak } from './headers/info-leak';
import { checkCacheCookie } from './headers/cache-cookie';
import { checkCookies } from './cookies/cookies';
import { checkSubdomainTrust } from './headers/subdomain-trust';
import { checkIsolationHeaders } from './headers/isolation';
import { checkReportingHeaders } from './headers/reporting';
import { checkPolicyHardeningHeaders } from './headers/policy-hardening';
import { checkCors } from './headers/cors';
import { computeScore } from './scoring';
import { checkDuplicateHeaders } from './utils';

// ---------------------------------------------------------------------------
// Public interfaces
// ---------------------------------------------------------------------------

/** Data fed into the rule engine from the capture layer. */
export interface RuleInput {
  /** All hops in the redirect chain; the final hop is used for header checks. */
  hops: Hop[];
  /** Cookies associated with the page at evaluation time. */
  cookies: CookieRecord[];
  /** The effective origin of the final page (e.g. 'https://example.com'). */
  origin: string;
  /** A meta CSP was detected in the document when no response header exists. */
  metaCspFound?: boolean;
  /** Response-correlation diagnostics that do not originate in static rules. */
  captureFindings?: Finding[];
  /** Optional cookie overrides from user settings. */
  cookieSettings?: {
    alwaysSensitive: string[];
    alwaysIgnore: string[];
  };
}

/** Aggregated result returned to the popup / storage layer. */
export interface RuleOutput {
  findings: Finding[];
  score: number;
  grade: Grade;
  qualityScore: number;
  qualityGrade: Grade;
  breakdown: ScoreBreakdown[];
  scoreVersion: string;
  /** Subdomain escalation analysis (always populated, may have no vectors). */
  subdomainTrust: SubdomainTrustAnalysis;
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/**
 * Run all security rules against captured hop and cookie data.
 *
 * Execution order:
 *  1. checkHsts         — transport security
 *  2. checkCsp          — content security policy (also yields directives map)
 *  3. checkXfo          — framing protection (uses CSP directives)
 *  4. checkXcto         — MIME-type sniffing
 *  5. checkReferrer     — referrer policy
 *  6. checkDeprecated   — deprecated headers
 *  7. checkInfoLeak     — information leakage
 *  8. checkCacheCookie  — cache control on cookie-setting responses
 *
 * @param input - Captured hops, cookies, and origin.
 * @returns Aggregated findings, score, grade, breakdown, and score version.
 */
export function runRules(input: RuleInput): RuleOutput {
  const { hops } = input;

  const emptySubdomainTrust: SubdomainTrustAnalysis = { hasEscalationPath: false, vectors: [] };

  // Guard: nothing to evaluate when no hops were captured.
  if (hops.length === 0) {
    return {
      findings: [],
      score: 100,
      grade: 'A',
      qualityScore: 100,
      qualityGrade: 'A',
      breakdown: [],
      scoreVersion: '',
      subdomainTrust: emptySubdomainTrust,
    };
  }

  // All header checks operate on the final hop (the authoritative response).
  const finalHop = hops[hops.length - 1];

  // noUncheckedIndexedAccess: array access returns T | undefined even when
  // length > 0. The guard above ensures we only reach here with hops.length > 0,
  // so finalHop is always defined. Cast with a non-null assertion here.
  if (finalHop === undefined) {
    return { findings: [], score: 100, grade: 'A', qualityScore: 100, qualityGrade: 'A', breakdown: [], scoreVersion: '', subdomainTrust: emptySubdomainTrust };
  }

  const findings: Finding[] = [];

  const redirectFindings = detectRedirectDegradation(hops);
  findings.push(...redirectFindings);
  findings.push(...(input.captureFindings ?? []));
  findings.push(...checkDuplicateHeaders(finalHop));

  // 1. HSTS
  findings.push(...checkHsts(finalHop));

  // 2. CSP — also returns the parsed directives map for downstream rules.
  const { findings: cspFindings, directives } = checkCsp(finalHop, input.metaCspFound);
  findings.push(...cspFindings);

  // 3. XFO — needs the CSP directives to decide if frame-ancestors supersedes it.
  findings.push(...checkXfo(finalHop, directives));

  // 4. X-Content-Type-Options
  findings.push(...checkXcto(finalHop));

  // 5. Referrer-Policy
  findings.push(...checkReferrer(finalHop));

  findings.push(...checkIsolationHeaders(finalHop));
  findings.push(...checkReportingHeaders(finalHop));
  findings.push(...checkPolicyHardeningHeaders(finalHop));
  findings.push(...checkCors(finalHop));

  // 6. Deprecated headers (X-XSS-Protection, etc.)
  findings.push(...checkDeprecated(finalHop));

  // 7. Information leakage via server/framework version headers
  findings.push(...checkInfoLeak(finalHop));

  // 8. Cache-Control on responses that set cookies
  findings.push(...checkCacheCookie(
    finalHop,
    input.cookieSettings?.alwaysSensitive,
    input.cookieSettings?.alwaysIgnore
  ));

  // 9. Cookie attribute rules (Secure, HttpOnly, SameSite, prefix compliance)
  const isHttps = finalHop.url.startsWith('https://');
  findings.push(...checkCookies(
    input.cookies,
    isHttps,
    input.cookieSettings?.alwaysSensitive,
    input.cookieSettings?.alwaysIgnore
  ));

  // 10. Subdomain → main-domain escalation trust analysis
  const subdomainResult = checkSubdomainTrust(
    finalHop,
    input.cookies,
    input.cookieSettings?.alwaysSensitive,
    input.cookieSettings?.alwaysIgnore
  );
  findings.push(...subdomainResult.findings);

  const findingsWithSource = findings.map((finding) => ({
    ...finding,
    sourceUrl: finding.sourceUrl ?? finalHop.url,
  }));

  // Compute the aggregate score and grade, taking caching into account.
  const { score, grade, qualityScore, qualityGrade, breakdown, scoreVersion } = computeScore(findingsWithSource, finalHop.fromCache);

  return {
    findings: findingsWithSource,
    score,
    grade,
    qualityScore,
    qualityGrade,
    breakdown,
    scoreVersion,
    subdomainTrust: {
      hasEscalationPath: subdomainResult.hasEscalationPath,
      vectors: subdomainResult.vectors,
    },
  };
}


export function runApiRules(
  apiHop: import('../shared/types').ApiHop,
  cookieSettings?: { alwaysSensitive: string[]; alwaysIgnore: string[] }
): Finding[] {
  const hopLike = apiHop as unknown as Hop;
  const findings: Finding[] = [];

  // API runs only a subset of rules that make sense for XHR/Fetch endpoints.
  findings.push(...checkCors(hopLike));
  findings.push(...checkXcto(hopLike));
  findings.push(...checkInfoLeak(hopLike));
  findings.push(...checkCacheCookie(
    hopLike,
    cookieSettings?.alwaysSensitive,
    cookieSettings?.alwaysIgnore
  ));
  
  // Tag all findings with the specific API source URL
  return findings.map(f => ({
    ...f,
    sourceUrl: apiHop.url
  }));
}

const REDIRECT_SECURITY_HEADERS = [
  'content-security-policy',
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
  'cross-origin-embedder-policy',
] as const;

function safeHopLabel(hop: Hop): string {
  try {
    const url = new URL(hop.url);
    return `${url.origin}${url.pathname}`;
  } catch {
    return hop.url.slice(0, 160);
  }
}

function detectRedirectDegradation(hops: Hop[]): Finding[] {
  const findings: Finding[] = [];
  for (let index = 1; index < hops.length; index += 1) {
    const previous = hops[index - 1];
    const current = hops[index];
    if (!previous || !current) continue;

    const removed = REDIRECT_SECURITY_HEADERS.filter((header) => {
      const previousValue = previous.headers[header]?.trim();
      const currentValue = current.headers[header]?.trim();
      return previousValue !== undefined && previousValue.length > 0
        && (currentValue === undefined || currentValue.length === 0);
    });
    if (removed.length === 0) continue;

    findings.push({
      ruleId: 'REDIR-001',
      category: 'header',
      severity: 'info',
      title: `Redirect response drops ${removed.length} previously present security header(s)`,
      impact: 'A protection present on an earlier redirect response is absent from the next response; review whether the destination needs its own policy.',
      evidence: `${safeHopLabel(previous)} -> ${safeHopLabel(current)}: ${removed.join(', ')}`,
      recommendation: 'Review the redirect chain and configure the destination response to send the protections required for that origin. Header policies do not automatically carry across responses.',
      reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections',
      sourceUrl: current.url,
    });
  }
  return findings;
}
