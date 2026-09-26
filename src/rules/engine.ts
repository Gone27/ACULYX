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
import { computeScore } from './scoring';

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
}

/** Aggregated result returned to the popup / storage layer. */
export interface RuleOutput {
  findings: Finding[];
  score: number;
  grade: Grade;
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
    return { findings: [], score: 100, grade: 'A', breakdown: [], scoreVersion: '', subdomainTrust: emptySubdomainTrust };
  }

  const findings: Finding[] = [];

  // 1. HSTS
  findings.push(...checkHsts(finalHop));

  // 2. CSP — also returns the parsed directives map for downstream rules.
  const { findings: cspFindings, directives } = checkCsp(finalHop);
  findings.push(...cspFindings);

  // 3. XFO — needs the CSP directives to decide if frame-ancestors supersedes it.
  findings.push(...checkXfo(finalHop, directives));

  // 4. X-Content-Type-Options
  findings.push(...checkXcto(finalHop));

  // 5. Referrer-Policy
  findings.push(...checkReferrer(finalHop));

  // 6. Deprecated headers (X-XSS-Protection, etc.)
  findings.push(...checkDeprecated(finalHop));

  // 7. Information leakage via server/framework version headers
  findings.push(...checkInfoLeak(finalHop));

  // 8. Cache-Control on responses that set cookies
  findings.push(...checkCacheCookie(finalHop));

  // 9. Cookie attribute rules (Secure, HttpOnly, SameSite, prefix compliance)
  const isHttps = finalHop.url.startsWith('https://');
  findings.push(...checkCookies(input.cookies, isHttps));

  // 10. Subdomain → main-domain escalation trust analysis
  const subdomainResult = checkSubdomainTrust(finalHop, input.cookies);
  findings.push(...subdomainResult.findings);

  const findingsWithSource = findings.map((finding) => ({
    ...finding,
    sourceUrl: finalHop.url,
  }));

  // Compute the aggregate score and grade, taking caching into account.
  const { score, grade, breakdown, scoreVersion } = computeScore(findingsWithSource, finalHop.fromCache);

  return {
    findings: findingsWithSource,
    score,
    grade,
    breakdown,
    scoreVersion,
    subdomainTrust: {
      hasEscalationPath: subdomainResult.hasEscalationPath,
      vectors: subdomainResult.vectors,
    },
  };
}
