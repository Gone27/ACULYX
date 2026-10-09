/** Rule engine — orchestrates all header and cookie security rules. */

import type {
  CookieRecord,
  Finding,
  Grade,
  Hop,
  ScoreBreakdown,
  SubdomainTrustAnalysis,
} from '../shared/types';
import type { ScopeEngine, ScopeProfile } from '../shared/scope';
import { ScopeEngine as ConcreteScopeEngine } from '../shared/scope/engine';

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

export interface RuleInput {
  hops: Hop[];
  cookies: CookieRecord[];
  origin: string;
  metaCspFound?: boolean;
  captureFindings?: Finding[];
  cookieSettings?: {
    alwaysSensitive: string[];
    alwaysIgnore: string[];
  };
  /** Optional ScopeEngine instance to evaluate scopeStatus on findings */
  scopeEngine?: ScopeEngine | undefined;
  /** Optional ScopeProfile to instantiate a ScopeEngine */
  scopeProfile?: ScopeProfile | undefined;
}

export interface RuleOutput {
  findings: Finding[];
  score: number;
  grade: Grade;
  qualityScore: number;
  qualityGrade: Grade;
  breakdown: ScoreBreakdown[];
  scoreVersion: string;
  subdomainTrust: SubdomainTrustAnalysis;
}

export function runRules(input: RuleInput): RuleOutput {
  const { hops } = input;
  const emptySubdomainTrust: SubdomainTrustAnalysis = { hasEscalationPath: false, vectors: [] };

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

  const finalHop = hops[hops.length - 1];
  if (finalHop === undefined) {
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

  const scopeEngine =
    input.scopeEngine !== undefined
      ? input.scopeEngine
      : input.scopeProfile !== undefined
        ? new ConcreteScopeEngine(input.scopeProfile)
        : undefined;

  const findings: Finding[] = [];
  const redirectFindings = detectRedirectDegradation(hops).map((f) => ({
    ...f,
    provenance: 'redirect' as const,
    outcome: 'partial-coverage' as const,
    limitations: ['Observed across redirect hops; intermediate hops may have different policy boundaries.'],
    scopeStatus: scopeEngine !== undefined ? scopeEngine.classify(f.sourceUrl ?? finalHop.url) : undefined,
  }));
  findings.push(...redirectFindings);
  findings.push(...(input.captureFindings ?? []));

  const headerFindings: Finding[] = [];
  headerFindings.push(...checkDuplicateHeaders(finalHop));
  headerFindings.push(...checkHsts(finalHop));

  const { findings: cspFindings, directives } = checkCsp(finalHop, input.metaCspFound);
  headerFindings.push(...cspFindings);

  headerFindings.push(...checkXfo(finalHop, directives));
  headerFindings.push(...checkXcto(finalHop));
  headerFindings.push(...checkReferrer(finalHop));
  headerFindings.push(...checkIsolationHeaders(finalHop));
  headerFindings.push(...checkReportingHeaders(finalHop));
  headerFindings.push(...checkPolicyHardeningHeaders(finalHop));
  headerFindings.push(...checkCors(finalHop));
  headerFindings.push(...checkDeprecated(finalHop));
  headerFindings.push(...checkInfoLeak(finalHop));
  headerFindings.push(...checkCacheCookie(
    finalHop,
    input.cookieSettings?.alwaysSensitive,
    input.cookieSettings?.alwaysIgnore,
  ));

  findings.push(...headerFindings.map((f) => ({ ...f, provenance: f.provenance ?? ('response-header' as const) })));

  const isHttps = finalHop.url.startsWith('https://');
  const cookieFindings = checkCookies(
    input.cookies,
    isHttps,
    input.cookieSettings?.alwaysSensitive,
    input.cookieSettings?.alwaysIgnore,
  );
  findings.push(...cookieFindings.map((f) => ({ ...f, provenance: f.provenance ?? ('cookie-metadata' as const) })));

  const subdomainResult = checkSubdomainTrust(
    finalHop,
    input.cookies,
    input.cookieSettings?.alwaysSensitive,
    input.cookieSettings?.alwaysIgnore,
  );
  findings.push(...subdomainResult.findings);

  const heuristicRules = new Set([
    'LEAK-001', 'CSP-009', 'CSP-008', 'CSP-META-001',
    'SUB-001', 'SUB-002', 'SUB-003H', 'SUB-004', 'SUB-005',
    'SUB-006', 'SUB-007', 'SUB-008',
  ]);

  const findingsWithSource: Finding[] = findings.map((finding) => {
    const isHeuristic =
      heuristicRules.has(finding.ruleId) ||
      finding.title.includes('(name-based heuristic)');
    const isPass = finding.severity === 'info' || finding.severity === 'pass';
    const targetUrl = finding.sourceUrl ?? finalHop.url;
    return {
      ...finding,
      sourceUrl: targetUrl,
      provenance: finding.provenance ?? 'response-header',
      confidence:
        finding.confidence ?? (isHeuristic ? 'heuristic' : 'deterministic'),
      outcome:
        finding.outcome ?? (isPass ? 'pass' : (finalHop.fromCache ? 'partial-coverage' : 'fail')),
      limitations: finding.limitations ?? (finalHop.fromCache
        ? ['Response served from browser cache; header presence unverified.']
        : ['Passive analysis only; no active probes or exploit verification executed.']),
      scopeStatus: finding.scopeStatus ?? (scopeEngine !== undefined ? scopeEngine.classify(targetUrl) : undefined),
    };
  });

  const { score, grade, qualityScore, qualityGrade, breakdown, scoreVersion } = computeScore(
    findingsWithSource,
    finalHop.fromCache,
  );

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
  optionsOrSettings?:
    | { alwaysSensitive?: string[]; alwaysIgnore?: string[]; scopeEngine?: ScopeEngine; scopeProfile?: ScopeProfile }
    | { alwaysSensitive: string[]; alwaysIgnore: string[] },
): Finding[] {
  const hopLike = apiHop as unknown as Hop;
  const findings: Finding[] = [];

  const sensitive =
    optionsOrSettings !== undefined && 'alwaysSensitive' in optionsOrSettings
      ? optionsOrSettings.alwaysSensitive
      : undefined;
  const ignored =
    optionsOrSettings !== undefined && 'alwaysIgnore' in optionsOrSettings
      ? optionsOrSettings.alwaysIgnore
      : undefined;
  const scopeEngine =
    optionsOrSettings !== undefined && 'scopeEngine' in optionsOrSettings && optionsOrSettings.scopeEngine !== undefined
      ? optionsOrSettings.scopeEngine
      : optionsOrSettings !== undefined && 'scopeProfile' in optionsOrSettings && optionsOrSettings.scopeProfile !== undefined
        ? new ConcreteScopeEngine(optionsOrSettings.scopeProfile)
        : undefined;

  findings.push(...checkCors(hopLike));
  findings.push(...checkXcto(hopLike));
  findings.push(...checkInfoLeak(hopLike));
  findings.push(...checkCacheCookie(
    hopLike,
    sensitive,
    ignored,
  ));

  return findings.map((f) => ({
    ...f,
    sourceUrl: apiHop.url,
    confidence: f.confidence ?? (f.ruleId === 'LEAK-001' ? 'heuristic' : 'deterministic'),
    provenance: 'response-header',
    outcome: f.outcome ?? (f.severity === 'info' || f.severity === 'pass' ? 'pass' : 'fail'),
    limitations: f.limitations ?? [
      'Passive analysis of captured API response; no active probes sent.',
    ],
    scopeStatus: f.scopeStatus ?? (scopeEngine !== undefined ? scopeEngine.classify(apiHop.url) : undefined),
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
      impact: 'A protection present on an earlier redirect response is absent from the next response.',
      evidence: `${safeHopLabel(previous)} -> ${safeHopLabel(current)}: ${removed.join(', ')}`,
      recommendation: 'Review the redirect chain and configure the destination response to send required protections.',
      reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections',
      sourceUrl: current.url,
    });
  }
  return findings;
}
