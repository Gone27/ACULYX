import type {
  EvidenceStatus,
  LeadFacts,
  LeadVerdict,
  SecurityAssessment,
  VerdictCheck,
  VerdictCheckOutcome,
  VerdictStatus,
} from '../types';
import { redactAllSecrets } from '../../shared/reporting/report-builder';

const STATUSES = new Set<VerdictStatus>(['confirmed', 'likely', 'uncertain', 'informational', 'false_positive']);
const OUTCOMES = new Set<VerdictCheckOutcome>(['pass', 'fail', 'inconclusive']);
const EVIDENCE_STATUSES = new Set<EvidenceStatus>(['observed', 'reproduced', 'inconclusive']);
const SECURITY_ASSESSMENTS = new Set<SecurityAssessment>([
  'unreviewed',
  'likely',
  'confirmed',
  'informational',
  'false_positive',
]);
const SCOPE_STATUSES = new Set<LeadVerdict['scopeStatus']>(['in-scope', 'out-of-scope', 'unknown']);

function safeCap(v: unknown, maxLen: number): string {
  if (typeof v !== 'string') return '';
  return redactAllSecrets(v.slice(0, maxLen));
}

/** Facts are numbers/booleans (plus a short alg label). Anything else is dropped. */
export function sanitizeFacts(raw: unknown): LeadFacts | undefined {
  if (typeof raw !== 'object' || raw === null) return undefined;
  const r = raw as Record<string, unknown>;
  const out: LeadFacts = {};
  const bool = (k: keyof LeadFacts): void => {
    if (typeof r[k] === 'boolean') (out as Record<string, unknown>)[k] = r[k];
  };
  const num = (k: keyof LeadFacts, max: number): void => {
    const v = r[k];
    if (typeof v === 'number' && Number.isFinite(v)) (out as Record<string, unknown>)[k] = Math.max(0, Math.min(max, v));
  };
  bool('checksumValid');
  bool('exampleContext');
  bool('inComment');
  bool('jwtExpired');
  bool('jwtHasExp');
  num('entropyBits', 16);
  num('length', 100000);
  num('occurrences', 1000);
  if (typeof r.jwtAlg === 'string') out.jwtAlg = r.jwtAlg.slice(0, 16).replace(/[^\w-]/g, '');
  return Object.keys(out).length > 0 ? out : undefined;
}

export function sanitizeVerdict(raw: unknown): LeadVerdict | undefined {
  if (typeof raw !== 'object' || raw === null) return undefined;
  const r = raw as Record<string, unknown>;
  if (typeof r.status !== 'string' || !STATUSES.has(r.status as VerdictStatus)) return undefined;

  const checks: VerdictCheck[] = [];
  if (Array.isArray(r.checks)) {
    for (const c of r.checks.slice(0, 30)) {
      if (typeof c !== 'object' || c === null) continue;
      const cc = c as Record<string, unknown>;
      if (typeof cc.outcome !== 'string' || !OUTCOMES.has(cc.outcome as VerdictCheckOutcome)) continue;
      checks.push({
        id: safeCap(cc.id, 60),
        kind: cc.kind === 'active' ? 'active' : 'passive',
        outcome: cc.outcome as VerdictCheckOutcome,
        detail: safeCap(cc.detail, 400),
      });
    }
  }

  const rawScope = typeof r.scopeStatus === 'string' && SCOPE_STATUSES.has(r.scopeStatus as LeadVerdict['scopeStatus'])
    ? (r.scopeStatus as LeadVerdict['scopeStatus'])
    : 'unknown';

  const rawEvidence = typeof r.evidenceStatus === 'string' && EVIDENCE_STATUSES.has(r.evidenceStatus as EvidenceStatus)
    ? (r.evidenceStatus as EvidenceStatus)
    : 'inconclusive';

  let rawAssessment = typeof r.securityAssessment === 'string' && SECURITY_ASSESSMENTS.has(r.securityAssessment as SecurityAssessment)
    ? (r.securityAssessment as SecurityAssessment)
    : 'unreviewed';

  // Invariant: non-in-scope target can never have confirmed security assessment
  if (rawScope !== 'in-scope' && rawAssessment === 'confirmed') {
    rawAssessment = 'unreviewed';
  }

  return {
    status: r.status as VerdictStatus,
    evidenceStatus: rawEvidence,
    scopeStatus: rawScope,
    securityAssessment: rawAssessment,
    method: r.method === 'active' ? 'active' : 'passive',
    summary: safeCap(r.summary, 400),
    checks,
    missing: Array.isArray(r.missing)
      ? r.missing
          .filter((m): m is string => typeof m === 'string')
          .slice(0, 20)
          .map((m) => safeCap(m, 300))
      : [],
    verifiedAt: typeof r.verifiedAt === 'number' && Number.isFinite(r.verifiedAt) ? r.verifiedAt : Date.now(),
  };
}
