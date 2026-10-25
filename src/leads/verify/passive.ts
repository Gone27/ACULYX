/**
 * Passive lead verification ("self-check").
 *
 * Judges a lead using only what ACULYX has already observed (no network traffic) and returns an explicit,
 * explainable verdict across three distinct dimensions:
 *  1. evidenceStatus: observed / reproduced / inconclusive
 *  2. scopeStatus: in-scope / out-of-scope / unknown
 *  3. securityAssessment: unreviewed / likely / confirmed / informational / false_positive
 *
 * Design rules:
 *  1. CONFIRMED is hard to earn. It requires an in-scope target, an observed or reproduced condition
 *     with no outstanding preconditions (`lead.needs` empty) that demonstrates a vulnerability (not merely
 *     an observed configuration or hardening gap), is not info-level, not page-forgeable, and not contradicted.
 *  2. Targets with unknown or out-of-scope status CAN NEVER produce a report-ready confirmed vulnerability verdict.
 *     Scope warnings are never cleared from `missing` items when scope is unknown or out-of-scope.
 *  3. A lead is only called FALSE_POSITIVE when a check positively rules it out (public-by-design identifier,
 *     researcher triage dismissal). A locally-decoded expired JWT claim without signature verification is
 *     an unverified fact, not a false_positive veto. Missing information is never a false positive - it is UNCERTAIN.
 *  4. Credentials are never "confirmed" passively: liveness cannot be established without using the credential,
 *     which ACULYX never does. Best passive result for a secret is LIKELY.
 */
import type {
  EvidenceStatus,
  Lead,
  LeadVerdict,
  SecurityAssessment,
  VerdictCheck,
  VerdictCheckOutcome,
  VerdictStatus,
} from '../types';

/** Rules whose truth can ONLY be settled by an (optional, gated) active probe; passively they stay uncertain. */
export const ACTIVE_ONLY_RULES: ReadonlySet<string> = new Set(['MAP-001', 'CLD-001']);

const MIN_CONFIDENCE_FOR_CLAIM = 0.7;
const LOW_ENTROPY_BITS = 3.0;

type Rank = 'confirmed' | 'likely' | 'uncertain';
const RANK_ORDER: Record<Rank, number> = { uncertain: 0, likely: 1, confirmed: 2 };

function capRank(cur: Rank, max: Rank): Rank {
  return RANK_ORDER[cur] > RANK_ORDER[max] ? max : cur;
}

function isSecretLead(lead: Lead): boolean {
  return lead.family === 'F1' && (lead.ruleId.startsWith('SEC-') || lead.tags.includes('secret'));
}

export function verifyLeadPassive(lead: Lead, now: number = Date.now()): LeadVerdict {
  const checks: VerdictCheck[] = [];
  const missing: string[] = [...lead.needs];
  const scope = lead.scopeStatus ?? 'unknown';

  const add = (id: string, outcome: VerdictCheckOutcome, detail: string): void => {
    checks.push({ id, kind: 'passive', outcome, detail });
  };

  // 1. Evidence status
  let evidenceStatus: EvidenceStatus;
  if (lead.tags.includes('active-verified')) {
    evidenceStatus = 'reproduced';
  } else if (lead.tier === 'observed' && lead.confidence >= MIN_CONFIDENCE_FOR_CLAIM && !lead.tags.includes('page-reported')) {
    evidenceStatus = 'observed';
  } else {
    evidenceStatus = 'inconclusive';
  }

  // 2. Scope handling
  if (scope === 'out-of-scope') {
    add('scope', 'fail', 'Target is out of scope: not reportable even if technically valid.');
    missing.push('Out of scope - do not test further or report.');
  } else if (scope === 'unknown') {
    add('scope', 'inconclusive', 'Scope not declared; confirm the asset is covered by the program before reporting.');
    missing.push('Confirm the asset is in program scope.');
  } else {
    add('scope', 'pass', 'Target is in declared scope.');
  }

  const finish = (
    status: VerdictStatus,
    securityAssessment: SecurityAssessment,
    summary: string,
    miss: string[] = missing,
  ): LeadVerdict => {
    // Invariant: Non-in-scope targets can never be confirmed as report-ready vulnerabilities.
    let finalAssessment = securityAssessment;
    let finalStatus = status;

    if (scope !== 'in-scope') {
      if (finalAssessment === 'confirmed') {
        finalAssessment = 'unreviewed';
      }
      if (finalStatus === 'confirmed') {
        finalStatus = scope === 'unknown' ? 'likely' : 'uncertain';
      }
    }

    const uniqueMissing = [...new Set(miss)];
    let finalMissing: string[];
    if (finalStatus === 'false_positive') {
      finalMissing = [];
    } else if (finalStatus === 'confirmed' && scope === 'in-scope') {
      finalMissing = [];
    } else {
      // Scope invariant: Never clear missing items or erase the scope warning on an unknown or out-of-scope target
      finalMissing = uniqueMissing;
    }

    return {
      status: finalStatus,
      evidenceStatus,
      scopeStatus: scope,
      securityAssessment: finalAssessment,
      method: 'passive',
      summary,
      checks,
      missing: finalMissing,
      verifiedAt: now,
    };
  };

  // --- Hard vetoes (positive evidence the lead is NOT a bug) -------------------------------------------------
  if (lead.triageState === 'false_positive') {
    add('researcher-triage', 'fail', 'Researcher marked this lead as a false positive.');
    return finish('false_positive', 'false_positive', 'Dismissed by researcher.');
  }

  if (lead.ruleId === 'SEC-001-PUB' || lead.tags.includes('public-key')) {
    add('public-by-design', 'fail', 'Identifier is designed to ship to browsers (publishable / public token).');
    return finish('false_positive', 'false_positive', 'Not a vulnerability: public-by-design identifier.');
  }

  // --- Baseline from evidence tier + outstanding preconditions ----------------------------------------------
  let rank: Rank;
  if (lead.tier === 'observed') {
    rank = lead.needs.length === 0 ? 'confirmed' : 'likely';
    add(
      'evidence-tier',
      'pass',
      lead.needs.length === 0
        ? 'Condition directly observed with no outstanding preconditions.'
        : `Condition directly observed, but ${lead.needs.length} precondition(s) still unproven.`,
    );
  } else if (lead.tier === 'strong') {
    rank = 'likely';
    add('evidence-tier', 'pass', 'Strong (corroborated / inferred) evidence.');
  } else {
    rank = 'uncertain';
    add('evidence-tier', 'inconclusive', `Only ${lead.tier} evidence (heuristic signal).`);
  }

  if (lead.confidence < MIN_CONFIDENCE_FOR_CLAIM) {
    rank = capRank(rank, 'uncertain');
    add('detector-confidence', 'inconclusive', `Detector confidence ${lead.confidence.toFixed(2)} is below ${MIN_CONFIDENCE_FOR_CLAIM}.`);
  }

  // --- Already proven by an active probe at creation time (e.g. Hunter CORS probe) ---------------------------
  if (lead.tags.includes('active-verified') && lead.tier === 'observed') {
    add('active-probe', 'pass', 'Condition was reproduced by a scope-gated Hunter probe.');
    rank = 'confirmed';
  }

  // --- Source trust ------------------------------------------------------------------------------------------
  if (lead.tags.includes('page-reported')) {
    rank = capRank(rank, 'uncertain');
    add('source-trust', 'inconclusive', 'Reported by a page-controlled hook; the page can forge this event, so it can never be confirmed passively.');
    missing.push('Reproduce manually in DevTools; page-reported signals are forgeable.');
  }

  // --- Rule-family specific checks ---------------------------------------------------------------------------
  if (isSecretLead(lead)) {
    const f = lead.facts;
    if (f === undefined) {
      add('offline-facts', 'inconclusive', 'No offline facts (checksum / entropy / context) were captured for this value.');
    } else {
      if (f.checksumValid === true) {
        add('token-checksum', 'pass', 'Embedded token checksum is valid (format and checksum pattern match vendor specification).');
      } else if (f.checksumValid === false) {
        rank = capRank(rank, 'uncertain');
        add('token-checksum', 'fail', 'Embedded token checksum does not match vendor specification - likely a random look-alike or truncated token.');
      }
      if (f.entropyBits !== undefined && (f.length ?? 0) >= 16) {
        if (f.entropyBits < LOW_ENTROPY_BITS) {
          rank = capRank(rank, 'uncertain');
          add('entropy', 'fail', `Low randomness (${f.entropyBits} bits/char) for a ${f.length}-char secret.`);
        } else {
          add('entropy', 'pass', `Randomness looks key-like (${f.entropyBits} bits/char).`);
        }
      }
      if (f.exampleContext === true) {
        rank = capRank(rank, 'uncertain');
        add('example-context', 'fail', 'Surrounding text looks like documentation / sample / placeholder code.');
      }
      if (f.inComment === true) {
        add('in-comment', 'inconclusive', 'Value sits inside a comment (could be a stale or demo credential).');
      }
      if (f.jwtHasExp === false) {
        add('jwt-expiry', 'inconclusive', 'JWT has no "exp" claim; it may be long-lived.');
      } else if (f.jwtHasExp === true && f.jwtExpired === true) {
        // P1: Locally decoded exp is not proof of issuer signature or enforcement; record as an unverified fact, not false_positive veto
        add('jwt-expiry', 'inconclusive', 'JWT "exp" claim appears expired based on local system clock (signature verification and server enforcement unverified).');
        missing.push('Verify server-side signature validation and expiration enforcement before replay.');
      } else if (f.jwtHasExp === true && f.jwtExpired === false) {
        add('jwt-expiry', 'pass', 'JWT "exp" claim is in the future based on local system clock.');
      }
    }
    if (lead.tags.includes('candidate') || lead.tags.includes('unpaired')) {
      rank = capRank(rank, 'uncertain');
      add('completeness', 'inconclusive', 'Only half of a credential pair was seen.');
    }
    // Liveness can never be settled passively without unauthorized API replay.
    rank = capRank(rank, 'likely');
    add('liveness', 'inconclusive', 'Whether the credential is live cannot be established without using it, which ACULYX never does.');
    missing.push('Confirm the credential is live using a method the program explicitly permits (or ask the owner).');
  }

  if (ACTIVE_ONLY_RULES.has(lead.ruleId) && !lead.tags.includes('active-verified')) {
    rank = capRank(rank, 'uncertain');
    add('needs-active-check', 'inconclusive', 'A passive observation of the reference cannot show real exposure; a scope-gated Hunter probe can.');
    missing.push('Run "Verify actively" (requires in-scope target + Hunter enabled) or test manually.');
  }

  if (lead.chainIds !== undefined && lead.chainIds.length > 0) {
    add('corroboration', 'pass', `Corroborated by correlated leads in chain ${lead.chainIds.join(', ')}.`);
  }

  // --- Final status and security assessment -------------------------------------------------------------------
  // Info-level observations are recon or hardening notes, not bugs.
  if (lead.potential === 'info') {
    return finish('informational', 'informational', 'Observation is real but informational only (not a vulnerability by itself).');
  }

  // Scope constraints:
  if (scope === 'out-of-scope') {
    return finish(
      'uncertain',
      'unreviewed',
      'Target is out of scope: not reportable even if technically observed.',
    );
  }

  if (scope === 'unknown') {
    return finish(
      'likely',
      'unreviewed',
      'Observed on an asset with unknown scope; confirm program scope before reporting.',
    );
  }

  // In-scope targets:
  switch (rank) {
    case 'confirmed':
      return finish(
        'confirmed',
        'confirmed',
        'Confirmed: the observed condition is a real issue and no precondition is outstanding.',
      );
    case 'likely':
      return finish(
        'likely',
        'likely',
        'Likely a real issue; at least one impact-defining condition is still unproven.',
      );
    default:
      return finish(
        'uncertain',
        'unreviewed',
        'Uncertain: evidence is not strong enough to call this a bug without manual verification.',
      );
  }
}

/**
 * Applies passive verdicts to a list of leads. An existing ACTIVE verdict is kept unless the researcher has
 * since dismissed the lead (triage false_positive always wins).
 */
export function applyPassiveVerdicts(leads: Lead[], now: number = Date.now()): Lead[] {
  return leads.map((lead) => {
    if (lead.verdict?.method === 'active' && lead.triageState !== 'false_positive') return lead;
    return { ...lead, verdict: verifyLeadPassive(lead, now) };
  });
}
