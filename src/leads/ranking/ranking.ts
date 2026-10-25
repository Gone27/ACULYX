import type { Lead, LeadPotential, EvidenceTier, VerdictStatus } from '../types';

const POTENTIAL_WEIGHTS: Record<LeadPotential, number> = {
  critical: 100,
  high: 70,
  medium: 40,
  low: 15,
  info: 5,
};

const CONFIDENCE_FACTORS: Record<EvidenceTier, number> = {
  observed: 1.0,
  strong: 0.8,
  weak: 0.35,
  whisper: 0.1,
};

/**
 * Self-check outcome multiplier. A lead the tool has verified floats up; one it has ruled out sinks to zero.
 * Leads without a verdict (not yet verified) are neutral.
 */
const VERDICT_FACTORS: Record<VerdictStatus, number> = {
  confirmed: 1.5,
  likely: 1.0,
  uncertain: 0.6,
  informational: 0.3,
  false_positive: 0,
};

const SCOPE_FACTORS: Record<Lead['scopeStatus'], number> = {
  'in-scope': 1.0,
  unknown: 0.5,
  'out-of-scope': 0.0,
};

/**
 * Calculates lead priority score according to formula:
 * potentialWeight * confidenceFactor * scopeFactor * novelty * chainBoost * verdictFactor
 */
export function calculateLeadPriority(
  lead: Lead,
  inChain: boolean = false,
  isNew: boolean = false
): number {
  if (lead.triageState === 'false_positive') return 0;
  const potentialWeight = POTENTIAL_WEIGHTS[lead.potential] ?? 5;
  const confidenceFactor = CONFIDENCE_FACTORS[lead.tier] ?? 0.5;
  const scopeFactor = SCOPE_FACTORS[lead.scopeStatus] ?? 0.5;

  const noveltyMultiplier = isNew || lead.novelty === true ? 1.2 : 1.0;
  const chainMultiplier = inChain || (lead.chainIds !== undefined && lead.chainIds.length > 0) ? 1.5 : 1.0;

  const verdictFactor = lead.verdict !== undefined ? (VERDICT_FACTORS[lead.verdict.status] ?? 1.0) : 1.0;

  const priority = potentialWeight * confidenceFactor * scopeFactor * noveltyMultiplier * chainMultiplier * verdictFactor;
  return Math.round(priority * 100) / 100;
}

/**
 * Ranks an array of leads in descending order of calculated priority.
 * Dynamically recomputes priority on every call so mutated scope, triage state,
 * or vulnerability chains always update rankings and exported priority.
 */
export function rankLeads(leads: Lead[]): Lead[] {
  return [...leads]
    .map(lead => {
      const priority = calculateLeadPriority(lead);
      return { ...lead, priority };
    })
    .sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));
}
