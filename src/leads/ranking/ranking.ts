import type { Lead, LeadPotential, EvidenceTier } from '../types';

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

const SCOPE_FACTORS: Record<Lead['scopeStatus'], number> = {
  'in-scope': 1.0,
  unknown: 0.5,
  'out-of-scope': 0.0,
};

/**
 * Calculates lead priority score according to formula:
 * potentialWeight * confidenceFactor * scopeFactor * novelty * chainBoost
 */
export function calculateLeadPriority(
  lead: Lead,
  inChain: boolean = false,
  isNew: boolean = false
): number {
  const potentialWeight = POTENTIAL_WEIGHTS[lead.potential] ?? 5;
  const confidenceFactor = CONFIDENCE_FACTORS[lead.tier] ?? 0.5;
  const scopeFactor = SCOPE_FACTORS[lead.scopeStatus] ?? 0.5;

  const noveltyMultiplier = isNew || lead.novelty === true ? 1.2 : 1.0;
  const chainMultiplier = inChain || (lead.chainIds !== undefined && lead.chainIds.length > 0) ? 1.5 : 1.0;

  const priority = potentialWeight * confidenceFactor * scopeFactor * noveltyMultiplier * chainMultiplier;
  return Math.round(priority * 100) / 100;
}

/**
 * Ranks an array of leads in descending order of calculated priority.
 */
export function rankLeads(leads: Lead[]): Lead[] {
  return [...leads].sort((a, b) => {
    const pA = a.priority ?? calculateLeadPriority(a);
    const pB = b.priority ?? calculateLeadPriority(b);
    return pB - pA;
  });
}
