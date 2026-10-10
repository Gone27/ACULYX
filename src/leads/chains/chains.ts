import type { ChainRule, Lead } from '../types';

export function extractApex(originOrUrl: string): string {
  try {
    let hostname = originOrUrl;
    if (originOrUrl.startsWith('http://') || originOrUrl.startsWith('https://')) {
      hostname = new URL(originOrUrl).hostname;
    }
    const parts = hostname.split('.');
    if (parts.length <= 2) return hostname;
    const secondLast = parts[parts.length - 2];
    if (['co', 'com', 'org', 'net', 'edu', 'gov'].includes(secondLast) && parts.length >= 3) {
      return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
  } catch {
    return originOrUrl;
  }
}

export const CHAINS: ChainRule[] = [
  {
    id: 'CH-001',
    needs: ['open-redirect-param', 'oauth-flow'],
    sameApex: true,
    potential: 'high',
    next: ['Verify OAuth token/code leakage via open redirect parameter chaining'],
  },
  {
    id: 'CH-002',
    needs: ['cors-reflection', 'api-endpoint'],
    sameOrigin: true,
    potential: 'critical',
    next: ['Test authenticated cross-origin data extraction on sensitive API endpoint'],
  },
  {
    id: 'CH-003',
    needs: ['csp-bypass', 'reflected-input'],
    sameOrigin: true,
    potential: 'high',
    next: ['Construct script gadget payload via allowlisted CDN and reflected input'],
  },
  {
    id: 'CH-004',
    needs: ['sourcemap', 'internal-paths'],
    sameOrigin: true,
    potential: 'medium',
    next: ['Inspect unbundled source tree for hidden administrative routes and secrets'],
  },
  {
    id: 'CH-005',
    needs: ['missing-csrf', 'state-changing-form'],
    sameOrigin: true,
    potential: 'medium',
    next: ['Verify SameSite cookie behavior on cross-site form submission'],
  },
  {
    id: 'CH-006',
    needs: ['cloud-bucket', 'excessive-data'],
    sameOrigin: false,
    potential: 'high',
    next: ['Cross-reference exposed bucket identifiers with excessive data leak keys'],
  },
  {
    id: 'CH-007',
    needs: ['cacheable-auth', 'pii-exposure'],
    sameOrigin: true,
    potential: 'medium',
    next: ['Test web cache deception on authenticated endpoints containing PII'],
  },
];

export interface ChainEvaluationResult {
  leads: Lead[];
  activeChains: { chain: ChainRule; matchedLeads: Lead[] }[];
}

export function evaluateChains(leads: Lead[]): ChainEvaluationResult {
  // Clone leads to avoid mutating input directly
  const updatedLeads = leads.map(l => ({ ...l, tags: [...l.tags], chainIds: [...(l.chainIds || [])] }));
  const activeChains: { chain: ChainRule; matchedLeads: Lead[] }[] = [];

  for (const chain of CHAINS) {
    const requiredNeeds = chain.needs;
    if (requiredNeeds.length === 0) continue;

    // Filter leads that match at least one need
    const candidateLeads = updatedLeads.filter(lead =>
      requiredNeeds.some(need => lead.tags.includes(need) || lead.ruleId === need)
    );

    // Group leads by domain/origin boundary if required
    let groups: Lead[][] = [];
    if (chain.sameOrigin) {
      const originMap = new Map<string, Lead[]>();
      for (const lead of candidateLeads) {
        if (!originMap.has(lead.origin)) originMap.set(lead.origin, []);
        originMap.get(lead.origin)!.push(lead);
      }
      groups = Array.from(originMap.values());
    } else if (chain.sameApex) {
      const apexMap = new Map<string, Lead[]>();
      for (const lead of candidateLeads) {
        const apex = extractApex(lead.origin);
        if (!apexMap.has(apex)) apexMap.set(apex, []);
        apexMap.get(apex)!.push(lead);
      }
      groups = Array.from(apexMap.values());
    } else {
      groups = [candidateLeads];
    }

    // Evaluate each group against chain requirements
    for (const group of groups) {
      const matchedGroupLeads: Lead[] = [];
      let allNeedsSatisfied = true;

      for (const need of requiredNeeds) {
        const found = group.find(
          lead => (lead.tags.includes(need) || lead.ruleId === need) && !matchedGroupLeads.includes(lead)
        );
        if (found) {
          matchedGroupLeads.push(found);
        } else {
          allNeedsSatisfied = false;
          break;
        }
      }

      if (allNeedsSatisfied) {
        activeChains.push({ chain, matchedLeads: matchedGroupLeads });

        // Promote member leads and attach chainId
        for (const lead of matchedGroupLeads) {
          if (lead.tier === 'whisper') {
            lead.tier = 'strong';
          }
          if (!lead.chainIds.includes(chain.id)) {
            lead.chainIds.push(chain.id);
          }
        }
      }
    }
  }

  return { leads: updatedLeads, activeChains };
}
