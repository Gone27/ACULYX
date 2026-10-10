import { describe, it, expect } from 'vitest';
import { calculateLeadPriority } from '../../src/leads/ranking/ranking';
import { evaluateChains, CHAINS } from '../../src/leads/chains/chains';
import type { Lead } from '../../src/leads/types';
import { maskSecret, maskLocation } from '../../src/leads/sieve/mask';

function createMockLead(overrides: Partial<Lead> = {}): Lead {
  return {
    id: 'LD-TEST-' + Math.random().toString(36).slice(2, 8),
    ruleId: 'SEC-001',
    family: 'F1',
    tier: 'observed',
    potential: 'high',
    confidence: 0.8,
    title: 'Test Lead',
    needs: ['manual confirmation'],
    doesNotProve: ['exploitability'],
    evidence: {
      preview: maskSecret('AKIAIOSFODNN7EXAMPLE'),
      location: maskLocation('https://example.com/app.js'),
    },
    tags: ['aws', 'secret'],
    scopeStatus: 'in-scope',
    timestamp: Date.now(),
    origin: 'https://example.com',
    url: 'https://example.com/app.js',
    sourceSensor: 'S2',
    ...overrides,
  };
}

describe('Lead Ranking Formula', () => {
  it('computes expected priority for in-scope observed critical lead', () => {
    const lead = createMockLead({
      potential: 'critical',
      tier: 'observed',
      confidence: 1.0,
      scopeStatus: 'in-scope',
    });
    // crit: 100 * observed: 1.0 * in-scope: 1.0 * novelty: 1.0 * chain: 1.0 = 100
    const priority = calculateLeadPriority(lead, false, false);
    expect(priority).toBe(100);
  });

  it('assigns zero priority to out-of-scope leads', () => {
    const lead = createMockLead({
      potential: 'critical',
      scopeStatus: 'out-of-scope',
    });
    const priority = calculateLeadPriority(lead, false, false);
    expect(priority).toBe(0);
  });

  it('boosts priority with novelty and chain correlation', () => {
    const lead = createMockLead({
      potential: 'high', // 70
      tier: 'strong', // 0.8
      scopeStatus: 'in-scope', // 1.0
    });
    // Base: 70 * 0.8 * 1.0 = 56
    const basePriority = calculateLeadPriority(lead, false, false);
    expect(basePriority).toBe(56);

    // With novelty (1.2): 56 * 1.2 = 67.2
    const novelPriority = calculateLeadPriority(lead, false, true);
    expect(novelPriority).toBeCloseTo(67.2, 1);

    // With chain boost (1.5) and novelty: 56 * 1.2 * 1.5 = 100.8
    const chainedNovelPriority = calculateLeadPriority(lead, true, true);
    expect(chainedNovelPriority).toBeCloseTo(100.8, 1);
  });
});

describe('Chains Correlator Engine', () => {
  it('defines 7 standard chain rules CH-001 through CH-007', () => {
    expect(CHAINS.length).toBeGreaterThanOrEqual(7);
    const ids = CHAINS.map(c => c.id);
    expect(ids).toContain('CH-001');
    expect(ids).toContain('CH-002');
    expect(ids).toContain('CH-003');
    expect(ids).toContain('CH-004');
    expect(ids).toContain('CH-005');
    expect(ids).toContain('CH-006');
    expect(ids).toContain('CH-007');
  });

  it('upgrades whisper leads to strong when chain conditions are met', () => {
    // CH-001 needs: ['open-redirect-param', 'oauth-flow'], sameApex: true
    const lead1 = createMockLead({
      id: 'lead-1',
      ruleId: 'PAR-002',
      tags: ['open-redirect-param'],
      tier: 'whisper',
      origin: 'https://auth.example.com',
    });
    const lead2 = createMockLead({
      id: 'lead-2',
      ruleId: 'AUTH-001',
      tags: ['oauth-flow'],
      tier: 'observed',
      origin: 'https://login.example.com',
    });

    const result = evaluateChains([lead1, lead2]);
    expect(result.activeChains.length).toBeGreaterThanOrEqual(1);

    // lead1 was whisper, now upgraded to strong because it is part of CH-001
    const updatedLead1 = result.leads.find(l => l.id === 'lead-1');
    expect(updatedLead1?.tier).toBe('strong');
    expect(updatedLead1?.chainIds).toContain('CH-001');
  });
});
