import { describe, it, expect } from 'vitest';
import { executeHunterProbe } from '../../src/leads/hunter/hunter';
import type { HunterProbeRequest, HunterConfig } from '../../src/leads/types';

describe('Hunter Active Tier Scope Gating & Safety', () => {
  const sampleConfig: HunterConfig = {
    enabled: true,
    maxRequestsPerSecond: 1,
    programHeaderName: 'X-Bug-Bounty-Researcher',
    programHeaderValue: 'ACULYX-Hunter-Test',
  };

  it('strictly blocks out-of-scope targets before making any request', async () => {
    const probe: HunterProbeRequest = {
      targetUrl: 'https://out-of-scope.example.com/api/test',
      method: 'GET',
      reason: 'Confirm endpoint presence',
    };

    const result = await executeHunterProbe(probe, 'out-of-scope', sampleConfig, true);
    expect(result.scopeStatus).toBe('out-of-scope');
    expect(result.resultNotes).toMatch(/blocked|out-of-scope/i);
    expect(result.response).toBeUndefined();
  });

  it('strictly blocks unknown scope targets', async () => {
    const probe: HunterProbeRequest = {
      targetUrl: 'https://unknown.example.com/api/test',
      method: 'GET',
      reason: 'Confirm endpoint presence',
    };

    const result = await executeHunterProbe(probe, 'unknown', sampleConfig, true);
    expect(result.scopeStatus).toBe('unknown');
    expect(result.resultNotes).toMatch(/blocked/i);
  });

  it('rejects forbidden HTTP methods like POST/PUT', async () => {
    const probe: any = {
      targetUrl: 'https://in-scope.example.com/api/test',
      method: 'POST',
      reason: 'Active payload injection',
    };

    const result = await executeHunterProbe(probe, 'in-scope', sampleConfig, true);
    expect(result.resultNotes).toMatch(/prohibited|disallowed|method/i);
  });

  it('strictly blocks probes not explicitly confirmed by the user', async () => {
    const probe: HunterProbeRequest = {
      targetUrl: 'https://in-scope.example.com/api/test',
      method: 'GET',
      reason: 'Confirm endpoint presence',
    };

    const result = await executeHunterProbe(probe, 'in-scope', sampleConfig, false);
    expect(result.confirmedByUser).toBe(false);
    expect(result.resultNotes).toMatch(/confirmed by the user/i);
  });
});
