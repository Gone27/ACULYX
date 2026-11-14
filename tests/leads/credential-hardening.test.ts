import { describe, it, expect, beforeEach, vi } from 'vitest';
import { handlePlanCredentialCheck, handleConfirmCredentialCheck, clearProposedPlans } from '../../src/background/credential-flow';
import { globalSecretCandidateStore } from '../../src/background/secret-candidate-store';
import { globalLeadStore } from '../../src/background/leads-handler';
import type { Lead } from '../../src/leads/types';
import { maskSecret, maskLocation } from '../../src/leads/sieve/mask';

const sender = { url: 'chrome-extension://abcdef/src/sidepanel/sidepanel.html' };
const TOKEN = 'ghp_012345678901234567890123456789012345';

const lead = (id: string, scopeStatus: Lead['scopeStatus']): Lead => ({
  id,
  ruleId: 'SEC-001',
  family: 'F1',
  tier: 'observed',
  potential: 'critical',
  confidence: 1,
  title: 'GitHub PAT Exposure',
  needs: ['verify scopes'],
  doesNotProve: [],
  evidence: { preview: maskSecret(TOKEN), location: maskLocation('https://example.com/b.js') },
  tags: ['github', 'secret'],
  scopeStatus,
  timestamp: Date.now(),
  origin: 'https://example.com',
  url: 'https://example.com/b.js',
  sourceSensor: 'S2',
});

describe('credential liveness authorization gate', () => {
  beforeEach(() => {
    clearProposedPlans();
    globalSecretCandidateStore.clear();
    globalLeadStore.clearAll();
  });

  it('refuses unknown scope without sending anything or consuming the candidate', async () => {
    globalLeadStore.addLead(lead('L1', 'unknown'));
    globalSecretCandidateStore.addCandidate('L1', 'github', 'ghp', TOKEN);
    const plan = await handlePlanCredentialCheck('L1', sender);
    expect(plan.success).toBe(true);
    const fetchFn = vi.fn();
    const res = await handleConfirmCredentialCheck(
      {
        type: 'CONFIRM_CREDENTIAL_CHECK',
        leadId: 'L1',
        planId: plan.plan?.planId ?? '',
        confirmedByUser: true,
        affirmAuthorized: true,
      } as never,
      sender,
      { fetchFn: fetchFn as never, checkPermission: () => Promise.resolve(true) }
    );
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/in scope/);
    expect(fetchFn).not.toHaveBeenCalled();
    expect(globalSecretCandidateStore.getCandidate('L1')).toBeDefined(); // not destroyed by the refusal
  });

  it('never plans a check for an out-of-scope lead (the store does not keep it)', async () => {
    globalLeadStore.addLead(lead('L3', 'out-of-scope'));
    globalSecretCandidateStore.addCandidate('L3', 'github', 'ghp', TOKEN);
    const plan = await handlePlanCredentialCheck('L3', sender);
    expect(plan.success).toBe(false);
  });

  it('plan ids are unpredictable and carry no timestamp', async () => {
    globalLeadStore.addLead(lead('L2', 'in-scope'));
    globalSecretCandidateStore.addCandidate('L2', 'github', 'ghp', TOKEN);
    const a = await handlePlanCredentialCheck('L2', sender);
    expect(a.plan?.planId).toMatch(/^plan-[0-9a-f]{8}-[0-9a-f]{4}-/);
  });
});
