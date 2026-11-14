import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  handlePlanCredentialCheck,
  handleConfirmCredentialCheck,
  clearProposedPlans,
  onCredentialLivenessDisabled,
  getProposedPlanCount,
} from '../../src/background/credential-flow';
import { globalSecretCandidateStore } from '../../src/background/secret-candidate-store';
import { globalLeadStore } from '../../src/background/leads-handler';
import type { Lead } from '../../src/leads/types';
import { maskSecret, maskLocation } from '../../src/leads/sieve/mask';
import { DEFAULT_SETTINGS } from '../../src/shared/constants';

const sender = { url: 'chrome-extension://abcdef/src/sidepanel/sidepanel.html' };
const TOKEN = 'ghp_012345678901234567890123456789012345';
const ENABLED_SETTINGS = { ...DEFAULT_SETTINGS, credentialLivenessEnabled: true };
const DISABLED_SETTINGS = { ...DEFAULT_SETTINGS, credentialLivenessEnabled: false };

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

  it('refuses planning if credentialLivenessEnabled is false', async () => {
    globalLeadStore.addLead(lead('L-DISABLED', 'in-scope'));
    globalSecretCandidateStore.addCandidate('L-DISABLED', 'github', 'ghp', TOKEN);
    const plan = await handlePlanCredentialCheck('L-DISABLED', sender, { settings: DISABLED_SETTINGS });
    expect(plan.success).toBe(false);
    expect(plan.error).toMatch(/disabled in settings/i);
  });

  it('refuses confirmation if credentialLivenessEnabled is false and does not consume candidate or call fetch', async () => {
    globalLeadStore.addLead(lead('L-CONF-DISABLED', 'in-scope'));
    globalSecretCandidateStore.addCandidate('L-CONF-DISABLED', 'github', 'ghp', TOKEN);
    const plan = await handlePlanCredentialCheck('L-CONF-DISABLED', sender, { settings: ENABLED_SETTINGS });
    expect(plan.success).toBe(true);

    const fetchFn = vi.fn();
    const res = await handleConfirmCredentialCheck(
      {
        type: 'CONFIRM_CREDENTIAL_CHECK',
        leadId: 'L-CONF-DISABLED',
        planId: plan.plan?.planId ?? '',
        confirmedByUser: true,
        affirmAuthorized: true,
      } as never,
      sender,
      { fetchFn: fetchFn as never, checkPermission: () => Promise.resolve(true), settings: DISABLED_SETTINGS }
    );
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/disabled in settings/i);
    expect(fetchFn).not.toHaveBeenCalled();
    expect(globalSecretCandidateStore.getCandidate('L-CONF-DISABLED')).toBeDefined();
  });

  it('clears all candidate entries and proposed plans on settings transition to disabled', async () => {
    globalLeadStore.addLead(lead('L-CLEAN', 'in-scope'));
    globalSecretCandidateStore.addCandidate('L-CLEAN', 'github', 'ghp', TOKEN);
    const plan = await handlePlanCredentialCheck('L-CLEAN', sender, { settings: ENABLED_SETTINGS });
    expect(plan.success).toBe(true);
    expect(globalSecretCandidateStore.getCandidate('L-CLEAN')).toBeDefined();
    expect(getProposedPlanCount()).toBe(1);

    onCredentialLivenessDisabled();

    expect(globalSecretCandidateStore.getCandidate('L-CLEAN')).toBeUndefined();
    expect(getProposedPlanCount()).toBe(0);
  });

  it('fails closed when chrome.permissions API is missing or unavailable', async () => {
    globalLeadStore.addLead(lead('L-NOPERM', 'in-scope'));
    globalSecretCandidateStore.addCandidate('L-NOPERM', 'github', 'ghp', TOKEN);
    const plan = await handlePlanCredentialCheck('L-NOPERM', sender, { settings: ENABLED_SETTINGS });
    expect(plan.success).toBe(true);

    const fetchFn = vi.fn();
    // Do not provide a checkPermission override; exercises defaultCheckPermission with no chrome.permissions
    const res = await handleConfirmCredentialCheck(
      {
        type: 'CONFIRM_CREDENTIAL_CHECK',
        leadId: 'L-NOPERM',
        planId: plan.plan?.planId ?? '',
        confirmedByUser: true,
        affirmAuthorized: true,
      } as never,
      sender,
      { fetchFn: fetchFn as never, settings: ENABLED_SETTINGS }
    );
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/Host permission .* was denied or not granted/i);
    expect(fetchFn).not.toHaveBeenCalled();
    expect(globalSecretCandidateStore.getCandidate('L-NOPERM')).toBeDefined();
  });

  it('fails closed when permissions check throws an exception or returns false', async () => {
    globalLeadStore.addLead(lead('L-THROWS', 'in-scope'));
    globalSecretCandidateStore.addCandidate('L-THROWS', 'github', 'ghp', TOKEN);
    const plan = await handlePlanCredentialCheck('L-THROWS', sender, { settings: ENABLED_SETTINGS });
    expect(plan.success).toBe(true);

    const fetchFn = vi.fn();
    const res = await handleConfirmCredentialCheck(
      {
        type: 'CONFIRM_CREDENTIAL_CHECK',
        leadId: 'L-THROWS',
        planId: plan.plan?.planId ?? '',
        confirmedByUser: true,
        affirmAuthorized: true,
      } as never,
      sender,
      {
        fetchFn: fetchFn as never,
        checkPermission: () => Promise.reject(new Error('API error')),
        settings: ENABLED_SETTINGS,
      }
    );
    expect(res.success).toBe(false);
    expect(fetchFn).not.toHaveBeenCalled();
    expect(globalSecretCandidateStore.getCandidate('L-THROWS')).toBeDefined();
  });

  it('refuses unknown scope without sending anything or consuming the candidate', async () => {
    globalLeadStore.addLead(lead('L1', 'unknown'));
    globalSecretCandidateStore.addCandidate('L1', 'github', 'ghp', TOKEN);
    const plan = await handlePlanCredentialCheck('L1', sender, { settings: ENABLED_SETTINGS });
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
      { fetchFn: fetchFn as never, checkPermission: () => Promise.resolve(true), settings: ENABLED_SETTINGS }
    );
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/in scope/);
    expect(fetchFn).not.toHaveBeenCalled();
    expect(globalSecretCandidateStore.getCandidate('L1')).toBeDefined(); // not destroyed by the refusal
  });

  it('never plans a check for an out-of-scope lead (the store does not keep it)', async () => {
    globalLeadStore.addLead(lead('L3', 'out-of-scope'));
    globalSecretCandidateStore.addCandidate('L3', 'github', 'ghp', TOKEN);
    const plan = await handlePlanCredentialCheck('L3', sender, { settings: ENABLED_SETTINGS });
    expect(plan.success).toBe(false);
  });

  it('plan ids are unpredictable and carry no timestamp', async () => {
    globalLeadStore.addLead(lead('L2', 'in-scope'));
    globalSecretCandidateStore.addCandidate('L2', 'github', 'ghp', TOKEN);
    const a = await handlePlanCredentialCheck('L2', sender, { settings: ENABLED_SETTINGS });
    expect(a.plan?.planId).toMatch(/^plan-[0-9a-f]{8}-[0-9a-f]{4}-/);
  });
});
