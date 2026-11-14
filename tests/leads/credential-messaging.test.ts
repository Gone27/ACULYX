import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  handlePlanCredentialCheck,
  handleConfirmCredentialCheck,
  clearProposedPlans,
} from '../../src/background/credential-flow';
import { globalSecretCandidateStore } from '../../src/background/secret-candidate-store';
import { globalLeadStore } from '../../src/background/leads-handler';
import type { Lead } from '../../src/leads/types';
import { maskSecret, maskLocation } from '../../src/leads/sieve/mask';
import { DEFAULT_SETTINGS } from '../../src/shared/constants';

describe('Credential Liveness Phase 3: Permission & Human Gate Message Flow', () => {
  beforeEach(() => {
    clearProposedPlans();
    globalSecretCandidateStore.clear();
    globalLeadStore.clearAll();
  });

  const enabledSettings = { ...DEFAULT_SETTINGS, credentialLivenessEnabled: true };

  const makeTestLead = (id: string, origin = 'https://example.com'): Lead => ({
    id,
    ruleId: 'SEC-001',
    family: 'F1',
    tier: 'observed',
    potential: 'critical',
    confidence: 1.0,
    title: 'GitHub PAT Exposure',
    needs: ['verify scopes'],
    doesNotProve: [],
    evidence: {
      preview: maskSecret('ghp_012345678901234567890123456789012345'),
      location: maskLocation(`${origin}/bundle.js`),
    },
    tags: ['github', 'secret'],
    scopeStatus: 'in-scope',
    timestamp: Date.now(),
    origin,
    url: `${origin}/bundle.js`,
    sourceSensor: 'S2',
  });

  describe('handlePlanCredentialCheck', () => {
    it('creates an opaque short-lived plan for eligible candidate', async () => {
      const lead = makeTestLead('LD-PLAN-1');
      globalLeadStore.addLead(lead);
      globalSecretCandidateStore.addCandidate(
        'LD-PLAN-1',
        'github',
        'ghp',
        'ghp_012345678901234567890123456789012345'
      );

      const sender: chrome.runtime.MessageSender = {
        url: 'chrome-extension://abcdef/src/sidepanel/sidepanel.html',
      };

      const res = await handlePlanCredentialCheck('LD-PLAN-1', sender, { settings: enabledSettings });
      expect(res.success).toBe(true);
      expect(res.plan).toBeDefined();
      expect(res.plan?.leadId).toBe('LD-PLAN-1');
      expect(res.plan?.provider).toBe('github');
      expect(res.plan?.endpointUrl).toBe('https://api.github.com/user');
      expect(res.plan?.method).toBe('GET');
      expect(res.plan?.requiredOrigin).toBe('https://api.github.com/*');
      expect(res.plan?.maxRequests).toBe(1);
      expect(res.plan?.planId).toMatch(/^plan-[a-z0-9-]+$/);
      // Raw token must never be present in returned plan
      expect(JSON.stringify(res)).not.toContain('ghp_0123456789');
    });

    it('rejects plan request if candidate is missing or expired', async () => {
      const lead = makeTestLead('LD-NOCAND');
      globalLeadStore.addLead(lead);

      const sender = { url: 'chrome-extension://abcdef/src/sidepanel/sidepanel.html' };
      const res = await handlePlanCredentialCheck('LD-NOCAND', sender, { settings: enabledSettings });
      expect(res.success).toBe(false);
      expect(res.error).toMatch(/No active candidate/);
    });

    it('rejects plan request from content scripts or page contexts', async () => {
      const lead = makeTestLead('LD-UNTRUSTED');
      globalLeadStore.addLead(lead);
      globalSecretCandidateStore.addCandidate('LD-UNTRUSTED', 'github', 'ghp', 'ghp_abc');

      const contentScriptSender = { url: 'https://example.com/page.html' };
      const res = await handlePlanCredentialCheck('LD-UNTRUSTED', contentScriptSender);
      expect(res.success).toBe(false);
      expect(res.error).toMatch(/Untrusted message sender/);
    });
  });

  describe('handleConfirmCredentialCheck', () => {
    it('executes check when confirmed with valid plan and origin permissions', async () => {
      const lead = makeTestLead('LD-CONFIRM-1');
      globalLeadStore.addLead(lead);
      globalSecretCandidateStore.addCandidate(
        'LD-CONFIRM-1',
        'github',
        'ghp',
        'ghp_012345678901234567890123456789012345'
      );

      const sender: chrome.runtime.MessageSender = {
        url: 'chrome-extension://abcdef/src/sidepanel/sidepanel.html',
      };

      const planRes = await handlePlanCredentialCheck('LD-CONFIRM-1', sender, { settings: enabledSettings });
      expect(planRes.plan).toBeDefined();
      const planId = planRes.plan?.planId ?? '';

      const mockFetch = vi.fn().mockResolvedValue(new Response('{}', { status: 200 }));
      const hasPermission = vi.fn().mockResolvedValue(true);

      const confirmRes = await handleConfirmCredentialCheck(
        {
          type: 'CONFIRM_CREDENTIAL_CHECK',
          leadId: 'LD-CONFIRM-1',
          planId,
          confirmedByUser: true,
          affirmAuthorized: true,
        },
        sender,
        {
          fetchFn: mockFetch,
          checkPermission: hasPermission,
          settings: { ...DEFAULT_SETTINGS, credentialLivenessEnabled: true },
        }
      );

      expect(confirmRes.success).toBe(true);
      expect(confirmRes.result?.status).toBe('active_at_check');
      expect(mockFetch).toHaveBeenCalledTimes(1);

      // Stored lead should have updated credentialCheck
      const storedLead = globalLeadStore.getLead('LD-CONFIRM-1');
      expect(storedLead?.credentialCheck?.status).toBe('active_at_check');

      // Candidate must be consumed from memory (one attempt only)
      expect(globalSecretCandidateStore.getCandidate('LD-CONFIRM-1')).toBeUndefined();
    });

    it('rejects confirmation if user permission for provider origin is denied', async () => {
      const lead = makeTestLead('LD-DENIED');
      globalLeadStore.addLead(lead);
      globalSecretCandidateStore.addCandidate('LD-DENIED', 'github', 'ghp', 'ghp_abc');

      const sender = { url: 'chrome-extension://abcdef/src/sidepanel/sidepanel.html' };
      const planRes = await handlePlanCredentialCheck('LD-DENIED', sender, { settings: enabledSettings });
      const planId = planRes.plan?.planId ?? '';

      const mockFetch = vi.fn();
      const hasPermission = vi.fn().mockResolvedValue(false); // Permission denied

      const confirmRes = await handleConfirmCredentialCheck(
        {
          type: 'CONFIRM_CREDENTIAL_CHECK',
          leadId: 'LD-DENIED',
          planId,
          confirmedByUser: true,
          affirmAuthorized: true,
        },
        sender,
        {
          fetchFn: mockFetch,
          checkPermission: hasPermission,
          settings: { ...DEFAULT_SETTINGS, credentialLivenessEnabled: true },
        }
      );

      expect(confirmRes.success).toBe(false);
      expect(confirmRes.error).toMatch(/Host permission/);
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('rejects replayed confirmation (one-use plan)', async () => {
      const lead = makeTestLead('LD-REPLAY');
      globalLeadStore.addLead(lead);
      globalSecretCandidateStore.addCandidate('LD-REPLAY', 'github', 'ghp', 'ghp_abc');

      const sender = { url: 'chrome-extension://abcdef/src/sidepanel/sidepanel.html' };
      const planRes = await handlePlanCredentialCheck('LD-REPLAY', sender, { settings: enabledSettings });
      const planId = planRes.plan?.planId ?? '';

      const mockFetch = vi.fn().mockResolvedValue(new Response('{}', { status: 200 }));
      const hasPermission = vi.fn().mockResolvedValue(true);

      const first = await handleConfirmCredentialCheck(
        { type: 'CONFIRM_CREDENTIAL_CHECK', leadId: 'LD-REPLAY', planId, confirmedByUser: true, affirmAuthorized: true },
        sender,
        { fetchFn: mockFetch, checkPermission: hasPermission, settings: { ...DEFAULT_SETTINGS, credentialLivenessEnabled: true } }
      );
      expect(first.success).toBe(true);

      // Replay attempt must fail without calling fetch again
      const replay = await handleConfirmCredentialCheck(
        { type: 'CONFIRM_CREDENTIAL_CHECK', leadId: 'LD-REPLAY', planId, confirmedByUser: true, affirmAuthorized: true },
        sender,
        { fetchFn: mockFetch, checkPermission: hasPermission, settings: { ...DEFAULT_SETTINGS, credentialLivenessEnabled: true } }
      );
      expect(replay.success).toBe(false);
      expect(replay.error).toMatch(/Invalid or expired plan/);
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('rejects confirmation if affirmAuthorized is false', async () => {
      const lead = makeTestLead('LD-NOAFFIRM');
      globalLeadStore.addLead(lead);
      globalSecretCandidateStore.addCandidate('LD-NOAFFIRM', 'github', 'ghp', 'ghp_abc');

      const sender = { url: 'chrome-extension://abcdef/src/sidepanel/sidepanel.html' };
      const planRes = await handlePlanCredentialCheck('LD-NOAFFIRM', sender);
      const planId = planRes.plan?.planId ?? '';

      const mockFetch = vi.fn();
      const hasPermission = vi.fn().mockResolvedValue(true);

      const res = await handleConfirmCredentialCheck(
        { type: 'CONFIRM_CREDENTIAL_CHECK', leadId: 'LD-NOAFFIRM', planId, confirmedByUser: true, affirmAuthorized: false },
        sender,
        { fetchFn: mockFetch, checkPermission: hasPermission, settings: { ...DEFAULT_SETTINGS, credentialLivenessEnabled: true } }
      );
      expect(res.success).toBe(false);
      expect(res.error).toMatch(/Authorization affirmation/);
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });
});
