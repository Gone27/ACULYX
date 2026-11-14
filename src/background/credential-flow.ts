import type {
  ProposedCredentialPlan,
  PlanCredentialCheckResponse,
  ConfirmCredentialCheckMessage,
  ConfirmCredentialCheckResponse,
} from '../shared/messaging';
import type { CredentialProvider } from '../leads/types';
import type { SettingsV2 } from '../shared/types';
import { SettingsService } from '../shared/settings';
import { globalSecretCandidateStore } from './secret-candidate-store';
import { globalLeadStore } from './leads-handler';
import {
  getLivenessProbeTarget,
  executeCredentialLivenessCheck,
} from '../leads/verify/credential-liveness';

const PLAN_TTL_MS = 2 * 60 * 1000; // 2 minutes

const proposedPlans = new Map<string, ProposedCredentialPlan>();

export function clearProposedPlans(): void {
  proposedPlans.clear();
}

export function onCredentialLivenessDisabled(): void {
  globalSecretCandidateStore.clear();
  clearProposedPlans();
}

export function getProposedPlanCount(): number {
  return proposedPlans.size;
}

/**
 * Maps a provider to its required optional host permission pattern.
 */
export function getRequiredProviderOrigin(provider: CredentialProvider): string {
  switch (provider) {
    case 'github':
      return 'https://api.github.com/*';
    case 'stripe':
      return 'https://api.stripe.com/*';
    case 'slack':
      return 'https://slack.com/*';
  }
}

/**
 * Validates that a message originates exclusively from the extension's own UI
 * (e.g., sidepanel, popup, options), never from content scripts or page contexts.
 */
export function isTrustedExtensionSender(sender?: chrome.runtime.MessageSender): boolean {
  if (!sender || typeof sender.url !== 'string') return false;
  const url = sender.url;

  // Prefer an exact match on this extension's own base URL (rejects pages of any other extension).
  if (typeof chrome !== 'undefined' && typeof chrome.runtime?.getURL === 'function') {
    const extBase = chrome.runtime.getURL('');
    if (extBase.length > 0) {
      return url.startsWith(extBase);
    }
  }

  // No runtime available (unit tests): fall back to the extension-page URL schemes.
  return url.startsWith('chrome-extension://') || url.startsWith('moz-extension://');
}

export interface PlanDeps {
  settings?: SettingsV2;
  getSettings?: () => Promise<SettingsV2>;
}

/**
 * Handles PLAN_CREDENTIAL_CHECK.
 * Constructs an opaque, short-lived plan for eligible candidates.
 * Raw tokens and custom endpoints are NEVER accepted or emitted here.
 */
export async function handlePlanCredentialCheck(
  leadId: string,
  sender?: chrome.runtime.MessageSender,
  deps: PlanDeps = {}
): Promise<PlanCredentialCheckResponse> {
  if (!isTrustedExtensionSender(sender)) {
    return {
      type: 'PLAN_CREDENTIAL_CHECK_RESPONSE',
      success: false,
      leadId,
      error: 'Untrusted message sender: only extension UI can initiate credential checks.',
    };
  }

  const settings = deps.settings ?? (deps.getSettings !== undefined ? await deps.getSettings() : await SettingsService.getSettings());
  if (settings.credentialLivenessEnabled !== true) {
    return {
      type: 'PLAN_CREDENTIAL_CHECK_RESPONSE',
      success: false,
      leadId,
      error: 'Credential liveness checking is disabled in settings. Enable it in settings first.',
    };
  }

  const lead = globalLeadStore.getLead(leadId);
  if (!lead) {
    return {
      type: 'PLAN_CREDENTIAL_CHECK_RESPONSE',
      success: false,
      leadId,
      error: `Lead "${leadId}" not found in store.`,
    };
  }

  const candidate = globalSecretCandidateStore.getCandidate(leadId);
  if (!candidate) {
    return {
      type: 'PLAN_CREDENTIAL_CHECK_RESPONSE',
      success: false,
      leadId,
      error: `No active candidate found for lead "${leadId}" (may be expired or already consumed).`,
    };
  }

  const target = getLivenessProbeTarget(candidate.provider, candidate.tokenFamily);
  if (!target) {
    return {
      type: 'PLAN_CREDENTIAL_CHECK_RESPONSE',
      success: false,
      leadId,
      error: `Token family "${candidate.tokenFamily}" is unsupported for automated checks in v1.`,
    };
  }

  // Purge expired plans
  const now = Date.now();
  for (const [id, plan] of proposedPlans.entries()) {
    if (now > plan.expiresAt) {
      proposedPlans.delete(id);
    }
  }

  const planId =
    typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
      ? `plan-${crypto.randomUUID()}`
      : `plan-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  const plan: ProposedCredentialPlan = {
    planId,
    leadId,
    provider: candidate.provider,
    endpointUrl: target.url,
    method: target.method,
    maskedIdentity: lead.evidence.preview,
    tokenFamily: candidate.tokenFamily,
    maxRequests: 1,
    expiresAt: now + PLAN_TTL_MS,
    requiredOrigin: getRequiredProviderOrigin(candidate.provider),
  };

  proposedPlans.set(planId, plan);

  return {
    type: 'PLAN_CREDENTIAL_CHECK_RESPONSE',
    success: true,
    leadId,
    plan,
  };
}

export interface ConfirmDeps {
  fetchFn?: typeof fetch;
  checkPermission?: (origin: string) => Promise<boolean>;
  settings?: SettingsV2;
  getSettings?: () => Promise<SettingsV2>;
}

/**
 * Checks runtime permission for an origin.
 */
async function defaultCheckPermission(origin: string): Promise<boolean> {
  if (typeof chrome === 'undefined' || typeof chrome.permissions?.contains !== 'function') {
    return true; // Test fallback
  }
  return new Promise<boolean>((resolve) => {
    chrome.permissions.contains({ origins: [origin] }, (granted) => {
      resolve(granted === true);
    });
  });
}

/**
 * Handles CONFIRM_CREDENTIAL_CHECK.
 * Verifies plan binding, single-use consumption, authorization affirmations,
 * and origin host permissions before executing exactly one provider request.
 */
export async function handleConfirmCredentialCheck(
  req: ConfirmCredentialCheckMessage,
  sender?: chrome.runtime.MessageSender,
  deps: ConfirmDeps = {}
): Promise<ConfirmCredentialCheckResponse> {
  if (!isTrustedExtensionSender(sender)) {
    return {
      type: 'CONFIRM_CREDENTIAL_CHECK_RESPONSE',
      success: false,
      leadId: req.leadId,
      error: 'Untrusted message sender.',
    };
  }

  if (req.confirmedByUser !== true) {
    return {
      type: 'CONFIRM_CREDENTIAL_CHECK_RESPONSE',
      success: false,
      leadId: req.leadId,
      error: 'Confirmation by user required.',
    };
  }

  if (req.affirmAuthorized !== true) {
    return {
      type: 'CONFIRM_CREDENTIAL_CHECK_RESPONSE',
      success: false,
      leadId: req.leadId,
      error: 'Authorization affirmation required before sending authenticated provider request.',
    };
  }

  const plan = proposedPlans.get(req.planId);
  if (!plan || plan.leadId !== req.leadId || Date.now() > plan.expiresAt) {
    return {
      type: 'CONFIRM_CREDENTIAL_CHECK_RESPONSE',
      success: false,
      leadId: req.leadId,
      error: 'Invalid or expired plan.',
    };
  }

  // Opt-in gate: refuse execution if credential liveness is disabled in settings.
  // Decide BEFORE consuming the plan or candidate.
  const settings = deps.settings ?? (deps.getSettings !== undefined ? await deps.getSettings() : await SettingsService.getSettings());
  if (settings.credentialLivenessEnabled !== true) {
    return {
      type: 'CONFIRM_CREDENTIAL_CHECK_RESPONSE',
      success: false,
      leadId: req.leadId,
      error: 'Credential liveness checking is disabled in settings. Enable it in settings first.',
    };
  }

  // Authorization gate: sending a found credential to a vendor needs the same in-scope proof as an
  // active probe. 'unknown' is not enough. Decide BEFORE consuming the plan or the one-shot candidate,
  // so a refusal does not destroy the credential candidate.
  const scopedLead = globalLeadStore.getLead(req.leadId);
  if (!scopedLead || scopedLead.scopeStatus !== 'in-scope') {
    return {
      type: 'CONFIRM_CREDENTIAL_CHECK_RESPONSE',
      success: false,
      leadId: req.leadId,
      error:
        'Credential checks require the lead to be in scope. Add the target to your program scope first; unknown or out-of-scope targets are refused.',
    };
  }

  // Consume plan immediately (strictly one-use)
  proposedPlans.delete(req.planId);

  // Check host permission for the exact provider origin
  const permissionChecker = deps.checkPermission ?? defaultCheckPermission;
  const hasPermission = await permissionChecker(plan.requiredOrigin);
  if (!hasPermission) {
    return {
      type: 'CONFIRM_CREDENTIAL_CHECK_RESPONSE',
      success: false,
      leadId: req.leadId,
      error: `Host permission for provider "${plan.requiredOrigin}" was denied or not granted.`,
    };
  }

  // Consume candidate immediately (one attempt only)
  const candidate = globalSecretCandidateStore.consumeCandidate(req.leadId);
  if (!candidate) {
    return {
      type: 'CONFIRM_CREDENTIAL_CHECK_RESPONSE',
      success: false,
      leadId: req.leadId,
      error: 'Candidate credential expired or already consumed.',
    };
  }

  const lead = globalLeadStore.getLead(req.leadId);
  if (!lead || lead.scopeStatus === 'out-of-scope') {
    return {
      type: 'CONFIRM_CREDENTIAL_CHECK_RESPONSE',
      success: false,
      leadId: req.leadId,
      error: 'Target lead is missing or out of scope.',
    };
  }

  // Execute the single provider check
  const checkDeps = deps.fetchFn !== undefined ? { fetchFn: deps.fetchFn } : {};
  const result = await executeCredentialLivenessCheck(candidate, checkDeps);

  // Update lead in store
  lead.credentialCheck = result;
  // Re-add to persist sanitized update
  globalLeadStore.addLead(lead);

  return {
    type: 'CONFIRM_CREDENTIAL_CHECK_RESPONSE',
    success: true,
    leadId: req.leadId,
    result,
  };
}
