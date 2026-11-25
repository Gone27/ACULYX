import type { Lead, LeadFamily, EvidenceTier, LeadPotential, LeadSensor, CredentialCheckResult, CredentialCheckStatus, CredentialProvider } from '../types';
import { maskSecret, maskLocation, sha256Hex } from '../sieve/mask';
import { redactAllSecrets } from '../../shared/reporting/report-builder';
import { calculateLeadPriority } from '../ranking/ranking';
import { sanitizeFacts, sanitizeVerdict } from '../verify/sanitize';
import type { LeadVerdict } from '../types';

const VALID_CRED_STATUSES = new Set<CredentialCheckStatus>([
  'not_checked', 'active_at_check', 'inactive_at_check',
  'permission_limited', 'unknown', 'unsupported',
]);
const VALID_CRED_PROVIDERS = new Set<CredentialProvider>(['github', 'stripe', 'slack']);

export function sanitizeCredentialCheck(raw: unknown): CredentialCheckResult | undefined {
  if (raw === undefined || raw === null || typeof raw !== 'object') return undefined;
  const r = raw as Record<string, unknown>;
  const status = typeof r.status === 'string' && VALID_CRED_STATUSES.has(r.status as CredentialCheckStatus)
    ? (r.status as CredentialCheckStatus)
    : 'unknown';
  const provider = typeof r.provider === 'string' && VALID_CRED_PROVIDERS.has(r.provider as CredentialProvider)
    ? (r.provider as CredentialProvider)
    : undefined;
  if (!provider) return undefined;
  const tokenFamily = typeof r.tokenFamily === 'string' ? r.tokenFamily.slice(0, 30) : '';
  const checkedAt = typeof r.checkedAt === 'number' && Number.isFinite(r.checkedAt) ? r.checkedAt : 0;
  const rawDetails = typeof r.details === 'string' ? r.details.slice(0, 500) : '';
  const cleanDetails = redactAllSecrets(rawDetails.replace(/[\x00-\x1F\x7F]/g, ''));
  const livemode = typeof r.livemode === 'boolean' ? r.livemode : undefined;
  // Allowlist: never persist rawToken, login, workspace, account IDs, response text
  return {
    status,
    provider,
    tokenFamily,
    checkedAt,
    details: cleanDetails,
    ...(livemode !== undefined ? { livemode } : {}),
  };
}

const VALID_FAMILIES = new Set<LeadFamily>(['F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8']);
const VALID_TIERS = new Set<EvidenceTier>(['observed', 'strong', 'weak', 'whisper']);
const VALID_POTENTIALS = new Set<LeadPotential>(['critical', 'high', 'medium', 'low', 'info']);
const VALID_SENSORS = new Set<LeadSensor>(['S1', 'S2', 'S3', 'S4', 'S5']);
const VALID_SCOPES = new Set<Lead['scopeStatus']>(['in-scope', 'out-of-scope', 'unknown']);
const VALID_TRIAGE_STATES = new Set<NonNullable<Lead['triageState']>>(['open', 'triaged', 'false_positive', 'resolved']);

const MAX_LEADS_PER_ORIGIN = 200;
const SESSION_STORAGE_KEY = 'aculyx_session_leads_v2';

interface SerializedSessionStore {
  leads: Lead[];
  tabToLeads: Array<[number, string[]]>;
  tabToLeadGenerations?: Array<[number, Array<[string, number]>]>;
}

export class LeadStore {
  /** Map from origin -> list of leads for that origin (bounded to MAX_LEADS_PER_ORIGIN) */
  private originLeads = new Map<string, Lead[]>();

  /** Map from leadId -> Lead */
  private leadById = new Map<string, Lead>();

  /** Map from dedupKey -> leadId */
  private dedupMap = new Map<string, string>();

  /** Map from tabId -> Set of leadIds */
  private tabToLeads = new Map<number, Set<string>>();

  /** Map from tabId -> Map<leadId, navigationGeneration> */
  private tabToLeadGenerations = new Map<number, Map<string, number>>();

  private tabGenerationResolver?: (tabId: number) => number;

  private saveTimeout: ReturnType<typeof setTimeout> | null = null;
  private isInitialized = false;

  public onLeadRemoved?: (leadId: string) => void;
  public onCleared?: () => void;

  public setTabGenerationResolver(resolver: (tabId: number) => number): void {
    this.tabGenerationResolver = resolver;
  }

  constructor() {
    void this.init();
  }

  public async init(): Promise<void> {
    if (this.isInitialized) return;
    this.isInitialized = true;
    await this.loadFromSession();
  }

  private hasStorageSession(): boolean {
    return typeof chrome !== 'undefined' && Boolean(chrome?.storage?.session);
  }

  private async loadFromSession(): Promise<void> {
    if (!this.hasStorageSession()) return;
    try {
      const res = await chrome.storage.session.get([SESSION_STORAGE_KEY]);
      const data = res[SESSION_STORAGE_KEY] as SerializedSessionStore | undefined;
      if (!data || !Array.isArray(data.leads)) return;

      this.originLeads.clear();
      this.leadById.clear();
      this.dedupMap.clear();
      this.tabToLeads.clear();
      this.tabToLeadGenerations.clear();

      for (const rawLead of data.leads) {
        const lead = this.sanitizeLeadEvidence(rawLead);
        const origin = lead.origin;
        const dedupKey = this.computeDedupKey(lead);

        this.leadById.set(lead.id, lead);
        this.dedupMap.set(dedupKey, lead.id);

        const existingOriginList = this.originLeads.get(origin);
        if (existingOriginList !== undefined) {
          existingOriginList.push(lead);
        } else {
          this.originLeads.set(origin, [lead]);
        }
      }

      if (Array.isArray(data.tabToLeads)) {
        for (const [tabId, leadIds] of data.tabToLeads) {
          if (Array.isArray(leadIds)) {
            this.tabToLeads.set(tabId, new Set(leadIds));
          }
        }
      }

      if (Array.isArray(data.tabToLeadGenerations)) {
        for (const [tabId, entries] of data.tabToLeadGenerations) {
          if (Array.isArray(entries)) {
            this.tabToLeadGenerations.set(tabId, new Map(entries));
          }
        }
      }
    } catch {
      // Graceful fallback to empty in-memory state
    }
  }

  private scheduleSave(): void {
    if (!this.hasStorageSession()) return;
    if (this.saveTimeout !== null) {
      clearTimeout(this.saveTimeout);
    }
    this.saveTimeout = setTimeout(() => {
      void this.persistToSession();
    }, 150);
  }

  private async persistToSession(): Promise<void> {
    if (!this.hasStorageSession()) return;
    try {
      const allLeads = Array.from(this.leadById.values());
      const serializedTabs: Array<[number, string[]]> = [];
      for (const [tabId, ids] of this.tabToLeads.entries()) {
        serializedTabs.push([tabId, Array.from(ids)]);
      }
      const serializedTabGens: Array<[number, Array<[string, number]>]> = [];
      for (const [tabId, gens] of this.tabToLeadGenerations.entries()) {
        serializedTabGens.push([tabId, Array.from(gens.entries())]);
      }
      const payload: SerializedSessionStore = {
        leads: allLeads,
        tabToLeads: serializedTabs,
        tabToLeadGenerations: serializedTabGens,
      };
      await chrome.storage.session.set({ [SESSION_STORAGE_KEY]: payload });
    } catch {
      // Storage quota or communication error ignored
    }
  }

  private computeDedupKey(lead: Lead): string {
    const raw = `${lead.ruleId}|${lead.evidence.location}|${lead.evidence.preview}`;
    return sha256Hex(raw).slice(0, 16);
  }

  /**
   * Sanitizes evidence to guarantee it conforms to Masked branding and never leaks raw secrets or query tokens.
   * Enforces pre-storage invariant: all free-text fields and arrays are sanitized and capped before persistence.
   */
  private sanitizeLeadEvidence(lead: Lead): Lead {
    const id = redactAllSecrets(String(lead.id || '').slice(0, 100));
    const ruleId = redactAllSecrets(String(lead.ruleId || '').slice(0, 50));
    const origin = redactAllSecrets(String(lead.origin || '').slice(0, 200));

    const rawPreview = lead.evidence?.preview;
    const rawLoc = lead.evidence?.location;
    const rawUrl = lead.url;
    const preview =
      lead.ruleId === 'MAP-001'
        ? maskLocation(typeof rawPreview === 'string' && rawPreview.length > 0 ? rawPreview : '')
        : maskSecret(typeof rawPreview === 'string' && rawPreview.length > 0 ? rawPreview : '');
    const location = maskLocation(typeof rawLoc === 'string' && rawLoc.length > 0 ? rawLoc : '');
    const url = (maskLocation(typeof rawUrl === 'string' && rawUrl.length > 0 ? rawUrl : '') as string) || lead.url;

    const rawTitle = lead.title;
    const title = redactAllSecrets(typeof rawTitle === 'string' ? rawTitle.slice(0, 300) : '');

    const rawContext = lead.evidence?.context;
    const context =
      typeof rawContext === 'string' && rawContext.length > 0
        ? redactAllSecrets(rawContext.slice(0, 1000))
        : undefined;

    const rawNames = lead.evidence?.extractedNames;
    const extractedNames = Array.isArray(rawNames)
      ? rawNames.slice(0, 50).map((n) => redactAllSecrets(String(n).slice(0, 150)))
      : undefined;

    const tags = Array.isArray(lead.tags)
      ? lead.tags.slice(0, 20).map((t) => redactAllSecrets(String(t).slice(0, 50)))
      : [];

    const chainIds = Array.isArray(lead.chainIds)
      ? lead.chainIds.slice(0, 20).map((c) => redactAllSecrets(String(c).slice(0, 50)))
      : undefined;

    const needs = Array.isArray(lead.needs)
      ? lead.needs.slice(0, 20).map((n) => redactAllSecrets(String(n).slice(0, 300)))
      : [];

    const doesNotProve = Array.isArray(lead.doesNotProve)
      ? lead.doesNotProve.slice(0, 20).map((d) => redactAllSecrets(String(d).slice(0, 300)))
      : [];

    const remediation =
      typeof lead.remediation === 'string' && lead.remediation.length > 0
        ? redactAllSecrets(lead.remediation.slice(0, 1000))
        : undefined;

    const family = VALID_FAMILIES.has(lead.family) ? lead.family : 'F8';
    const tier = VALID_TIERS.has(lead.tier) ? lead.tier : 'whisper';
    const potential = VALID_POTENTIALS.has(lead.potential) ? lead.potential : 'info';
    const sourceSensor = VALID_SENSORS.has(lead.sourceSensor) ? lead.sourceSensor : 'S2';
    const scopeStatus = VALID_SCOPES.has(lead.scopeStatus) ? lead.scopeStatus : 'unknown';
    const confidence = typeof lead.confidence === 'number' && Number.isFinite(lead.confidence)
      ? Math.min(1.0, Math.max(0.0, lead.confidence))
      : 0.8;
    const timestamp = typeof lead.timestamp === 'number' && Number.isFinite(lead.timestamp)
      ? lead.timestamp
      : Date.now();
    const triageState = lead.triageState && VALID_TRIAGE_STATES.has(lead.triageState)
      ? lead.triageState
      : undefined;

    const facts = sanitizeFacts(lead.facts);
    const verdict = sanitizeVerdict(lead.verdict);
    const credentialCheck = sanitizeCredentialCheck(lead.credentialCheck);

    return {
      id,
      ruleId,
      family,
      tier,
      potential,
      confidence,
      title,
      needs,
      doesNotProve,
      evidence: {
        preview,
        location,
        ...(context !== undefined ? { context } : {}),
        ...(extractedNames !== undefined ? { extractedNames } : {}),
      },
      tags,
      scopeStatus,
      timestamp,
      origin,
      url,
      sourceSensor,
      ...(chainIds !== undefined ? { chainIds } : {}),
      ...(typeof lead.priority === 'number' && Number.isFinite(lead.priority) ? { priority: lead.priority } : {}),
      ...(typeof lead.novelty === 'boolean' ? { novelty: lead.novelty } : {}),
      ...(typeof lead.pinned === 'boolean' ? { pinned: lead.pinned } : {}),
      ...(triageState !== undefined ? { triageState } : {}),
      ...(remediation !== undefined ? { remediation } : {}),
      ...(facts !== undefined ? { facts } : {}),
      ...(verdict !== undefined ? { verdict } : {}),
      ...(credentialCheck !== undefined ? { credentialCheck } : {}),
    };
  }

  /**
   * Adds or updates a lead, enforcing LRU bounds and deduplication.
   * Returns the ID of the surviving lead in the store (may differ from rawLead.id
   * when the lead merges into an existing duplicate). Returns undefined if dropped.
   */
  public addLead(rawLead: Lead, tabId?: number, generation?: number): string | undefined {
    if (rawLead.scopeStatus === 'out-of-scope') {
      return undefined;
    }
    const lead = this.sanitizeLeadEvidence(rawLead);
    const origin = lead.origin;
    const dedupKey = this.computeDedupKey(lead);

    const existingLeadId = this.dedupMap.get(dedupKey);

    if (existingLeadId !== undefined && existingLeadId.length > 0 && this.leadById.has(existingLeadId)) {
      // Update existing lead in place
      const existing = this.leadById.get(existingLeadId);
      if (existing !== undefined) {
        existing.timestamp = Math.max(existing.timestamp, lead.timestamp);
        existing.confidence = Math.max(existing.confidence, lead.confidence);
        if (lead.chainIds !== undefined && lead.chainIds.length > 0) {
          const mergedChains = new Set([...(existing.chainIds !== undefined ? existing.chainIds : []), ...lead.chainIds]);
          existing.chainIds = Array.from(mergedChains);
        }
        if (tabId !== undefined) {
          this.associateTabLead(tabId, existing.id, generation);
        }
        existing.priority = calculateLeadPriority(existing);
      }
      this.scheduleSave();
      // Return the surviving lead's ID, not the incoming (possibly discarded) ID
      return existingLeadId;
    }

    // New lead
    lead.priority = calculateLeadPriority(lead);
    this.leadById.set(lead.id, lead);
    this.dedupMap.set(dedupKey, lead.id);

    let originList = this.originLeads.get(origin);
    if (originList === undefined) {
      originList = [];
      this.originLeads.set(origin, originList);
    }
    originList.push(lead);

    // Enforce LRU bounding per origin
    if (originList.length > MAX_LEADS_PER_ORIGIN) {
      const removed = originList.shift();
      if (removed !== undefined) {
        this.leadById.delete(removed.id);
        const oldKey = this.computeDedupKey(removed);
        this.dedupMap.delete(oldKey);
        this.onLeadRemoved?.(removed.id);
      }
    }

    if (tabId !== undefined) {
      this.associateTabLead(tabId, lead.id, generation);
    }
    this.scheduleSave();
    return lead.id;
  }

  public associateTabLead(tabId: number, leadId: string, generation?: number): void {
    let set = this.tabToLeads.get(tabId);
    if (set === undefined) {
      set = new Set();
      this.tabToLeads.set(tabId, set);
    }
    set.add(leadId);

    const resolvedGen = generation ?? (this.tabGenerationResolver ? this.tabGenerationResolver(tabId) : undefined);
    if (resolvedGen !== undefined) {
      let genMap = this.tabToLeadGenerations.get(tabId);
      if (genMap === undefined) {
        genMap = new Map();
        this.tabToLeadGenerations.set(tabId, genMap);
      }
      genMap.set(leadId, resolvedGen);
    }
  }

  /**
   * Clears tab-to-lead links without removing underlying origin-level lead history.
   * When preserveGeneration is provided, preserves links already associated with that generation.
   */
  public clearTabAssociations(tabId: number, preserveGeneration?: number): void {
    const existingSet = this.tabToLeads.get(tabId);
    if (existingSet === undefined) {
      this.tabToLeadGenerations.delete(tabId);
      return;
    }

    if (preserveGeneration === undefined) {
      this.tabToLeads.delete(tabId);
      this.tabToLeadGenerations.delete(tabId);
      this.scheduleSave();
      return;
    }

    const genMap = this.tabToLeadGenerations.get(tabId);
    let removedAny = false;
    for (const leadId of Array.from(existingSet)) {
      const leadGen = genMap?.get(leadId);
      if (leadGen !== preserveGeneration) {
        existingSet.delete(leadId);
        genMap?.delete(leadId);
        removedAny = true;
      }
    }

    if (existingSet.size === 0) {
      this.tabToLeads.delete(tabId);
      this.tabToLeadGenerations.delete(tabId);
    }

    if (removedAny) {
      this.scheduleSave();
    }
  }

  public getLeadsForOrigin(origin: string): Lead[] {
    const leads = this.originLeads.get(origin) ?? [];
    return [...leads];
  }

  public getLeadsForTab(tabId: number, origin: string): Lead[] {
    const tabLeadIds = this.tabToLeads.get(tabId);
    const seen = new Set<string>();
    const result: Lead[] = [];

    if (tabLeadIds !== undefined && tabLeadIds.size > 0) {
      for (const id of tabLeadIds) {
        const lead = this.leadById.get(id);
        if (lead !== undefined) {
          result.push(lead);
          seen.add(lead.id);
        }
      }
    }

    if (origin.length > 0) {
      const originList = this.originLeads.get(origin) ?? [];
      for (const lead of originList) {
        if (!seen.has(lead.id)) {
          result.push(lead);
          seen.add(lead.id);
        }
      }
    }

    return result;
  }

  public getLead(id: string): Lead | undefined {
    return this.leadById.get(id);
  }

  public getAllLeads(): Lead[] {
    return Array.from(this.leadById.values());
  }

  public clearForOrigin(origin: string): void {
    const leads = this.originLeads.get(origin) || [];
    for (const lead of leads) {
      this.leadById.delete(lead.id);
      this.dedupMap.delete(this.computeDedupKey(lead));
      for (const [tabId, ids] of this.tabToLeads.entries()) {
        if (ids.delete(lead.id)) {
          this.tabToLeadGenerations.get(tabId)?.delete(lead.id);
          if (ids.size === 0) {
            this.tabToLeads.delete(tabId);
            this.tabToLeadGenerations.delete(tabId);
          }
        }
      }
      this.onLeadRemoved?.(lead.id);
    }
    this.originLeads.delete(origin);
    this.scheduleSave();
  }

  public clearAll(): void {
    this.originLeads.clear();
    this.leadById.clear();
    this.dedupMap.clear();
    this.tabToLeads.clear();
    this.tabToLeadGenerations.clear();
    this.onCleared?.();
    if (this.hasStorageSession()) {
      void chrome.storage.session.remove([SESSION_STORAGE_KEY]).catch(() => undefined);
    }
  }

  /** Stores a verification verdict (e.g. the result of an active check) on a lead. */
  public setVerdict(id: string, verdict: LeadVerdict): boolean {
    const lead = this.leadById.get(id);
    if (!lead) return false;
    const clean = sanitizeVerdict(verdict);
    if (clean === undefined) return false;
    lead.verdict = clean;
    lead.priority = calculateLeadPriority(lead);
    this.scheduleSave();
    return true;
  }

  public updateLeadTriage(id: string, state?: Lead['triageState'], pinned?: boolean): void {
    const lead = this.leadById.get(id);
    if (!lead) return;

    if (state !== undefined) {
      lead.triageState = state;
    }
    if (pinned !== undefined) {
      lead.pinned = pinned;
    }
    lead.priority = calculateLeadPriority(lead);
    this.scheduleSave();
  }
}

export const globalLeadStore = new LeadStore();
