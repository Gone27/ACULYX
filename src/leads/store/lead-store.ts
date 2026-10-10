import type { Lead, Masked } from '../types';
import { maskSecret, maskLocation, hasCanary, sha256Hex } from '../sieve/mask';

const MAX_LEADS_PER_ORIGIN = 200;

export class LeadStore {
  /** Map from origin -> list of leads for that origin (bounded to MAX_LEADS_PER_ORIGIN) */
  private originLeads = new Map<string, Lead[]>();

  /** Map from leadId -> Lead */
  private leadById = new Map<string, Lead>();

  /** Map from dedupKey -> leadId */
  private dedupMap = new Map<string, string>();

  /** Map from tabId -> Set of leadIds */
  private tabToLeads = new Map<number, Set<string>>();

  private computeDedupKey(lead: Lead): string {
    const raw = `${lead.ruleId}|${lead.evidence.location}|${lead.evidence.preview}`;
    return sha256Hex(raw).slice(0, 16);
  }

  /**
   * Sanitizes evidence to guarantee it conforms to Masked branding and never leaks raw secrets.
   */
  private sanitizeLeadEvidence(lead: Lead): Lead {
    let preview = lead.evidence.preview;
    let location = lead.evidence.location;

    // Safety checks against unmasked or leaked canary data
    if (!preview || hasCanary(preview)) {
      preview = maskSecret(preview || '');
    }

    if (!location || hasCanary(location)) {
      location = maskLocation(location || '');
    }

    return {
      ...lead,
      evidence: {
        ...lead.evidence,
        preview: preview as Masked<string>,
        location: location as Masked<string>,
      },
    };
  }

  /**
   * Adds or updates a lead, enforcing LRU bounds and deduplication.
   */
  public addLead(rawLead: Lead, tabId?: number): void {
    const lead = this.sanitizeLeadEvidence(rawLead);
    const origin = lead.origin;
    const dedupKey = this.computeDedupKey(lead);

    const existingLeadId = this.dedupMap.get(dedupKey);

    if (existingLeadId && this.leadById.has(existingLeadId)) {
      // Update existing lead in place
      const existing = this.leadById.get(existingLeadId)!;
      existing.timestamp = Math.max(existing.timestamp, lead.timestamp);
      existing.confidence = Math.max(existing.confidence, lead.confidence);
      if (lead.chainIds && lead.chainIds.length > 0) {
        const mergedChains = new Set([...(existing.chainIds || []), ...lead.chainIds]);
        existing.chainIds = Array.from(mergedChains);
      }
      if (tabId !== undefined) {
        this.associateTabLead(tabId, existing.id);
      }
      return;
    }

    // New lead
    this.leadById.set(lead.id, lead);
    this.dedupMap.set(dedupKey, lead.id);

    if (!this.originLeads.has(origin)) {
      this.originLeads.set(origin, []);
    }
    const originList = this.originLeads.get(origin)!;
    originList.push(lead);

    // Enforce LRU bounding per origin
    if (originList.length > MAX_LEADS_PER_ORIGIN) {
      const removed = originList.shift();
      if (removed) {
        this.leadById.delete(removed.id);
        const oldKey = this.computeDedupKey(removed);
        this.dedupMap.delete(oldKey);
      }
    }

    if (tabId !== undefined) {
      this.associateTabLead(tabId, lead.id);
    }
  }

  public associateTabLead(tabId: number, leadId: string): void {
    if (!this.tabToLeads.has(tabId)) {
      this.tabToLeads.set(tabId, new Set());
    }
    this.tabToLeads.get(tabId)!.add(leadId);
  }

  public getLeadsForOrigin(origin: string): Lead[] {
    const leads = this.originLeads.get(origin) || [];
    return [...leads];
  }

  public getLeadsForTab(tabId: number, origin: string): Lead[] {
    const tabLeadIds = this.tabToLeads.get(tabId);
    if (!tabLeadIds) {
      return this.getLeadsForOrigin(origin);
    }

    const result: Lead[] = [];
    for (const id of tabLeadIds) {
      const lead = this.leadById.get(id);
      if (lead && lead.origin === origin) {
        result.push(lead);
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
    }
    this.originLeads.delete(origin);
  }

  public clearAll(): void {
    this.originLeads.clear();
    this.leadById.clear();
    this.dedupMap.clear();
    this.tabToLeads.clear();
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
  }
}

export const globalLeadStore = new LeadStore();
