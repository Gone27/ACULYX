import type { Lead, Masked } from '../types';
import { maskSecret, maskLocation, sha256Hex } from '../sieve/mask';

const MAX_LEADS_PER_ORIGIN = 200;
const SESSION_STORAGE_KEY = 'aculyx_session_leads_v2';

interface SerializedSessionStore {
  leads: Lead[];
  tabToLeads: Array<[number, string[]]>;
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

  private saveTimeout: any = null;
  private isInitialized = false;

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

      for (const rawLead of data.leads) {
        const lead = this.sanitizeLeadEvidence(rawLead);
        const origin = lead.origin;
        const dedupKey = this.computeDedupKey(lead);

        this.leadById.set(lead.id, lead);
        this.dedupMap.set(dedupKey, lead.id);

        if (!this.originLeads.has(origin)) {
          this.originLeads.set(origin, []);
        }
        this.originLeads.get(origin)!.push(lead);
      }

      if (Array.isArray(data.tabToLeads)) {
        for (const [tabId, leadIds] of data.tabToLeads) {
          if (Array.isArray(leadIds)) {
            this.tabToLeads.set(tabId, new Set(leadIds));
          }
        }
      }
    } catch {
      // Graceful fallback to empty in-memory state
    }
  }

  private scheduleSave(): void {
    if (!this.hasStorageSession()) return;
    if (this.saveTimeout) {
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
      const payload: SerializedSessionStore = {
        leads: allLeads,
        tabToLeads: serializedTabs,
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
   */
  private sanitizeLeadEvidence(lead: Lead): Lead {
    const preview = maskSecret(lead.evidence.preview || '');
    const location = maskLocation(lead.evidence.location || '');
    const url = (maskLocation(lead.url || '') as string) || lead.url;

    return {
      ...lead,
      url,
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
      this.scheduleSave();
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
    this.scheduleSave();
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
    this.scheduleSave();
  }

  public clearAll(): void {
    this.originLeads.clear();
    this.leadById.clear();
    this.dedupMap.clear();
    this.tabToLeads.clear();
    if (this.hasStorageSession()) {
      void chrome.storage.session.remove([SESSION_STORAGE_KEY]).catch(() => undefined);
    }
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
    this.scheduleSave();
  }
}

export const globalLeadStore = new LeadStore();
