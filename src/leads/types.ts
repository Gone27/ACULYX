export type EvidenceTier = 'observed' | 'strong' | 'weak' | 'whisper';

export type LeadPotential = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type LeadFamily = 'F1' | 'F2' | 'F3' | 'F4' | 'F5' | 'F6' | 'F7' | 'F8';

export type LeadSensor = 'S1' | 'S2' | 'S3' | 'S4' | 'S5';

declare const MASKED: unique symbol;
export type Masked<T> = T & { readonly [MASKED]: true };

export interface LeadEvidence {
  preview: Masked<string>;
  location: Masked<string>;
  context?: string;
  extractedNames?: string[];
}

export interface Lead {
  id: string;
  ruleId: string;
  family: LeadFamily;
  tier: EvidenceTier;
  potential: LeadPotential;
  confidence: number; // 0.0 to 1.0
  title: string;
  needs: string[];
  doesNotProve: string[];
  evidence: LeadEvidence;
  tags: string[];
  scopeStatus: 'in-scope' | 'out-of-scope' | 'unknown';
  timestamp: number;
  origin: string;
  url: string;
  sourceSensor: LeadSensor;
  chainIds?: string[];
  priority?: number;
  novelty?: boolean;
  pinned?: boolean;
  triageState?: 'open' | 'triaged' | 'false_positive' | 'resolved';
  remediation?: string;
}

export interface ChainRule {
  id: string; // e.g. CH-001
  needs: string[];
  sameOrigin?: boolean;
  sameApex?: boolean;
  potential: LeadPotential;
  next: string[];
}

export interface ReconHost {
  hostname: string;
  scopeStatus: 'in-scope' | 'out-of-scope' | 'unknown';
  discoveredVia: string;
  firstSeen: number;
  lastSeen: number;
}

export interface ReconParam {
  name: string;
  category?: 'redirect' | 'ssrf' | 'file' | 'idor' | 'debug' | 'callback' | 'general';
  origin: string;
  contexts: string[];
}

export interface ReconEndpoint {
  path: string;
  origin: string;
  method?: string;
  tags: string[];
  status?: number;
}

export interface ReconBucket {
  bucket: string;
  provider: 'aws' | 'gcp' | 'azure' | 'digitalocean';
  origin: string;
}

export interface ReconMemory {
  hosts: ReconHost[];
  params: ReconParam[];
  endpoints: ReconEndpoint[];
  buckets: ReconBucket[];
}

export interface HunterProbeRequest {
  targetUrl: string;
  method: 'GET' | 'HEAD' | 'OPTIONS';
  headers?: Record<string, string>;
  reason: string;
  leadId?: string;
}

export interface HunterLedgerEntry {
  id: string;
  timestamp: number;
  request: HunterProbeRequest;
  response?: {
    status: number;
    headers: Record<string, string>;
    elapsedMs: number;
  };
  confirmedByUser: boolean;
  scopeStatus: 'in-scope' | 'out-of-scope' | 'unknown';
  resultNotes?: string;
}

export interface HunterConfig {
  enabled: boolean;
  programHeaderName?: string;
  programHeaderValue?: string;
  customUserAgent?: string;
  maxRequestsPerSecond: number;
}
