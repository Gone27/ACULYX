export type EvidenceTier = 'observed' | 'strong' | 'weak' | 'whisper';

export type LeadPotential = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type LeadFamily = 'F1' | 'F2' | 'F3' | 'F4' | 'F5' | 'F6' | 'F7' | 'F8';

export type LeadSensor = 'S1' | 'S2' | 'S3' | 'S4' | 'S5';

declare const MASKED: unique symbol;
export type Masked<T> = T & { readonly [MASKED]: true };

export interface LeadEvidence {
  preview: Masked<string>;
  location: Masked<string>;
  context?: string | undefined;
  extractedNames?: string[] | undefined;
}

/**
 * Final judgement on a lead.
 *  - confirmed:      the evidence itself demonstrates the issue on an in-scope asset (observed/reproduced, not a placeholder/hardening note)
 *  - likely:         strong evidence, but one impact-defining condition or scope confirmation is still unproven
 *  - uncertain:      cannot be decided from what ACULYX can safely observe; manual verification required
 *  - informational:  the observation is real, but it is not a vulnerability by itself (recon / hardening note)
 *  - false_positive: a check positively ruled the lead out (placeholder, public-by-design, researcher dismissed)
 */
export type VerdictStatus = 'confirmed' | 'likely' | 'uncertain' | 'informational' | 'false_positive';

export type EvidenceStatus = 'observed' | 'reproduced' | 'inconclusive';

export type SecurityAssessment = 'unreviewed' | 'likely' | 'confirmed' | 'informational' | 'false_positive';

export type VerdictCheckOutcome = 'pass' | 'fail' | 'inconclusive';

export interface VerdictCheck {
  id: string;
  /** passive = derived from data already observed; active = needed a gated Hunter request */
  kind: 'passive' | 'active';
  outcome: VerdictCheckOutcome;
  detail: string;
}

export interface LeadVerdict {
  status: VerdictStatus;
  evidenceStatus: EvidenceStatus;
  scopeStatus: 'in-scope' | 'out-of-scope' | 'unknown';
  securityAssessment: SecurityAssessment;
  method: 'passive' | 'active';
  summary: string;
  checks: VerdictCheck[];
  /** What is still missing before this lead could be called confirmed. Never empty if scope is unknown or out-of-scope. */
  missing: string[];
  verifiedAt: number;
}

/**
 * Non-sensitive facts computed at detection time, while the raw value is still in memory.
 * Raw values are NEVER stored (see Behavior Contract invariant 1); only derived booleans/buckets are.
 */
export interface LeadFacts {
  /** Offline integrity checksum of the token format: true = valid, false = invalid, undefined = format has none. */
  checksumValid?: boolean | undefined;
  entropyBits?: number | undefined;
  length?: number | undefined;
  /** Surrounding text looked like documentation / sample / placeholder / test fixture. */
  exampleContext?: boolean | undefined;
  /** Value appeared inside an HTML/JS comment. */
  inComment?: boolean | undefined;
  occurrences?: number | undefined;
  /** JWT only */
  jwtExpired?: boolean | undefined;
  jwtHasExp?: boolean | undefined;
  jwtAlg?: string | undefined;
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
  chainIds?: string[] | undefined;
  priority?: number | undefined;
  novelty?: boolean | undefined;
  pinned?: boolean | undefined;
  triageState?: 'open' | 'triaged' | 'false_positive' | 'resolved' | undefined;
  remediation?: string | undefined;
  facts?: LeadFacts | undefined;
  verdict?: LeadVerdict | undefined;
  credentialCheck?: CredentialCheckResult | undefined;
}

export type CredentialCheckStatus =
  | 'not_checked'
  | 'active_at_check'
  | 'inactive_at_check'
  | 'permission_limited'
  | 'unknown'
  | 'unsupported';

export type CredentialProvider = 'github' | 'stripe' | 'slack';

export interface CredentialCheckResult {
  status: CredentialCheckStatus;
  provider: CredentialProvider;
  tokenFamily: string;
  checkedAt: number;
  details: string;
  livemode?: boolean | undefined;
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
  scopeStatus?: 'in-scope' | 'out-of-scope' | 'unknown';
}

export interface ReconEndpoint {
  path: string;
  origin: string;
  method?: string;
  tags: string[];
  status?: number;
  scopeStatus?: 'in-scope' | 'out-of-scope' | 'unknown';
}

export type CloudBucketProvider =
  | 'aws'
  | 'gcp'
  | 'azure'
  | 'digitalocean'
  | 'cloudflare-r2'
  | 'alibaba-oss'
  | 'oracle-oss'
  | 'backblaze-b2'
  | 'generic';

export interface ReconBucket {
  bucket: string;
  provider: CloudBucketProvider;
  origin: string;
  scopeStatus?: 'in-scope' | 'out-of-scope' | 'unknown';
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
  programHeaderName?: string | undefined;
  programHeaderValue?: string | undefined;
  customUserAgent?: string | undefined;
  maxRequestsPerSecond: number;
  customHeaders?: Record<string, string> | undefined;
}
