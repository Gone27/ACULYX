import type { ScopeStatus, ScopeProfile, ScopeRule } from './scope/contracts';
export type { ScopeStatus, ScopeProfile, ScopeRule };

// ─── Core enumerations ────────────────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'pass';
export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';
export type Category = 'header' | 'cookie' | 'transport' | 'cors';
export type CapturePoint = 'onHeadersReceived' | 'onResponseStarted';
export type MonitoringMode = 'per-site' | 'all-sites' | 'off';
export type ServiceWorkerStatus = 'unknown' | 'controlled' | 'not-controlled';

// ─── Subdomain trust analysis ─────────────────────────────────────────────────

/**
 * A single trust-bridge vector for the subdomain escalation analysis.
 * present = true  → trust bridge confirmed (risk exists)
 * present = false → explicitly blocked
 * present = null  → not applicable (e.g. HTTP page for HSTS check)
 */
export interface SubdomainTrustVector {
  id: string;
  label: string;
  detail: string;
  risk: 'critical' | 'high' | 'medium' | 'low' | 'info';
  present: boolean | null;
}

export interface SubdomainTrustAnalysis {
  hasEscalationPath: boolean;
  vectors: SubdomainTrustVector[];
}

// ─── Network ──────────────────────────────────────────────────────────────────

/** One hop in a redirect chain or the final response. */
export interface Hop {
  requestId: string;
  url: string;
  status: number;
  /**
   * Lowercase-keyed header map.
   * When a header appears multiple times, the last value wins
   * (except Set-Cookie which is handled separately).
   */
  headers: Record<string, string>;
  /** Original casing and all values preserved. */
  rawHeaders: Array<{ name: string; value: string }>;
  fromCache: boolean;
  /**
   * True when the response includes Non-Authoritative-Reason: HSTS,
   * meaning the browser upgraded this hop internally via the HSTS store.
   */
  isHstsUpgrade: boolean;
  /**
   * Which webRequest event produced this snapshot.
   * When both events are captured and differ, headersDiffer is set.
   */
  capturedAt: CapturePoint;
  /**
  * True when onHeadersReceived and onResponseStarted produced different
  * header sets. webRequest does not expose which extension, if any, caused it.
   */
  headersDiffer: boolean;
  timestamp: number;
  /** Number of redirects represented before this captured response. */
  redirectCount?: number;
  /** Navigation generation counter for the owning tab. */
  generation?: number;
}

// ─── Cookies ──────────────────────────────────────────────────────────────────

/**
 * Cookie record, stripped of its value.
 * Cookie values are NEVER persisted, displayed, or exported.
 * Only attributes and derived metadata are stored.
 */
export interface CookieRecord {
  name: string;
  domain: string;
  /** True only when the observed Set-Cookie header explicitly had Domain=. */
  domainAttributePresent: boolean | null;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: 'strict' | 'lax' | 'none' | '';
  session: boolean;
  /** Unix-ms expiry, null for session cookies. */
  expiresAt: number | null;
  partitioned: boolean;
  /** True when directly observed as JS-set, false from a response header, null when unknown. */
  setByJs: boolean | null;
  isThirdParty: boolean;
}

// ─── Findings ─────────────────────────────────────────────────────────────────

export interface Finding {
  ruleId: string;
  category: Category;
  severity: Severity;
  title: string;
  /**
   * Plain-English real-world impact sentence ("so what happens if not fixed?").
   */
  impact?: string;
  /**
   * Sanitized, length-capped representation of the offending value.
   * Any control characters and BiDi overrides are escaped before storage.
   * Never contains a cookie value.
   */
  evidence: string;
  recommendation: string;
  /** MDN/OWASP canonical reference URL. */
  reference: string;
  /** URL of the response that produced this finding. */
  sourceUrl?: string;
  /**
   * Finding confidence: deterministic (direct header absence or exact syntax verification)
   * vs heuristic (name pattern matching, bypass-prone host heuristics, version string regex).
   */
  confidence?: 'deterministic' | 'heuristic';
  provenance?: FindingProvenance;
  outcome?: FindingOutcome;
  limitations?: string[] | undefined;
  scopeStatus?: ScopeStatus | undefined;
}

export type FindingProvenance =
  | 'response-header'
  | 'redirect-hop'
  | 'redirect'
  | 'cookie-metadata'
  | 'dom-signal'
  | 'har-import'
  | 'har-json'
  | 'cli-fetch';

export type FindingOutcome =
  | 'pass'
  | 'violation'
  | 'fail'
  | 'not-observed'
  | 'not-applicable'
  | 'partial-coverage';

export interface BaselineMetadata {
  schemaVersion: string;
  rulesetVersion: string;
  environmentLabel?: string;
  captureScope?: string;
  coverageHopsExpected?: number;
  coverageHopsCaptured?: number;
}

export interface OriginHistoryItem {
  timestamp: number;
  score: number;
  grade: Grade;
}

export interface ScoreBreakdown {
  ruleId: string;
  title: string;
  severity: Severity;
  weight: number;
  /** Points actually deducted (0 = finding is pass or weight is 0). */
  penalty: number;
}

// ─── Coverage & Ledger ────────────────────────────────────────────────────────

/**
 * A single entry in the per-tab coverage ledger documenting where data came from
 * (network, cache, service worker, redirect, or DOM scan) so security audits
 * never display a reassuring grade when coverage has blind spots.
 */
export interface CoverageLedgerEntry {
  type: 'navigation' | 'redirect' | 'api' | 'subresource' | 'cookie-jar' | 'service-worker' | 'third-party-blocked';
  url: string;
  source: 'network' | 'cache' | 'hsts-upgrade' | 'service-worker' | 'dom' | 'boundary-filter' | 'third-party-blocked';
  status?: number | undefined;
  timestamp: number;
  notes?: string | undefined;
}

export interface CoverageInfo {
  /** Total redirects + final response the browser performed. */
  hopsExpected: number;
  /** Hops successfully captured by webRequest. */
  hopsCaptured: number;
  /** Final response was served from cache. */
  hasCache: boolean;
  /** Backward-compatible boolean derived from serviceWorkerStatus. */
  hasServiceWorker: boolean;
  /** Direct page-level service-worker control signal. */
  serviceWorkerStatus: ServiceWorkerStatus;
  /** Service-worker script URL when the page reports one. */
  serviceWorkerUrl: string | null;
  /** Page is a restricted scheme (chrome://, etc.) we cannot inspect. */
  isRestricted: boolean;
  /** A <meta http-equiv="Content-Security-Policy"> was found by content script. */
  metaCspFound: boolean;
  /**
   * The actual policy strings extracted from meta CSP tags (in document order).
   * The browser applies ALL of them simultaneously (intersection semantics).
   * Populated when metaCspFound is true.
   */
  metaCspPolicies?: string[];
  /** Chronological ledger of every hop and signal observed for this tab. */
  ledger?: CoverageLedgerEntry[];
  /** Explicit list of blind spots (e.g. cache, service-worker synthesis, restricted scheme). */
  blindSpots?: string[];
}

// ─── Tab state ────────────────────────────────────────────────────────────────

export interface TabState {
  tabId: number;
  origin: string;
  url: string;
  hops: Hop[];
  cookies: CookieRecord[];
  findings: Finding[];
  /** Diagnostics tied to the latest captured response, such as unobserved cookies. */
  captureFindings?: Finding[];
  grade: Grade;
  score: number;
  /** Advisory hardening/configuration quality sub-score, separate from security score. */
  qualityScore?: number;
  qualityGrade?: Grade;
  scoreVersion: string;
  scoreBreakdown: ScoreBreakdown[];
  coverage: CoverageInfo;
  /** Subdomain → main-domain escalation analysis. */
  subdomainTrust: SubdomainTrustAnalysis;
  /** True when the user explicitly granted permission for this origin. */
  monitoredByUser: boolean;
  apiEndpoints?: Map<string, ApiEndpointState>;
  updatedAt: number;
  /** Navigation generation counter for this tab's current document lifecycle. */
  navigationGeneration?: number;
  /** True when this tab is an incognito/private tab. Incognito state is session-only and never persisted to local storage. */
  isIncognito?: boolean | undefined;
  /** Overall scope status evaluated against the active scope profile. */
  scopeStatus?: ScopeStatus | undefined;
  /** Human-readable explanation of determined scope status. */
  scopeReason?: string | undefined;
}

export interface SettingsV2 {
  schemaVersion: 2;
  monitoringMode: MonitoringMode;
  severityFilter: Severity[];
  retainHistoryDays: number;
  maxHistoryPerOrigin: number;
  sensitiveCookieNames: string[];
  ignoredCookieNames: string[];
  evaluationMode: boolean;
  /** User-defined scope profiles for bug-bounty targets and programs. */
  scopeProfiles?: ScopeProfile[];
  /** Active scope profile ID, or null if unassigned / global. */
  activeScopeProfileId?: string | null;
  /** Appearance: color theme preference. 'system' follows prefers-color-scheme. */
  theme?: 'system' | 'dark' | 'light';
  /** Appearance: layout density for lists and tables. */
  density?: 'comfortable' | 'compact';
  /** Appearance: motion preference override. 'system' follows prefers-reduced-motion. */
  reducedMotion?: 'system' | 'always' | 'never';
  legacyAllowedOrigins?: string[];
  /** Legacy fields for backward compatibility */
  allowedOrigins?: string[];
  alwaysSensitiveCookies?: string[];
  alwaysIgnoreCookies?: string[];
  isEvaluation?: boolean;
  isPro?: boolean;
}

export type Settings = SettingsV2;

export interface ApiHop {
  requestId: string;
  tabId: number;
  url: string;
  normalizedPath: string; // origin + pathname (no query params)
  method: string;
  status: number;
  requestOrigin?: string | undefined; // from request headers
  headers: Record<string, string>;
  rawHeaders: Array<{ name: string; value: string }>;
  isThirdParty?: boolean | undefined; // computed after capture
  timestamp?: number | undefined;
  fromCache?: boolean | undefined;
  /** Navigation generation counter for the owning tab. */
  generation?: number;
}

export interface ApiEndpointState {
  normalizedPath: string;
  lastHop: ApiHop;
  findings: Finding[];
  isFirstParty: boolean;
}

// ─── Posture diff (Pre-login vs. Post-login) ──────────────────────────────────

export interface CompactFinding {
  ruleId: string;
  title: string;
  severity: Severity;
}

export interface AuthBaseline {
  origin: string;
  tabId?: number | undefined;
  url?: string | undefined;
  cookies: CookieRecord[];
  findings: CompactFinding[] | Finding[];
  score: number;
  grade: Grade;
  timestamp: number;
  hasSensitiveCookie: boolean;
  sensitiveCookieSignature?: string | undefined;
  lastAuthEventTimestamp?: number | undefined;
}

export interface AuthDiffFindingChange {
  ruleId: string;
  title: string;
  severity: Severity;
  type: 'added' | 'removed' | 'modified';
  oldSeverity?: Severity | undefined;
}

export interface AuthDiffRecord {
  origin: string;
  tabId?: number | undefined;
  timestamp: number;
  triggeredByCookie: string;
  triggerReason?: string | undefined;
  preAuthScore: number;
  postAuthScore: number;
  scoreDelta: number;
  preAuthGrade: Grade;
  postAuthGrade: Grade;
  preAuthUrl?: string | undefined;
  postAuthUrl?: string | undefined;
  scope?: 'origin' | 'page' | undefined;
  preAuthFindings: CompactFinding[];
  postAuthFindings: CompactFinding[];
  changes: AuthDiffFindingChange[];
}

// ─── Attack Surface Graph ─────────────────────────────────────────────────────

export type DiscoveredVia = 'csp' | 'cookie' | 'cors' | 'navigation' | 'api';

export interface DiscoveredNode {
  hostname: string;
  discoveredVia: DiscoveredVia;
  sourceHost?: string | undefined;
}

export interface GraphNode {
  hostname: string;
  isApex: boolean;
  score?: number;
  grade?: Grade;
  lastSeen: number;
  discoveredVia: DiscoveredVia[];
  scopeStatus?: ScopeStatus | undefined;
}

export interface GraphEdge {
  source: string;
  target: string;
  type: 'cookie' | 'csp' | 'cors' | 'frame';
  severity: Severity;
  provenance?: 'observed' | 'inferred';
}

export interface AttackSurfaceGraph {
  apexDomain: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  isEvaluation?: boolean;
  /** @deprecated Use isEvaluation instead */
  isPro?: boolean;
  lastUpdated: number;
}
