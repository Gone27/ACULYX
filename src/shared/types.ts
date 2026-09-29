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

// ─── Coverage ─────────────────────────────────────────────────────────────────

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
}

// ─── Settings ─────────────────────────────────────────────────────────────────

export interface Settings {
  monitoringMode: MonitoringMode;
  /** Effective when monitoringMode === 'per-site'. */
  allowedOrigins: string[];
  severityFilter: Severity[];
  retainHistoryDays: number;
  alwaysSensitiveCookies: string[];
  alwaysIgnoreCookies: string[];
}

export interface ApiHop {
  requestId: string;
  tabId: number;
  url: string;
  normalizedPath: string; // origin + pathname (no query params)
  method: string;
  status: number;
  requestOrigin?: string; // from request headers
  headers: Record<string, string>;
  rawHeaders: Array<{ name: string; value: string }>;
  isThirdParty?: boolean; // computed after capture
}

export interface ApiEndpointState {
  normalizedPath: string;
  lastHop: ApiHop;
  findings: Finding[];
  isFirstParty: boolean;
}
