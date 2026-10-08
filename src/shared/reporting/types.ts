/**
 * Reporting & Researcher Triage Contracts.
 *
 * Authoritative contracts for bug-bounty reporting, evidence management,
 * and researcher triage workflow in ACULYX:
 * - ResearcherReviewState: Local triage annotations decoupled from immutable findings.
 * - FindingReportDetail: Structured vulnerability report detail with sanitized evidence.
 * - BugBountyReportDraft: Complete Markdown & JSON report export model.
 * - Invariant: Zero secret leakage — credentials, tokens, sensitive path segments,
 *   and raw cookies are strictly redacted from evidence and reports.
 * - Invariant: Incognito session isolation — private window findings are never persisted.
 */

import type { ScopeStatus } from '../scope/contracts';
import type { Severity } from '../types';

/**
 * Triage workflow status assigned by the researcher.
 * Decoupled from automated scanner findings to preserve audit integrity.
 */
export type ResearcherReviewState =
  | 'unreviewed'
  | 'needs-manual-verification'
  | 'verified-by-researcher'
  | 'not-reproducible'
  | 'not-a-finding';

/**
 * Detailed technical breakdown of a finding prepared for bug bounty submission.
 */
export interface FindingReportDetail {
  /** Ordered steps to reproduce the vulnerability. */
  reproductionSteps: string[];
  /** System, network, or authentication prerequisites required for reproduction. */
  preconditions: string[];
  /** Expected secure behavior according to RFCs / security guidelines. */
  expectedBehavior: string;
  /** Actual observed insecure behavior from passive analysis. */
  observedBehavior: string;
  /** Realistic security impact analysis ("so what happens if exploited?"). */
  impact: string;
  /** Sanitized, length-capped proof string with credentials and secrets redacted. */
  sanitizedEvidence: string;
  /** Explicit scanner coverage limitations or ambiguity caveats. */
  limitations: string[];
  /** Optional note regarding program scope rules and target boundaries. */
  scopeNote?: string | undefined;
  /** Prescriptive, actionable remediation guidance for developers. */
  remediation: string;
  /** Current scope status at the time of reporting. */
  scopeStatus?: ScopeStatus | undefined;
}

/**
 * Local triage annotation attached to a finding by the researcher.
 * Stored in local triage store without mutating the immutable Finding record.
 */
export interface TriageAnnotation {
  /** Stable finding identifier. */
  findingId: string;
  /** Researcher's triage classification. */
  state: ResearcherReviewState;
  /** Optional researcher comments, validation notes, or bug tracker ticket ID. */
  notes?: string | undefined;
  /** Unix timestamp (ms) when this annotation was last modified. */
  updatedAt: number;
}

/**
 * Complete bug-bounty report draft suitable for Markdown or JSON export.
 */
export interface BugBountyReportDraft {
  /** Optional unique report identifier. */
  id?: string | undefined;
  /** Report title adhering to bug bounty standards (e.g. "[Impact] on [Endpoint]"). */
  title: string;
  /** Finding severity rating. */
  severity: Severity;
  /** Vulnerable target URL or origin. */
  target: string;
  /** Executive summary of the issue. */
  summary: string;
  /** Numbered, deterministic reproduction steps. */
  reproductionSteps: string[];
  /** Preconditions required to trigger the issue. */
  preconditions: string[];
  /** Expected secure configuration or behavior. */
  expectedBehavior: string;
  /** Observed insecure configuration or response behavior. */
  observedBehavior: string;
  /** Detailed impact narrative with threat model context. */
  impact: string;
  /** Sanitized evidence string (strictly free of secrets/canary tokens). */
  evidence: string;
  /** Remediation instructions including code/config examples. */
  remediation: string;
  /** Technical limitations and coverage caveats of the detection. */
  limitations: string[];
  /** Program scope classification for this finding. */
  scopeStatus?: ScopeStatus | undefined;
  /** Current researcher review / verification status. */
  reviewState: ResearcherReviewState;
  /** Unix timestamp (ms) when the draft was created. */
  createdAt?: number | undefined;
  /** Unix timestamp (ms) when the draft was last updated. */
  updatedAt?: number | undefined;
  /** Stable rule identifier that generated the base finding. */
  ruleId?: string | undefined;
  /** Common Weakness Enumeration ID (e.g., 'CWE-16', 'CWE-614'). */
  cweId?: string | undefined;
  /** Common Vulnerability Scoring System (CVSS) base score. */
  cvssScore?: number | undefined;
  /** Canonical security references and documentation URLs. */
  references?: string[] | undefined;
}
