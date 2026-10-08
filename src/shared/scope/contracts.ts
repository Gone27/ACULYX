/**
 * Scope Engine Contracts & Interface Definitions.
 *
 * Authoritative contracts for ACULYX scope evaluation:
 * - ScopeStatus: 'in-scope' | 'out-of-scope' | 'unknown'
 * - Host & Port Normalization: IDNA lowercase, trailing-dot removal,
 *   explicit port preservation, and deliberate apex vs. wildcard boundaries
 *   (e.g., *.example.com does NOT match example.com unless explicitly listed).
 * - Exclusions take precedence over inclusions.
 */

/**
 * High-level scope classification of a target URL or host.
 * - 'in-scope': Target matches an active inclusion rule and is not excluded.
 * - 'out-of-scope': Target matches an exclusion rule or falls outside bounded targets.
 * - 'unknown': Target has no matching rule or third-party context is unclassified.
 */
export type ScopeStatus = 'in-scope' | 'out-of-scope' | 'unknown';

/**
 * Result of evaluating a target host or URL against scope rules.
 */
export interface ScopeResult {
  /** Determined scope status. */
  status: ScopeStatus;
  /** Matched rule pattern if a rule triggered the determination. */
  matchedPattern?: string | undefined;
  /** Human-readable explanation of why the target received this status. */
  reason: string;
  /** Type of rule that matched, if any. */
  ruleType?: 'include' | 'exclude' | undefined;
}

/**
 * A single declarative rule within a scope profile.
 */
export interface ScopeRule {
  /** Target domain, wildcard pattern (e.g., '*.example.com'), or host with explicit port. */
  pattern: string;
  /** Whether matching targets are included or excluded (exclusions take precedence). */
  type: 'include' | 'exclude';
  /** Optional human-readable rationale or program note. */
  description?: string | undefined;
}

/**
 * Named scope profile containing a set of inclusion and exclusion rules.
 */
export interface ScopeProfile {
  /** Unique identifier for the profile. */
  id: string;
  /** Human-readable name for the profile / bounty program. */
  name: string;
  /** Ordered list of scope rules. */
  rules: ScopeRule[];
  /** Optional program notes or policy guidelines. */
  notes?: string | undefined;
  /** Unix timestamp (ms) when the profile was last audited or updated. */
  lastReviewed?: number | undefined;
}

/**
 * Normalized representation of a scope evaluation target.
 *
 * Normalization requirements:
 * 1. Hostname is normalized using IDNA/punycode, lowercase, and trailing dot stripped.
 * 2. Scheme (http/https) and explicit port (e.g., 8443) are preserved separately.
 * 3. Wildcard boundary flag is preserved (e.g., *.example.com vs example.com).
 */
export interface NormalizedScopeTarget {
  /** Original raw input string. */
  raw: string;
  /** Normalized URL scheme if present (e.g., 'https', 'http'). */
  scheme?: string | undefined;
  /** Normalized lowercase IDNA hostname. */
  hostname: string;
  /** Explicit port number if specified, preserved without silent truncation. */
  port?: number | undefined;
  /** Whether the target represents a wildcard pattern (e.g., *.domain.com). */
  isWildcard: boolean;
}
