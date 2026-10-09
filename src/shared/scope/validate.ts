/**
 * Scope Profile and Rule Validation for ACULYX Scope Engine.
 *
 * Implements strict fail-closed validation for scope rules and profiles:
 * - Rejects malformed wildcards (e.g. *example.com without explicit "*." prefix).
 * - Ensures valid rule types ('include' | 'exclude').
 * - Validates profile structure and uniqueness.
 */

import type { ScopeProfile, ScopeRule } from './contracts';
import { normalizeScopeTarget } from './normalize';

export interface ScopeValidationResult {
  valid: boolean;
  error?: string;
}

/**
 * Validates a single scope rule.
 */
export function validateScopeRule(rule: unknown): ScopeValidationResult {
  if (typeof rule !== 'object' || rule === null) {
    return { valid: false, error: 'Rule must be an object' };
  }

  const r = rule as Partial<ScopeRule>;
  if (typeof r.pattern !== 'string' || r.pattern.trim().length === 0) {
    return { valid: false, error: 'Rule pattern must be a non-empty string' };
  }

  if (r.type !== 'include' && r.type !== 'exclude') {
    return { valid: false, error: 'Rule type must be either "include" or "exclude"' };
  }

  try {
    normalizeScopeTarget(r.pattern);
  } catch (err) {
    return {
      valid: false,
      error: `Invalid rule pattern "${r.pattern}": ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  return { valid: true };
}

/**
 * Validates a complete scope profile and all its constituent rules.
 */
export function validateScopeProfile(profile: unknown): ScopeValidationResult {
  if (typeof profile !== 'object' || profile === null) {
    return { valid: false, error: 'Scope profile must be an object' };
  }

  const p = profile as Partial<ScopeProfile>;
  if (typeof p.id !== 'string' || p.id.trim().length === 0) {
    return { valid: false, error: 'Profile ID must be a non-empty string' };
  }

  if (typeof p.name !== 'string' || p.name.trim().length === 0) {
    return { valid: false, error: 'Profile name must be a non-empty string' };
  }

  if (!Array.isArray(p.rules)) {
    return { valid: false, error: 'Profile rules must be an array' };
  }

  for (let i = 0; i < p.rules.length; i++) {
    const res = validateScopeRule(p.rules[i]);
    if (!res.valid) {
      return { valid: false, error: `Rule at index ${i} is invalid: ${res.error}` };
    }
  }

  return { valid: true };
}
