/**
 * Pure Deterministic Domain & Wildcard Matcher for ACULYX Scope Engine.
 *
 * Implements:
 * - Exact host matching (e.g. api.example.com)
 * - Wildcard boundaries (*.example.com matches subdomains, but NOT apex example.com)
 * - Preserved explicit port matching (e.g. host:8443)
 * - Scheme boundary matching when specified
 */

import type { NormalizedScopeTarget, ScopeRule } from './contracts';
import { normalizeScopeTarget } from './normalize';

/**
 * Checks whether targetHost is a true subdomain of parentHost.
 * Strictly enforces that apex parentHost itself is NOT a subdomain of itself.
 * Example:
 * - 'api.example.com' isSubdomainOf 'example.com' -> true
 * - 'sub.api.example.com' isSubdomainOf 'example.com' -> true
 * - 'example.com' isSubdomainOf 'example.com' -> false (apex boundary)
 * - 'fakeexample.com' isSubdomainOf 'example.com' -> false
 */
export function isSubdomainOf(targetHost: string, parentHost: string): boolean {
  const normTarget = targetHost.toLowerCase();
  const normParent = parentHost.toLowerCase();

  if (normTarget === normParent) {
    return false; // Apex is not a subdomain
  }

  return normTarget.endsWith(`.${normParent}`);
}

/**
 * Evaluates whether a normalized target matches a normalized scope rule.
 */
export function matchTarget(
  target: NormalizedScopeTarget,
  ruleInput: ScopeRule | NormalizedScopeTarget
): boolean {
  const rule: NormalizedScopeTarget =
    'isWildcard' in ruleInput
      ? ruleInput
      : normalizeScopeTarget(ruleInput.pattern);

  // 1. Port match: if rule specifies an explicit port, target must have the identical port
  if (rule.port !== undefined) {
    if (target.port !== rule.port) {
      return false;
    }
  }

  // 2. Scheme match: if rule specifies a scheme, target must have the identical scheme (fail closed)
  if (rule.scheme !== undefined) {
    if (target.scheme === undefined || target.scheme !== rule.scheme) {
      return false;
    }
  }

  // 3. Hostname match
  if (rule.isWildcard) {
    // Wildcard rule (*.example.com): matches subdomains, but NOT apex
    return isSubdomainOf(target.hostname, rule.hostname);
  }

  // Exact rule (example.com or api.example.com): matches only exact host
  return target.hostname === rule.hostname;
}

/**
 * Checks if target matches the apex domain exactly.
 */
export function isApexMatch(targetHost: string, apexHost: string): boolean {
  return targetHost.toLowerCase() === apexHost.toLowerCase();
}
