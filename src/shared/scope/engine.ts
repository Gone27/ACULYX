/**
 * ACULYX Scope Engine.
 *
 * Implements:
 * - Deterministic scope evaluation with exclusion precedence:
 *   Exclusion rules take precedence over inclusion rules.
 * - Unknown scope resolution (unmatched targets return 'unknown').
 * - Independent redirect hop and third-party API scope evaluation.
 */

import type {
  NormalizedScopeTarget,
  ScopeProfile,
  ScopeResult,
  ScopeRule,
  ScopeStatus,
} from './contracts';
import { normalizeScopeTarget } from './normalize';
import { matchTarget } from './matcher';

export class ScopeEngine {
  private rules: ScopeRule[] = [];
  private profile?: ScopeProfile | undefined;

  constructor(profileOrRules?: ScopeProfile | ScopeRule[]) {
    if (profileOrRules !== undefined) {
      if (Array.isArray(profileOrRules)) {
        this.setRules(profileOrRules);
      } else {
        this.setProfile(profileOrRules);
      }
    }
  }

  public setProfile(profile: ScopeProfile): void {
    this.profile = profile;
    this.rules = [...profile.rules];
  }

  public getProfile(): ScopeProfile | undefined {
    return this.profile;
  }

  public setRules(rules: ScopeRule[]): void {
    this.rules = [...rules];
  }

  public getRules(): ScopeRule[] {
    return [...this.rules];
  }

  public addRule(rule: ScopeRule): void {
    this.rules.push(rule);
  }

  public removeRule(pattern: string): void {
    this.rules = this.rules.filter((r) => r.pattern !== pattern);
  }

  public clearRules(): void {
    this.rules = [];
    this.profile = undefined;
  }

  /**
   * Evaluates a target URL, hostname, or normalized target against the active scope rules.
   *
   * Precedence:
   * 1. Any matching exclude rule -> 'out-of-scope' (exclude precedence).
   * 2. Any matching include rule -> 'in-scope'.
   * 3. No match -> 'unknown'.
   */
  public evaluate(target: string | NormalizedScopeTarget): ScopeResult {
    let normTarget: NormalizedScopeTarget;
    try {
      normTarget = typeof target === 'string' ? normalizeScopeTarget(target) : target;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        status: 'unknown',
        reason: `Target normalization failed: ${msg}`,
      };
    }

    if (this.rules.length === 0) {
      return {
        status: 'unknown',
        reason: 'No scope rules configured in engine',
      };
    }

    // Step 1: Evaluate exclusions first (exclusion precedence)
    for (const rule of this.rules) {
      if (rule.type === 'exclude' && matchTarget(normTarget, rule)) {
        return {
          status: 'out-of-scope',
          matchedPattern: rule.pattern,
          ruleType: 'exclude',
          reason: (rule.description !== undefined && rule.description.length > 0)
            ? `Target matches exclusion rule ${rule.pattern}: ${rule.description}`
            : `Target matches exclusion rule: ${rule.pattern}`,
        };
      }
    }

    // Step 2: Evaluate inclusions
    for (const rule of this.rules) {
      if (rule.type === 'include' && matchTarget(normTarget, rule)) {
        return {
          status: 'in-scope',
          matchedPattern: rule.pattern,
          ruleType: 'include',
          reason: (rule.description !== undefined && rule.description.length > 0)
            ? `Target matches inclusion rule ${rule.pattern}: ${rule.description}`
            : `Target matches inclusion rule: ${rule.pattern}`,
        };
      }
    }

    // Step 3: No matching rules
    return {
      status: 'unknown',
      reason: `Target ${normTarget.hostname} is not covered by any configured scope rule`,
    };
  }

  /**
   * Independently evaluates a redirect hop URL.
   * Redirect targets never blindly inherit the scope of the initiating request.
   */
  public evaluateRedirectHop(hopUrl: string, sourceUrl?: string): ScopeResult {
    const result = this.evaluate(hopUrl);
    const sourceContext = (sourceUrl !== undefined && sourceUrl.length > 0) ? ` (redirected from ${sourceUrl})` : '';
    return {
      ...result,
      reason: `Redirect hop${sourceContext} evaluated independently: ${result.reason}`,
    };
  }

  /**
   * Independently evaluates a third-party subresource or API endpoint URL.
   */
  public evaluateThirdParty(resourceUrl: string, firstPartyUrl: string): ScopeResult {
    const result = this.evaluate(resourceUrl);
    return {
      ...result,
      reason: `Subresource evaluated independently from page ${firstPartyUrl}: ${result.reason}`,
    };
  }

  public isTargetInScope(target: string | NormalizedScopeTarget): boolean {
    return this.evaluate(target).status === 'in-scope';
  }

  public isTargetOutOfScope(target: string | NormalizedScopeTarget): boolean {
    return this.evaluate(target).status === 'out-of-scope';
  }

  public classify(target: string | NormalizedScopeTarget): ScopeStatus {
    return this.evaluate(target).status;
  }
}

/**
 * Functional helper to evaluate scope against a profile or rule list.
 */
export function evaluateScope(
  target: string | NormalizedScopeTarget,
  profileOrRules: ScopeProfile | ScopeRule[]
): ScopeResult {
  const engine = new ScopeEngine(profileOrRules);
  return engine.evaluate(target);
}

/**
 * Functional helper to evaluate a redirect hop independently.
 */
export function evaluateRedirectHop(
  hopUrl: string,
  profileOrRules: ScopeProfile | ScopeRule[]
): ScopeResult {
  const engine = new ScopeEngine(profileOrRules);
  return engine.evaluateRedirectHop(hopUrl);
}

/**
 * Functional helper to evaluate a third-party target independently.
 */
export function evaluateThirdParty(
  resourceUrl: string,
  firstPartyUrl: string,
  profileOrRules: ScopeProfile | ScopeRule[]
): ScopeResult {
  const engine = new ScopeEngine(profileOrRules);
  return engine.evaluateThirdParty(resourceUrl, firstPartyUrl);
}
