import { describe, it, expect } from 'vitest';
import type {
  ScopeStatus,
  ScopeResult,
  ScopeRule,
  ScopeProfile,
  NormalizedScopeTarget,
} from '../../src/shared/scope/contracts';

/**
 * Runtime validator for ScopeStatus.
 */
function isScopeStatus(val: unknown): val is ScopeStatus {
  return val === 'in-scope' || val === 'out-of-scope' || val === 'unknown';
}

/**
 * Runtime validator for ScopeResult.
 */
function isValidScopeResult(res: unknown): res is ScopeResult {
  if (typeof res !== 'object' || res === null) return false;
  const r = res as Record<string, unknown>;
  if (!isScopeStatus(r['status'])) return false;
  if (typeof r['reason'] !== 'string' || r['reason'].length === 0) return false;
  if (r['matchedPattern'] !== undefined && typeof r['matchedPattern'] !== 'string') return false;
  if (
    r['ruleType'] !== undefined &&
    r['ruleType'] !== 'include' &&
    r['ruleType'] !== 'exclude'
  ) {
    return false;
  }
  return true;
}

/**
 * Runtime validator for ScopeRule.
 */
function isValidScopeRule(rule: unknown): rule is ScopeRule {
  if (typeof rule !== 'object' || rule === null) return false;
  const r = rule as Record<string, unknown>;
  if (typeof r['pattern'] !== 'string' || r['pattern'].length === 0) return false;
  if (r['type'] !== 'include' && r['type'] !== 'exclude') return false;
  if (r['description'] !== undefined && typeof r['description'] !== 'string') return false;
  return true;
}

/**
 * Runtime validator for ScopeProfile.
 */
function isValidScopeProfile(prof: unknown): prof is ScopeProfile {
  if (typeof prof !== 'object' || prof === null) return false;
  const p = prof as Record<string, unknown>;
  if (typeof p['id'] !== 'string' || p['id'].length === 0) return false;
  if (typeof p['name'] !== 'string' || p['name'].length === 0) return false;
  if (!Array.isArray(p['rules'])) return false;
  for (const rule of p['rules']) {
    if (!isValidScopeRule(rule)) return false;
  }
  if (p['notes'] !== undefined && typeof p['notes'] !== 'string') return false;
  if (p['lastReviewed'] !== undefined && (typeof p['lastReviewed'] !== 'number' || isNaN(p['lastReviewed']))) {
    return false;
  }
  return true;
}

/**
 * Runtime validator for NormalizedScopeTarget.
 */
function isValidNormalizedScopeTarget(target: unknown): target is NormalizedScopeTarget {
  if (typeof target !== 'object' || target === null) return false;
  const t = target as Record<string, unknown>;
  if (typeof t['raw'] !== 'string') return false;
  if (typeof t['hostname'] !== 'string' || t['hostname'].length === 0) return false;
  if (typeof t['isWildcard'] !== 'boolean') return false;
  if (t['scheme'] !== undefined && typeof t['scheme'] !== 'string') return false;
  if (
    t['port'] !== undefined &&
    (typeof t['port'] !== 'number' || !Number.isInteger(t['port']) || t['port'] < 1 || t['port'] > 65535)
  ) {
    return false;
  }
  return true;
}

describe('Scope Contracts (R0)', () => {
  describe('ScopeStatus', () => {
    it('accepts all three valid status values', () => {
      const inScope: ScopeStatus = 'in-scope';
      const outOfScope: ScopeStatus = 'out-of-scope';
      const unknownStatus: ScopeStatus = 'unknown';

      expect(isScopeStatus(inScope)).toBe(true);
      expect(isScopeStatus(outOfScope)).toBe(true);
      expect(isScopeStatus(unknownStatus)).toBe(true);
    });

    it('rejects invalid or ambiguous status strings', () => {
      expect(isScopeStatus('allowed')).toBe(false);
      expect(isScopeStatus('blocked')).toBe(false);
      expect(isScopeStatus('in_scope')).toBe(false);
      expect(isScopeStatus('')).toBe(false);
      expect(isScopeStatus(null)).toBe(false);
      expect(isScopeStatus(undefined)).toBe(false);
    });
  });

  describe('ScopeResult', () => {
    it('constructs a minimal ScopeResult without optional fields', () => {
      const result: ScopeResult = {
        status: 'unknown',
        reason: 'No matching scope rule configured',
      };

      expect(isValidScopeResult(result)).toBe(true);
      expect(result.status).toBe('unknown');
      expect(result.reason).toBe('No matching scope rule configured');
      expect(result.matchedPattern).toBeUndefined();
      expect(result.ruleType).toBeUndefined();
    });

    it('constructs a full in-scope ScopeResult with include ruleType', () => {
      const result: ScopeResult = {
        status: 'in-scope',
        matchedPattern: '*.example.com',
        reason: 'Matched wildcard include rule *.example.com',
        ruleType: 'include',
      };

      expect(isValidScopeResult(result)).toBe(true);
      expect(result.status).toBe('in-scope');
      expect(result.matchedPattern).toBe('*.example.com');
      expect(result.ruleType).toBe('include');
    });

    it('constructs an out-of-scope ScopeResult with exclude ruleType', () => {
      const result: ScopeResult = {
        status: 'out-of-scope',
        matchedPattern: 'logout.example.com',
        reason: 'Target is explicitly excluded by scope rule',
        ruleType: 'exclude',
      };

      expect(isValidScopeResult(result)).toBe(true);
      expect(result.status).toBe('out-of-scope');
      expect(result.matchedPattern).toBe('logout.example.com');
      expect(result.ruleType).toBe('exclude');
    });

    it('rejects invalid ScopeResult objects', () => {
      expect(isValidScopeResult({ status: 'in-scope' })).toBe(false); // missing reason
      expect(isValidScopeResult({ status: 'invalid', reason: 'foo' })).toBe(false); // invalid status
      expect(isValidScopeResult({ status: 'in-scope', reason: '', ruleType: 'include' })).toBe(false); // empty reason
      expect(isValidScopeResult({ status: 'in-scope', reason: 'ok', ruleType: 'other' })).toBe(false); // invalid ruleType
    });
  });

  describe('ScopeRule', () => {
    it('creates valid include and exclude rules with patterns', () => {
      const includeRule: ScopeRule = {
        pattern: '*.target.io',
        type: 'include',
        description: 'Primary customer-facing domain tree',
      };

      const excludeRule: ScopeRule = {
        pattern: 'admin.target.io',
        type: 'exclude',
        description: 'Internal employee administration portal out of scope',
      };

      expect(isValidScopeRule(includeRule)).toBe(true);
      expect(isValidScopeRule(excludeRule)).toBe(true);
      expect(includeRule.type).toBe('include');
      expect(excludeRule.type).toBe('exclude');
    });

    it('supports rules with explicit port patterns', () => {
      const portRule: ScopeRule = {
        pattern: 'api.target.io:8443',
        type: 'include',
        description: 'Specific testing service on custom TLS port',
      };

      expect(isValidScopeRule(portRule)).toBe(true);
      expect(portRule.pattern).toBe('api.target.io:8443');
      expect(portRule.description).toBe('Specific testing service on custom TLS port');
    });

    it('rejects malformed ScopeRule objects', () => {
      expect(isValidScopeRule({ pattern: '', type: 'include' })).toBe(false);
      expect(isValidScopeRule({ pattern: 'example.com', type: 'allow' })).toBe(false);
      expect(isValidScopeRule({ type: 'include' })).toBe(false);
    });
  });

  describe('ScopeProfile', () => {
    it('constructs a minimal ScopeProfile', () => {
      const profile: ScopeProfile = {
        id: 'bounty-prod-001',
        name: 'Production Bug Bounty',
        rules: [],
      };

      expect(isValidScopeProfile(profile)).toBe(true);
      expect(profile.rules).toHaveLength(0);
      expect(profile.notes).toBeUndefined();
      expect(profile.lastReviewed).toBeUndefined();
    });

    it('constructs a comprehensive ScopeProfile with include and exclude precedence rules', () => {
      const now = Date.now();
      const profile: ScopeProfile = {
        id: 'hackerone-corp',
        name: 'Acme Corp VDP',
        rules: [
          { pattern: 'admin.acme.com', type: 'exclude', description: 'Third-party admin portal' },
          { pattern: '*.acme.com', type: 'include', description: 'All *.acme.com subdomains' },
          { pattern: 'acme.com', type: 'include', description: 'Apex website' },
          { pattern: 'payments.partner.net', type: 'exclude', description: 'Payment gateway out of scope' },
        ],
        notes: 'Strict exclusion precedence: exclusions take priority over wildcard includes.',
        lastReviewed: now,
      };

      expect(isValidScopeProfile(profile)).toBe(true);
      expect(profile.rules).toHaveLength(4);
      expect(profile.rules[0]?.type).toBe('exclude');
      expect(profile.rules[1]?.type).toBe('include');
      expect(profile.lastReviewed).toBe(now);
    });

    it('rejects profiles with invalid structure or invalid rules', () => {
      expect(isValidScopeProfile({ id: '', name: 'Test', rules: [] })).toBe(false);
      expect(isValidScopeProfile({ id: '1', name: '', rules: [] })).toBe(false);
      expect(isValidScopeProfile({ id: '1', name: 'Test', rules: [{ pattern: '', type: 'bad' }] })).toBe(false);
    });
  });

  describe('NormalizedScopeTarget', () => {
    it('represents an apex host without scheme or port', () => {
      const target: NormalizedScopeTarget = {
        raw: 'example.com',
        hostname: 'example.com',
        isWildcard: false,
      };

      expect(isValidNormalizedScopeTarget(target)).toBe(true);
      expect(target.hostname).toBe('example.com');
      expect(target.isWildcard).toBe(false);
      expect(target.scheme).toBeUndefined();
      expect(target.port).toBeUndefined();
    });

    it('preserves scheme and explicit port separately without silent truncation', () => {
      const target: NormalizedScopeTarget = {
        raw: 'https://staging.example.com:8443/login',
        scheme: 'https',
        hostname: 'staging.example.com',
        port: 8443,
        isWildcard: false,
      };

      expect(isValidNormalizedScopeTarget(target)).toBe(true);
      expect(target.scheme).toBe('https');
      expect(target.hostname).toBe('staging.example.com');
      expect(target.port).toBe(8443);
      expect(target.isWildcard).toBe(false);
    });

    it('marks wildcard patterns correctly', () => {
      const target: NormalizedScopeTarget = {
        raw: '*.sub.example.org',
        hostname: 'sub.example.org',
        isWildcard: true,
      };

      expect(isValidNormalizedScopeTarget(target)).toBe(true);
      expect(target.isWildcard).toBe(true);
      expect(target.hostname).toBe('sub.example.org');
    });

    it('handles IDNA punycode hostnames in normalized format', () => {
      const target: NormalizedScopeTarget = {
        raw: 'https://xn--e1afmkfd.xn--p1ai:443',
        scheme: 'https',
        hostname: 'xn--e1afmkfd.xn--p1ai',
        port: 443,
        isWildcard: false,
      };

      expect(isValidNormalizedScopeTarget(target)).toBe(true);
      expect(target.hostname).toBe('xn--e1afmkfd.xn--p1ai');
      expect(target.isWildcard).toBe(false);
    });

    it('rejects targets with invalid port numbers or invalid hostnames', () => {
      expect(isValidNormalizedScopeTarget({ raw: 'test', hostname: '', isWildcard: false })).toBe(false);
      expect(isValidNormalizedScopeTarget({ raw: 'test', hostname: 'host', port: 70000, isWildcard: false })).toBe(false);
      expect(isValidNormalizedScopeTarget({ raw: 'test', hostname: 'host', port: 0, isWildcard: false })).toBe(false);
      expect(isValidNormalizedScopeTarget({ raw: 'test', hostname: 'host', isWildcard: 'no' })).toBe(false);
    });
  });
});
