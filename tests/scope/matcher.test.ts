import { describe, it, expect } from 'vitest';
import { isSubdomainOf, matchTarget } from '../../src/shared/scope/matcher';
import { normalizeScopeTarget } from '../../src/shared/scope/normalize';

describe('Scope Matcher', () => {
  describe('isSubdomainOf & Apex Boundary', () => {
    it('strictly treats apex domain as NOT a subdomain of itself', () => {
      expect(isSubdomainOf('example.com', 'example.com')).toBe(false);
      expect(isSubdomainOf('TARGET.IO', 'target.io')).toBe(false);
    });

    it('identifies direct and nested subdomains', () => {
      expect(isSubdomainOf('api.example.com', 'example.com')).toBe(true);
      expect(isSubdomainOf('auth.stage.example.com', 'example.com')).toBe(true);
    });

    it('rejects unrelated domains sharing a common suffix', () => {
      expect(isSubdomainOf('notexample.com', 'example.com')).toBe(false);
      expect(isSubdomainOf('my-example.com', 'example.com')).toBe(false);
    });
  });

  describe('matchTarget with Wildcard Rules', () => {
    const wildcardRule = normalizeScopeTarget('*.acme.com');

    it('matches subdomains under wildcard', () => {
      const target1 = normalizeScopeTarget('api.acme.com');
      const target2 = normalizeScopeTarget('v1.dev.acme.com');
      expect(matchTarget(target1, wildcardRule)).toBe(true);
      expect(matchTarget(target2, wildcardRule)).toBe(true);
    });

    it('does NOT match apex domain on wildcard rule', () => {
      const apexTarget = normalizeScopeTarget('acme.com');
      expect(matchTarget(apexTarget, wildcardRule)).toBe(false);
    });
  });

  describe('matchTarget with Exact Rules', () => {
    const exactRule = normalizeScopeTarget('api.acme.com');

    it('matches exact host', () => {
      expect(matchTarget(normalizeScopeTarget('api.acme.com'), exactRule)).toBe(true);
    });

    it('does not match subdomains or apex', () => {
      expect(matchTarget(normalizeScopeTarget('sub.api.acme.com'), exactRule)).toBe(false);
      expect(matchTarget(normalizeScopeTarget('acme.com'), exactRule)).toBe(false);
    });
  });

  describe('matchTarget with Explicit Port Rules', () => {
    const portRule = normalizeScopeTarget('api.acme.com:8443');

    it('matches target with identical port', () => {
      expect(matchTarget(normalizeScopeTarget('https://api.acme.com:8443/'), portRule)).toBe(true);
    });

    it('rejects target with different or missing port', () => {
      expect(matchTarget(normalizeScopeTarget('https://api.acme.com:80/'), portRule)).toBe(false);
      expect(matchTarget(normalizeScopeTarget('https://api.acme.com/'), portRule)).toBe(false);
    });
  });

  describe('matchTarget with Scheme-Pinned Rules (Fail-Closed)', () => {
    const schemeRule = normalizeScopeTarget('https://example.com:8443');

    it('matches target with identical scheme and port', () => {
      expect(matchTarget(normalizeScopeTarget('https://example.com:8443'), schemeRule)).toBe(true);
    });

    it('rejects scheme-less target on scheme-pinned rule (fail closed)', () => {
      expect(matchTarget(normalizeScopeTarget('example.com:8443'), schemeRule)).toBe(false);
    });

    it('rejects target with mismatched scheme', () => {
      expect(matchTarget(normalizeScopeTarget('http://example.com:8443'), schemeRule)).toBe(false);
    });
  });
});
