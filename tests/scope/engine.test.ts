import { describe, it, expect } from 'vitest';
import { ScopeEngine } from '../../src/shared/scope/engine';
import type { ScopeProfile } from '../../src/shared/scope/contracts';

describe('ScopeEngine', () => {
  const profile: ScopeProfile = {
    id: 'test-profile',
    name: 'Acme Bounty Scope',
    rules: [
      { pattern: 'admin.acme.com', type: 'exclude', description: 'Internal admin panel excluded' },
      { pattern: '*.acme.com', type: 'include', description: 'All subdomains' },
      { pattern: 'acme.com', type: 'include', description: 'Apex site' },
      { pattern: 'api.acme.com:8443', type: 'include', description: 'Dedicated staging port' },
    ],
  };

  it('enforces exclusion precedence over wildcard inclusion', () => {
    const engine = new ScopeEngine(profile);
    const result = engine.evaluate('https://admin.acme.com/dashboard');

    expect(result.status).toBe('out-of-scope');
    expect(result.ruleType).toBe('exclude');
    expect(result.matchedPattern).toBe('admin.acme.com');
    expect(result.reason).toContain('exclusion rule admin.acme.com');
  });

  it('classifies matching wildcard subdomain as in-scope', () => {
    const engine = new ScopeEngine(profile);
    const result = engine.evaluate('https://payments.acme.com/checkout');

    expect(result.status).toBe('in-scope');
    expect(result.ruleType).toBe('include');
    expect(result.matchedPattern).toBe('*.acme.com');
  });

  it('classifies explicitly listed apex as in-scope', () => {
    const engine = new ScopeEngine(profile);
    const result = engine.evaluate('https://acme.com/');

    expect(result.status).toBe('in-scope');
    expect(result.matchedPattern).toBe('acme.com');
  });

  it('returns unknown for unconfigured third-party targets', () => {
    const engine = new ScopeEngine(profile);
    const result = engine.evaluate('https://external-auth.partner.com/oauth');

    expect(result.status).toBe('unknown');
    expect(result.ruleType).toBeUndefined();
    expect(result.reason).toContain('is not covered by any configured scope rule');
  });

  it('evaluates redirect hops independently', () => {
    const engine = new ScopeEngine(profile);
    const redirectResult = engine.evaluateRedirectHop(
      'https://external-auth.partner.com/oauth',
      'https://payments.acme.com/login',
    );

    expect(redirectResult.status).toBe('unknown');
    expect(redirectResult.reason).toContain('Redirect hop (redirected from');
  });

  it('evaluates third-party subresources independently', () => {
    const engine = new ScopeEngine(profile);
    const thirdPartyResult = engine.evaluateThirdParty(
      'https://cdn.thirdparty.com/library.js',
      'https://acme.com/',
    );

    expect(thirdPartyResult.status).toBe('unknown');
    expect(thirdPartyResult.reason).toContain('Subresource evaluated independently');
  });

  it('returns unknown when engine has no configured rules', () => {
    const emptyEngine = new ScopeEngine([]);
    expect(emptyEngine.evaluate('https://example.com').status).toBe('unknown');
  });
});
