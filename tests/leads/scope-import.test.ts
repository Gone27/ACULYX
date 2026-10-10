import { describe, it, expect } from 'vitest';
import {
  parseHackerOneScope,
  parseBugcrowdScope,
  parseIntigritiScope,
  generateNameOnlyWordlist,
} from '../../src/leads/export/export';

describe('Scope Import Parsers', () => {
  it('parses HackerOne structured scope JSON into ScopeProfile', () => {
    const h1Json = JSON.stringify({
      program: 'Acme-Security',
      structured_scopes: [
        { asset_identifier: '*.acme.com', asset_type: 'URL', eligible_for_bounty: true, instruction: 'In scope' },
        { asset_identifier: 'out-of-scope.acme.com', asset_type: 'URL', eligible_for_bounty: false, instruction: 'Do not test' },
      ],
    });

    const profile = parseHackerOneScope(h1Json);
    expect(profile.name).toBe('Acme-Security');
    expect(profile.rules.length).toBe(2);
    expect(profile.rules[0].pattern).toBe('*.acme.com');
    expect(profile.rules[0].effect).toBe('in-scope');
    expect(profile.rules[1].pattern).toBe('out-of-scope.acme.com');
    expect(profile.rules[1].effect).toBe('out-of-scope');
  });

  it('parses Bugcrowd target scope JSON into ScopeProfile', () => {
    const bcJson = JSON.stringify({
      name: 'Bugcrowd-Target',
      targets: [
        { uri: 'https://api.target.com', category: 'api' },
        { uri: 'https://admin.target.com', category: 'out_of_scope' },
      ],
    });

    const profile = parseBugcrowdScope(bcJson);
    expect(profile.name).toBe('Bugcrowd-Target');
    expect(profile.rules[0].effect).toBe('in-scope');
    expect(profile.rules[1].effect).toBe('out-of-scope');
  });

  it('parses Intigriti scope JSON into ScopeProfile', () => {
    const intigritiJson = JSON.stringify({
      companyName: 'Intigriti-Program',
      domains: [
        { endpoint: 'shop.intigriti.test', type: 'web', inScope: true },
        { endpoint: 'dev.intigriti.test', type: 'web', inScope: false },
      ],
    });

    const profile = parseIntigritiScope(intigritiJson);
    expect(profile.name).toBe('Intigriti-Program');
    expect(profile.rules[0].effect).toBe('in-scope');
    expect(profile.rules[1].effect).toBe('out-of-scope');
  });

  it('generates deduped name-only wordlist from discovered parameters and endpoints', () => {
    const params = ['redirect_uri', 'next', 'token', 'next', 'state', 'redirect_uri'];
    const endpoints = ['/api/v1/user', '/api/v1/auth', '/admin', '/api/v1/user'];

    const wordlist = generateNameOnlyWordlist(params, endpoints);
    const lines = wordlist.split('\n').filter(Boolean);

    // Deduped
    expect(lines).toContain('redirect_uri');
    expect(lines).toContain('next');
    expect(lines).toContain('token');
    expect(lines).toContain('state');
    expect(lines).toContain('/api/v1/user');
    expect(lines).toContain('/api/v1/auth');
    expect(lines).toContain('/admin');

    const redirectCount = lines.filter(l => l === 'redirect_uri').length;
    expect(redirectCount).toBe(1);
  });
});
