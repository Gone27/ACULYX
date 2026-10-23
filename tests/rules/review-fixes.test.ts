import { describe, it, expect } from 'vitest';
import { checkHsts } from '../../src/rules/headers/hsts';
import { checkXcto } from '../../src/rules/headers/xcto';
import { checkCsp } from '../../src/rules/headers/csp';
import { isSensitiveCookie } from '../../src/rules/utils';
import { detectSecrets } from '../../src/leads/detectors/f1-secrets';
import type { Hop } from '../../src/shared/types';

function hop(url: string, raw: Array<[string, string]>): Hop {
  const headers: Record<string, string> = {};
  for (const [k, v] of raw) headers[k.toLowerCase()] = v;
  return {
    requestId: '1',
    url,
    status: 200,
    headers,
    rawHeaders: raw.map(([name, value]) => ({ name, value })),
    fromCache: false,
    isHstsUpgrade: false,
    capturedAt: 'onResponseStarted',
    headersDiffer: false,
    timestamp: Date.now(),
  };
}
const ids = (f: Array<{ ruleId: string }>): string[] => f.map((x) => x.ruleId);
const BASE = "; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";
const csp = (v: string) => checkCsp(hop('https://a.com/', [['Content-Security-Policy', v]]));

describe('HSTS parsing', () => {
  it('accepts quoted max-age', () => {
    const f = checkHsts(hop('https://a.com/', [['Strict-Transport-Security', 'max-age="31536000"; includeSubDomains']]));
    expect(ids(f)).not.toContain('HSTS-002');
  });
  it('first max-age wins and name case is ignored', () => {
    const f = checkHsts(hop('https://a.com/', [['Strict-Transport-Security', 'MAX-AGE=10; max-age=31536000; INCLUDESUBDOMAINS']]));
    expect(ids(f)).toContain('HSTS-002');
  });
  it('does not treat a substring as includeSubDomains', () => {
    const f = checkHsts(hop('https://a.com/', [['Strict-Transport-Security', 'max-age=31536000; includeSubDomainsX']]));
    expect(ids(f)).toContain('HSTS-003');
  });
});

describe('XCTO duplicates', () => {
  it('"nosniff, nosniff" is effective', () => {
    expect(checkXcto(hop('https://a.com/', [['X-Content-Type-Options', 'nosniff, nosniff']]))).toHaveLength(0);
  });
  it('"sniff" is still reported', () => {
    expect(checkXcto(hop('https://a.com/', [['X-Content-Type-Options', 'sniff']]))).toHaveLength(1);
  });
});

describe('CSP gaps', () => {
  it('flags uppercase keywords', () => {
    expect(ids(csp("script-src 'self' 'UNSAFE-INLINE'" + BASE).findings)).toContain('CSP-002');
  });
  it('flags blob: and unsafe-hashes', () => {
    const r = ids(csp("script-src 'self' blob: 'unsafe-hashes' 'sha256-abc='" + BASE).findings);
    expect(r).toContain('CSP-004B');
    expect(r).toContain('CSP-004H');
  });
  it('flags script-src-elem / script-src-attr overrides', () => {
    const r = ids(csp("script-src 'self'; script-src-elem 'self' 'unsafe-inline'; script-src-attr 'unsafe-inline'" + BASE).findings);
    expect(r).toContain('CSP-002E');
    expect(r).toContain('CSP-002A');
  });
  it('flags frame-ancestors that allows everything', () => {
    expect(ids(csp("default-src 'self'; frame-ancestors *").findings)).toContain('CSP-005W');
    expect(ids(csp("default-src 'self'; frame-ancestors https:").findings)).toContain('CSP-005W');
    expect(ids(csp("default-src 'self'; frame-ancestors 'none'").findings)).not.toContain('CSP-005W');
  });
  it('intersects multiple enforced policies instead of last-header-wins', () => {
    const h = hop('https://a.com/', [
      ['Content-Security-Policy', "default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"],
      ['Content-Security-Policy', 'default-src *'],
    ]);
    const r = checkCsp(h);
    expect(ids(r.findings)).toContain('CSP-011');
    expect(ids(r.findings)).not.toContain('CSP-004'); // strict policy has no wildcard, so it is not effective
    expect(r.directives.has('frame-ancestors')).toBe(true);
  });
});

describe('cookie sensitivity', () => {
  it.each(['SSID', 'refreshToken', '.AspNetCore.Cookies', '.ASPXAUTH', 'userid', 'xsrf_session', 'sessionid'])(
    '%s is sensitive', (n) => expect(isSensitiveCookie(n).isSensitive).toBe(true));
  it.each(['_ga', 'theme', 'csrftoken', 'XSRF-TOKEN', 'lang'])('%s stays non-sensitive', (n) =>
    expect(isSensitiveCookie(n).isSensitive).toBe(false));
});

describe('secret detectors', () => {
  const hit = (code: string) => detectSecrets(code, 'https://a.com/app.js', 'in-scope').map((l) => l.title).join('|');
  it('matches legacy OpenAI keys (T3BlbkFJ regex was malformed)', () => {
    expect(hit('k="sk-' + 'A'.repeat(20) + 'T3BlbkFJ' + 'b'.repeat(20) + '"')).toMatch(/OpenAI/);
  });
  it('matches fine-grained GitHub PAT', () => {
    expect(hit('t="github_pat_' + 'Ab3dE5gH7jK9mN1pQ3sT5vX7zB9dF1hJ3lN5pR7tV9xZ1bD3fH5jL7nP9rT'.slice(0, 60) + '"')).toMatch(/Fine-Grained/);
  });
  it('matches Hugging Face and hard-coded Bearer', () => {
    expect(hit('t="hf_AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIj"')).toMatch(/Hugging Face/);
    expect(hit('headers:{Authorization:"Bearer a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6"}')).toMatch(/Bearer/);
  });
  it('does not flag placeholders', () => {
    expect(hit('t="hf_YOUR_TOKEN_GOES_HERE_xxxxxxxxxxxxxxxxxxxx"')).toBe('');
  });
});
