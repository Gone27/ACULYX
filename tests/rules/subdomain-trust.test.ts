/**
 * @file subdomain-trust.test.ts
 * Vitest tests for subdomain trust & escalation analysis (subdomain-trust.ts).
 */

import { describe, it, expect } from 'vitest';
import {
  checkSubdomainTrust,
  registrableDomain,
  isSubdomain,
} from '../../src/rules/headers/subdomain-trust';
import type { Hop, CookieRecord } from '../../src/shared/types';

function makeHop(overrides: Partial<Hop> & { headers?: Record<string, string> }): Hop {
  const headers = overrides.headers ?? {};
  const rawHeaders = Object.entries(headers).map(([name, value]) => ({ name, value }));
  return {
    requestId: 'test-req',
    url: 'https://example.com/',
    status: 200,
    headers,
    rawHeaders,
    fromCache: false,
    isHstsUpgrade: false,
    capturedAt: 'onResponseStarted',
    headersDiffer: false,
    timestamp: Date.now(),
    ...overrides,
  };
}

function makeCookie(overrides: Partial<CookieRecord>): CookieRecord {
  return {
    name: 'test_cookie',
    domain: 'example.com',
    domainAttributePresent: false,
    path: '/',
    secure: true,
    httpOnly: true,
    sameSite: 'lax',
    session: false,
    expiresAt: Date.now() + 86400000,
    partitioned: false,
    setByJs: false,
    isThirdParty: false,
    ...overrides,
  };
}

describe('Domain Parsing & Subdomain Detection', () => {
  it('correctly derives registrable domain for standard TLDs', () => {
    expect(registrableDomain('example.com')).toBe('example.com');
    expect(registrableDomain('sub.example.com')).toBe('example.com');
    expect(registrableDomain('a.b.c.example.com')).toBe('example.com');
  });

  it('correctly derives registrable domain for multi-part eTLDs (e.g. .co.uk, .com.au)', () => {
    expect(registrableDomain('example.co.uk')).toBe('example.co.uk');
    expect(registrableDomain('api.example.co.uk')).toBe('example.co.uk');
    expect(registrableDomain('staging.shop.example.com.au')).toBe('example.com.au');
  });

  it('returns null for IP addresses and localhost', () => {
    expect(registrableDomain('127.0.0.1')).toBeNull();
    expect(registrableDomain('192.168.1.100')).toBeNull();
    expect(registrableDomain('localhost')).toBeNull();
  });

  it('correctly classifies subdomains vs apex', () => {
    expect(isSubdomain('example.com')).toBe(false);
    expect(isSubdomain('www.example.com')).toBe(false); // www treated as apex
    expect(isSubdomain('api.example.com')).toBe(true);
    expect(isSubdomain('app.portal.example.co.uk')).toBe(true);
  });
});

describe('Vector 1: Cookie Scope & Cookie Tossing', () => {
  it('detects domain-wide cookies scoped to .example.com (SUB-001)', () => {
    const hop = makeHop({ url: 'https://example.com/' });
    const cookies = [
      makeCookie({ name: 'session_id', domain: '.example.com' }),
    ];

    const result = checkSubdomainTrust(hop, cookies);
    expect(result.hasEscalationPath).toBe(true);
    const sub001 = result.findings.find((f) => f.ruleId === 'SUB-001');
    expect(sub001).toBeDefined();
    expect(sub001?.severity).toBe('critical');

    const v1 = result.vectors.find((v) => v.id === 'SUB-001');
    expect(v1?.present).toBe(true);
  });

  it('flags sensitive cookies lacking __Host- prefix for cookie tossing (SUB-005)', () => {
    const hop = makeHop({ url: 'https://example.com/' });
    const cookies = [
      makeCookie({ name: 'session', domain: 'example.com' }),
    ];

    const result = checkSubdomainTrust(hop, cookies);
    const sub005 = result.findings.find((f) => f.ruleId === 'SUB-005');
    expect(sub005).toBeDefined();
    expect(sub005?.severity).toBe('medium');
    expect(sub005?.title).toContain('Cookie Tossing');
  });

  it('passes when sensitive cookie uses __Host- prefix', () => {
    const hop = makeHop({
      url: 'https://example.com/',
      headers: {
        'content-security-policy': "default-src 'self'",
        'cross-origin-opener-policy': 'same-origin',
        'origin-agent-cluster': '?1',
        'x-frame-options': 'DENY',
      },
    });
    const cookies = [
      makeCookie({ name: '__Host-session', domain: '' }),
    ];

    const result = checkSubdomainTrust(hop, cookies);
    expect(result.findings.some((f) => f.ruleId === 'SUB-005')).toBe(false);
  });
});

describe('Vector 2: CSP Subdomain Trust', () => {
  it('flags CSP script-src containing *.example.com (SUB-002)', () => {
    const hop = makeHop({
      url: 'https://example.com/',
      headers: {
        'content-security-policy': "script-src 'self' *.example.com",
      },
    });

    const result = checkSubdomainTrust(hop, []);
    expect(result.hasEscalationPath).toBe(true);
    const sub002 = result.findings.find((f) => f.ruleId === 'SUB-002');
    expect(sub002).toBeDefined();
    expect(sub002?.severity).toBe('critical');
    expect(sub002?.evidence).toContain('*.example.com');
  });

  it('flags missing CSP as implicit subdomain trust (SUB-002)', () => {
    const hop = makeHop({
      url: 'https://example.com/',
      headers: {},
    });

    const result = checkSubdomainTrust(hop, []);
    expect(result.hasEscalationPath).toBe(true);
    expect(result.findings.some((f) => f.ruleId === 'SUB-002')).toBe(true);
  });
});

describe('Vector 3: CORS & Framing / Opener Trust', () => {
  it('flags CORS trusting a subdomain of the same root (SUB-003)', () => {
    const hop = makeHop({
      url: 'https://example.com/api',
      headers: {
        'access-control-allow-origin': 'https://user-content.example.com',
        'access-control-allow-credentials': 'true',
      },
    });

    const result = checkSubdomainTrust(hop, []);
    expect(result.hasEscalationPath).toBe(true);
    const sub003 = result.findings.find((f) => f.ruleId === 'SUB-003');
    expect(sub003).toBeDefined();
    expect(sub003?.severity).toBe('high');
    expect(sub003?.evidence).toContain('user-content.example.com');
  });

  it('flags unconstrained framing allowing postMessage confusion (SUB-004)', () => {
    const hop = makeHop({
      url: 'https://example.com/',
      headers: {}, // No CSP frame-ancestors, no XFO
    });

    const result = checkSubdomainTrust(hop, []);
    expect(result.findings.some((f) => f.ruleId === 'SUB-004')).toBe(true);
  });

  it('flags missing Cross-Origin-Opener-Policy (SUB-006)', () => {
    const hop = makeHop({
      url: 'https://example.com/',
      headers: {},
    });

    const result = checkSubdomainTrust(hop, []);
    expect(result.findings.some((f) => f.ruleId === 'SUB-006')).toBe(true);
  });
});

describe('Subdomain Isolation Certification (SUB-008)', () => {
  it('certifies subdomain is isolated when no trust bridges exist', () => {
    // Current URL is on a subdomain: https://blog.example.com/
    // All trust bridges to main domain are closed!
    const hop = makeHop({
      url: 'https://blog.example.com/',
      headers: {
        'content-security-policy': "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
        'cross-origin-opener-policy': 'same-origin',
        'origin-agent-cluster': '?1',
        'x-frame-options': 'DENY',
      },
    });
    // Host-only cookie, not scoped to apex
    const cookies = [
      makeCookie({ name: '__Host-blog_session', domain: '' }),
    ];

    const result = checkSubdomainTrust(hop, cookies);
    expect(result.hasEscalationPath).toBe(false);

    // SUB-008 should be present
    const sub008 = result.findings.find((f) => f.ruleId === 'SUB-008');
    expect(sub008).toBeDefined();
    expect(sub008?.severity).toBe('info');
    expect(sub008?.title).toContain('Subdomain Isolated');

    const vIsolated = result.vectors.find((v) => v.id === 'SUB-008');
    expect(vIsolated?.present).toBe(false);
  });
});
