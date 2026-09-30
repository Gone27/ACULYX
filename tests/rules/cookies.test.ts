/**
 * @file cookies.test.ts
 * Vitest unit tests for all 6 cookie security rules (COOK-001..006).
 *
 * Tests operate on CookieRecord[] — no browser APIs, no chrome.cookies.
 * Cookie values are never used anywhere in this test file.
 */

import { describe, it, expect } from 'vitest';
import { checkCookies } from '../../src/rules/cookies/cookies';
import type { CookieRecord, Finding } from '../../src/shared/types';

// ---------------------------------------------------------------------------
// Helper: build a CookieRecord with sane defaults.
// Only supply the fields relevant to the case under test.
// ---------------------------------------------------------------------------
function makeCookie(overrides: Partial<CookieRecord> = {}): CookieRecord {
  return {
    name:        'session',
    domain:      'example.com',
    domainAttributePresent: false,
    path:        '/',
    secure:      true,
    httpOnly:    true,
    sameSite:    'lax',
    session:     false,
    expiresAt:   null,
    partitioned: false,
    setByJs:     false,
    isThirdParty: false,
    ...overrides,
  };
}

/** Returns the rule IDs of all findings for the given cookie list. */
function ruleIds(cookies: CookieRecord[], isHttps = true): string[] {
  return checkCookies(cookies, isHttps).map((f: Finding) => f.ruleId);
}

// ---------------------------------------------------------------------------
// COOK-001 — Secure flag
// ---------------------------------------------------------------------------
describe('COOK-001 — Secure flag absent on HTTPS', () => {
  it('fires when Secure=false on an HTTPS origin', () => {
    expect(ruleIds([makeCookie({ secure: false })])).toContain('COOK-001');
  });

  it('does not fire when Secure=true', () => {
    expect(ruleIds([makeCookie({ secure: true })])).not.toContain('COOK-001');
  });

  it('does not fire on HTTP origin even when Secure=false', () => {
    expect(ruleIds([makeCookie({ secure: false })], false)).not.toContain('COOK-001');
  });

  it('evidence contains the cookie name, not a value', () => {
    const findings = checkCookies([makeCookie({ name: 'auth_token', secure: false })], true);
    const f = findings.find((x) => x.ruleId === 'COOK-001');
    expect(f).toBeDefined();
    expect(f?.evidence).toContain('auth_token');
    // Evidence must not contain any value-like content
    expect(f?.evidence).not.toContain('Bearer');
  });
});

// ---------------------------------------------------------------------------
// COOK-002 — HttpOnly flag
// ---------------------------------------------------------------------------
describe('COOK-002 — HttpOnly flag absent', () => {
  it('fires when HttpOnly=false and not a JS-set cookie', () => {
    expect(ruleIds([makeCookie({ httpOnly: false, setByJs: false })])).toContain('COOK-002');
  });

  it('does not fire when HttpOnly=true', () => {
    expect(ruleIds([makeCookie({ httpOnly: true })])).not.toContain('COOK-002');
  });

  it('does not fire for JS-set cookies (they cannot have HttpOnly)', () => {
    expect(ruleIds([makeCookie({ httpOnly: false, setByJs: true })])).not.toContain('COOK-002');
  });
});

// ---------------------------------------------------------------------------
// COOK-003 — SameSite=None without Secure
// ---------------------------------------------------------------------------
describe('COOK-003 — SameSite=None without Secure', () => {
  it('fires when SameSite=none and Secure=false', () => {
    expect(ruleIds([makeCookie({ sameSite: 'none', secure: false })])).toContain('COOK-003');
  });

  it('does not fire when SameSite=none AND Secure=true', () => {
    expect(ruleIds([makeCookie({ sameSite: 'none', secure: true })])).not.toContain('COOK-003');
  });

  it('does not fire when SameSite=lax', () => {
    expect(ruleIds([makeCookie({ sameSite: 'lax' })])).not.toContain('COOK-003');
  });
});

// ---------------------------------------------------------------------------
// COOK-004 — SameSite missing
// ---------------------------------------------------------------------------
describe('COOK-004 — SameSite absent', () => {
  it('fires when sameSite is empty string', () => {
    expect(ruleIds([makeCookie({ sameSite: '' })])).toContain('COOK-004');
  });

  it('does not fire when sameSite is lax', () => {
    expect(ruleIds([makeCookie({ sameSite: 'lax' })])).not.toContain('COOK-004');
  });

  it('does not fire when sameSite is strict', () => {
    expect(ruleIds([makeCookie({ sameSite: 'strict' })])).not.toContain('COOK-004');
  });

  it('does not fire when sameSite is none (COOK-003 handles that path)', () => {
    // SameSite=none is not "missing" — different rule
    expect(ruleIds([makeCookie({ sameSite: 'none', secure: true })])).not.toContain('COOK-004');
  });
});

// ---------------------------------------------------------------------------
// COOK-005 — __Host- prefix violations
// ---------------------------------------------------------------------------
describe('COOK-005 — __Host- prefix violations', () => {
  it('fires when __Host- cookie has Secure=false', () => {
    const c = makeCookie({ name: '__Host-session', secure: false, path: '/', domain: '' });
    expect(ruleIds([c])).toContain('COOK-005');
  });

  it('fires when __Host- cookie has Path≠/', () => {
    const c = makeCookie({ name: '__Host-session', secure: true, path: '/app', domain: '' });
    expect(ruleIds([c])).toContain('COOK-005');
  });

  it('fires when __Host- cookie has a non-empty Domain', () => {
    const c = makeCookie({ name: '__Host-session', secure: true, path: '/', domain: 'example.com', domainAttributePresent: true });
    expect(ruleIds([c])).toContain('COOK-005');
  });

  it('does not fire when all __Host- requirements are met', () => {
    const c = makeCookie({ name: '__Host-session', secure: true, path: '/', domain: '' });
    expect(ruleIds([c])).not.toContain('COOK-005');
  });

  it('does not fire on a cookie without __Host- prefix', () => {
    expect(ruleIds([makeCookie({ name: 'session' })])).not.toContain('COOK-005');
  });
});

// ---------------------------------------------------------------------------
// COOK-006 — __Secure- prefix violations
// ---------------------------------------------------------------------------
describe('COOK-006 — __Secure- prefix violations', () => {
  it('fires when __Secure- cookie has Secure=false', () => {
    const c = makeCookie({ name: '__Secure-token', secure: false });
    expect(ruleIds([c])).toContain('COOK-006');
  });

  it('does not fire when __Secure- cookie has Secure=true', () => {
    const c = makeCookie({ name: '__Secure-token', secure: true });
    expect(ruleIds([c])).not.toContain('COOK-006');
  });

  it('does not fire on a cookie without __Secure- prefix', () => {
    expect(ruleIds([makeCookie({ name: 'token', secure: false })])).not.toContain('COOK-006');
  });
});

// ---------------------------------------------------------------------------
// Multiple cookies — findings are per-cookie
// ---------------------------------------------------------------------------
describe('Multiple cookies', () => {
  it('returns separate findings for each offending cookie', () => {
    const cookies = [
      makeCookie({ name: 'session_a', secure: false }),   // COOK-001
      makeCookie({ name: 'session_b', httpOnly: false }), // COOK-002
      makeCookie({ name: 'session_c', sameSite: '' }),    // COOK-004
    ];
    const ids = ruleIds(cookies);
    expect(ids).toContain('COOK-001');
    expect(ids).toContain('COOK-002');
    expect(ids).toContain('COOK-004');
  });

  it('does not flag COOK-002 on harmless client cookies (analytics, preferences)', () => {
    const harmless = [
      makeCookie({ name: 'theme', httpOnly: false }),
      makeCookie({ name: 'lang', httpOnly: false }),
      makeCookie({ name: '_ga', httpOnly: false }),
      makeCookie({ name: 'csrftoken', httpOnly: false }),
    ];
    const ids = ruleIds(harmless);
    expect(ids).not.toContain('COOK-002');
  });

  it('returns no findings for a cookie with all best-practice attributes', () => {
    const cookie = makeCookie({
      name:     'session',
      secure:   true,
      httpOnly: true,
      sameSite: 'strict',
      domain:   '',
      path:     '/',
    });
    expect(checkCookies([cookie], true)).toHaveLength(0);
  });

  it('returns no findings for an empty cookie list', () => {
    expect(checkCookies([], true)).toHaveLength(0);
  });
});

describe('Header & Set-Cookie value redaction (P1 privacy)', () => {
  it('redacts cookie values while preserving name and attributes in Set-Cookie', async () => {
    const { redactSetCookieHeader, extractSetCookieHeaders, normalizeHeaders } = await import('../../src/rules/utils');

    const raw = 'session=V2_SYNTHETIC_CANARY; Path=/; Secure; HttpOnly; SameSite=Lax';
    const redacted = redactSetCookieHeader(raw);
    expect(redacted).toBe('session=[REDACTED]; Path=/; Secure; HttpOnly; SameSite=Lax');
    expect(redacted).not.toContain('V2_SYNTHETIC_CANARY');

    // Multi-attribute with domain and max-age
    const raw2 = 'auth_token=supersecret123; Domain=example.com; Max-Age=3600; Secure';
    expect(redactSetCookieHeader(raw2)).toBe('auth_token=[REDACTED]; Domain=example.com; Max-Age=3600; Secure');

    // extractSetCookieHeaders produces redacted entries
    const extracted = extractSetCookieHeaders([
      { name: 'Set-Cookie', value: raw },
      { name: 'Content-Type', value: 'text/html' },
    ]);
    expect(extracted).toEqual(['session=[REDACTED]; Path=/; Secure; HttpOnly; SameSite=Lax']);

    // normalizeHeaders produces redacted lowercase entries
    const normalized = normalizeHeaders([
      { name: 'Set-Cookie', value: raw },
      { name: 'Authorization', value: 'Bearer MY_BEARER_TOKEN' },
      { name: 'Cookie', value: 'user=admin; token=xyz789' },
    ]);
    expect(normalized['set-cookie']).toBe('session=[REDACTED]; Path=/; Secure; HttpOnly; SameSite=Lax');
    expect(normalized['authorization']).toBe('[REDACTED]');
    expect(normalized['cookie']).toBe('user=[REDACTED]; token=[REDACTED]');
  });

  it('assertNoSensitiveSecrets throws if unredacted cookie canaries or credentials are in state', async () => {
    const { assertNoSensitiveSecrets } = await import('../../src/shared/storage');
    const validState: import('../../src/shared/types').TabState = {
      tabId: 1,
      origin: 'https://example.com',
      url: 'https://example.com/',
      hops: [
        {
          requestId: 'r1',
          url: 'https://example.com/',
          status: 200,
          headers: {
            'set-cookie': 'session=[REDACTED]; Path=/; Secure; HttpOnly',
            'authorization': '[REDACTED]',
          },
          rawHeaders: [
            { name: 'Set-Cookie', value: 'session=[REDACTED]; Path=/; Secure; HttpOnly' },
            { name: 'Authorization', value: '[REDACTED]' },
          ],
          fromCache: false,
          isHstsUpgrade: false,
          capturedAt: 'onResponseStarted',
          headersDiffer: false,
          timestamp: Date.now(),
        },
      ],
      cookies: [
        {
          name: 'session',
          domain: 'example.com',
          path: '/',
          secure: true,
          httpOnly: true,
          sameSite: 'strict',
          session: true,
          expiresAt: null,
          partitioned: false,
          setByJs: false,
          isThirdParty: false,
          domainAttributePresent: true,
        },
      ],
      findings: [],
      grade: 'A',
      score: 100,
      qualityScore: 100,
      qualityGrade: 'A',
      scoreVersion: '1.7.0',
      scoreBreakdown: [],
      coverage: {
        hopsExpected: 1,
        hopsCaptured: 1,
        hasCache: false,
        hasServiceWorker: false,
        serviceWorkerStatus: 'not-controlled',
        serviceWorkerUrl: null,
        isRestricted: false,
        metaCspFound: false,
      },
      subdomainTrust: { hasEscalationPath: false, vectors: [] },
      monitoredByUser: true,
      updatedAt: Date.now(),
    };

    // Valid state passes assertion
    expect(() => assertNoSensitiveSecrets(validState)).not.toThrow();

    // State with unredacted Set-Cookie canary in hop headers throws
    const leakedHeaderState = structuredClone(validState);
    const hop0 = leakedHeaderState.hops[0];
    if (hop0 !== undefined) {
      hop0.headers['set-cookie'] = 'session=V2_SYNTHETIC_CANARY; Path=/';
    }
    expect(() => assertNoSensitiveSecrets(leakedHeaderState)).toThrow(/Unredacted/);

    // State with unredacted Set-Cookie in hop rawHeaders throws
    const leakedRawState = structuredClone(validState);
    const rawHop0 = leakedRawState.hops[0];
    const rawH0 = rawHop0?.rawHeaders[0];
    if (rawH0 !== undefined) {
      rawH0.value = 'session=V2_SYNTHETIC_CANARY; Path=/';
    }
    expect(() => assertNoSensitiveSecrets(leakedRawState)).toThrow(/Unredacted/);

    // State with unredacted Authorization header throws
    const leakedAuthState = structuredClone(validState);
    const authHop0 = leakedAuthState.hops[0];
    if (authHop0 !== undefined) {
      authHop0.headers['authorization'] = 'Bearer secret-canary-token';
    }
    expect(() => assertNoSensitiveSecrets(leakedAuthState)).toThrow(/Unredacted/);

    // State with cookie record having value throws
    const leakedCookieRecordState = structuredClone(validState);
    (leakedCookieRecordState.cookies[0] as unknown as { value: string }).value = 'V2_SYNTHETIC_CANARY';
    expect(() => assertNoSensitiveSecrets(leakedCookieRecordState)).toThrow(/Cookie value detected/);
  });
});
