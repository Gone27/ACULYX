import { describe, expect, it } from 'vitest';
import { findUnobservedCookieFindings } from '../../src/background/correlate';

describe('Set-Cookie jar correlation diagnostics', () => {
  it('reports SameSite=None without Secure when the cookie is not visible in the jar', () => {
    const findings = findUnobservedCookieFindings(
      ['session=secret-value; SameSite=None; HttpOnly'],
      [],
      'https://app.example.com/login',
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('COOKIE-REJECTED');
    expect(findings[0]?.recommendation).toContain('SameSite=None requires Secure');
    expect(JSON.stringify(findings)).not.toContain('secret-value');
  });

  it('reports a Domain attribute that cannot apply to the response host', () => {
    const findings = findUnobservedCookieFindings(
      ['session=secret-value; Domain=attacker.test; Path=/'],
      [],
      'https://app.example.com/',
    );

    expect(findings[0]?.recommendation).toContain('Domain attribute does not match');
    expect(JSON.stringify(findings)).not.toContain('secret-value');
  });

  it('does not report names that are present in the accessible jar', () => {
    const findings = findUnobservedCookieFindings(
      ['session=secret-value; Path=/'],
      [{ name: 'session', path: '/', domain: 'app.example.com' }],
      'https://app.example.com/',
    );

    expect(findings).toHaveLength(0);
  });

  it('does not call an API-path cookie rejected when the current URL is outside its Path scope', () => {
    const findings = findUnobservedCookieFindings(
      ['token=secret-value; Path=/api'],
      [],
      'https://app.example.com/home',
    );

    expect(findings).toHaveLength(0);
  });

  it('mentions Path scope when another likely rejection reason is present', () => {
    const findings = findUnobservedCookieFindings(
      ['token=secret-value; Path=/api; SameSite=None'],
      [],
      'https://app.example.com/home',
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]?.recommendation).toContain('SameSite=None requires Secure');
    expect(findings[0]?.recommendation).toContain('cookie Path (/api) does not include');
    expect(JSON.stringify(findings)).not.toContain('secret-value');
  });

  it('uses cookie path segment boundaries when deciding whether the jar query covers it', () => {
    const mismatch = findUnobservedCookieFindings(
      ['token=secret-value; Path=/api'],
      [],
      'https://app.example.com/api-v2',
    );
    const matchingPath = findUnobservedCookieFindings(
      ['token=secret-value; Path=/api'],
      [],
      'https://app.example.com/api/users',
    );

    expect(mismatch).toHaveLength(0);
    expect(matchingPath).toHaveLength(1);
  });

  it('does not report cookie deletions with Max-Age=0 as COOKIE-REJECTED (N1)', () => {
    const findings = findUnobservedCookieFindings(
      ['session=; Max-Age=0; Path=/; Secure; HttpOnly'],
      [],
      'https://app.example.com/',
    );
    expect(findings).toHaveLength(0);
  });

  it('does not report cookie deletions with past Expires as COOKIE-REJECTED (N1)', () => {
    const findings = findUnobservedCookieFindings(
      ['session=deleted; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; Secure; HttpOnly'],
      [],
      'https://app.example.com/',
    );
    expect(findings).toHaveLength(0);
  });

  it('does not report third-party cookies from third-party hop responses as COOKIE-REJECTED (M9)', () => {
    const findings = findUnobservedCookieFindings(
      ['tracker_id=123; Domain=tracker.org; Path=/; Secure; SameSite=None'],
      [],
      'https://app.example.com/',
      'https://api.tracker.org/event',
    );
    expect(findings).toHaveLength(0);
  });

  it('derives third-party cookie records from hop Set-Cookie headers (M9)', async () => {
    const { correlateCookies } = await import('../../src/background/correlate');

    const originalChrome = globalThis.chrome;
    globalThis.chrome = {
      cookies: {
        getAll: () => Promise.resolve([
          {
            name: 'first_party_sess',
            domain: 'app.example.com',
            path: '/',
            secure: true,
            httpOnly: true,
            sameSite: 'lax',
            session: true,
            hostOnly: true,
            storeId: '0',
            value: 'REDACTED',
          },
        ]),
      },
    } as unknown as typeof chrome;

    try {
      const result = await correlateCookies(
        1,
        'https://app.example.com/',
        [
          'first_party_sess=val; Path=/; Secure; HttpOnly',
          'external_tracker=tid_999; Domain=analytics.net; Path=/; Secure; SameSite=None',
        ],
        1,
        () => true,
        'req-1',
        'https://sub.analytics.net/collect',
      );

      const firstParty = result.records.find((r) => r.name === 'first_party_sess');
      const thirdParty = result.records.find((r) => r.name === 'external_tracker');

      expect(firstParty).toBeDefined();
      expect(firstParty?.isThirdParty).toBe(false);

      expect(thirdParty).toBeDefined();
      expect(thirdParty?.isThirdParty).toBe(true);
      expect(thirdParty?.domain).toBe('analytics.net');
      expect(thirdParty?.sameSite).toBe('none');
      expect(thirdParty?.secure).toBe(true);
      expect((thirdParty as unknown as { value?: string }).value).toBeUndefined();
    } finally {
      globalThis.chrome = originalChrome;
    }
  });
});