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
});