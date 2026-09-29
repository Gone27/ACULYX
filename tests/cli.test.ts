import { describe, expect, it } from 'vitest';
import { buildCliReport, formatMarkdown, formatSarif, redactResponseHeaders, selectHarInput, shouldFail } from '../src/cli';
import fixes from '../fixes.json';
import packageInfo from '../package.json';
import weights from '../src/rules/weights.json';

describe('SecCheck CLI report', () => {
  it('attaches a rule-specific fix snippet to findings', () => {
    const report = buildCliReport({ url: 'https://example.com', headers: {} });
    const cspFinding = report.findings.find((finding) => finding.ruleId === 'CSP-001');

    expect(cspFinding?.fix?.snippet).toContain('Content-Security-Policy:');
    expect(cspFinding?.fix?.note).toContain('production policy');
  });

  it('never includes Set-Cookie values in JSON or Markdown reports', () => {
    const report = buildCliReport({
      url: 'https://example.com',
      headers: {
        'set-cookie': 'session=secret-session-value; HttpOnly; Secure',
        'cache-control': 'public, max-age=3600',
      },
    });
    const serialized = JSON.stringify(report);

    expect(serialized).not.toContain('secret-session-value');
    expect(formatMarkdown(report)).not.toContain('secret-session-value');
  });

  it('redacts Set-Cookie before storing fetched response headers', () => {
    const headers = new Headers([
      ['set-cookie', 'session=secret-session-value; HttpOnly; Secure'],
      ['content-type', 'text/html'],
    ]);
    const redacted = redactResponseHeaders(headers);

    expect(redacted['set-cookie']).toBe('[redacted]');
    expect(JSON.stringify(redacted)).not.toContain('secret-session-value');
    expect(redacted['content-type']).toBe('text/html');
  });

  it('imports a selected HAR response and never copies cookie values', () => {
    const input = selectHarInput({
      log: {
        version: '1.2',
        entries: [
          {
            request: { url: 'https://example.test/other' },
            response: { status: 200, headers: [] },
          },
          {
            request: { url: 'https://example.test/protected?view=1' },
            response: {
              status: 200,
              headers: [
                { name: 'Set-Cookie', value: 'session=secret-har-value; Secure; HttpOnly' },
                { name: 'Cache-Control', value: 'no-store' },
              ],
              cookies: [{
                name: 'session',
                value: 'secret-har-value',
                domain: 'example.test',
                path: '/',
                secure: true,
                httpOnly: true,
                sameSite: 'Lax',
              }],
            },
          },
        ],
      },
    }, 'https://example.test/protected?view=1');
    const report = buildCliReport(input);

    expect(input.url).toBe('https://example.test/protected?view=1');
    expect(input.headers['set-cookie']).toBe('[redacted]');
    expect(report.findings.some((finding) => finding.ruleId === 'COOK-001')).toBe(false);
    expect(JSON.stringify(report)).not.toContain('secret-har-value');
  });

  it('requires an exact URL selector when importing a HAR', () => {
    expect(() => selectHarInput({ log: { entries: [] } }, 'https://example.test/'))
      .toThrow('No HAR response matched');
  });

  it('rejects cookie records containing values', () => {
    expect(() => buildCliReport({
      url: 'https://example.com',
      headers: {},
      cookies: [{
        name: 'session',
        value: 'secret-session-value',
      } as never],
    })).toThrow('Cookie values are not accepted');
  });

  it('renders fix snippets and manual-review notes in Markdown', () => {
    const report = buildCliReport({ url: 'https://example.com', headers: {} });
    const markdown = formatMarkdown(report);

    expect(markdown).toContain('Suggested fix:');
    expect(markdown).toContain('```text');
    expect(markdown).toContain('require manual review');
  });

  it('has a fix entry for every scored rule', () => {
    expect(Object.keys(weights.rules).every((ruleId) => ruleId in fixes.rules)).toBe(true);
  });

  it('supports severity-based CI failure thresholds', () => {
    const findings = buildCliReport({ url: 'https://example.com', headers: {} }).findings;
    expect(shouldFail(findings, 'high')).toBe(true);
    expect(shouldFail(findings, 'never')).toBe(false);
  });

  it('formats findings as SARIF 2.1.0 with source locations and rule metadata', () => {
    const report = buildCliReport({ url: 'https://example.com', headers: {} });
    const sarif = formatSarif(report);
    const run = sarif.runs[0];

    expect(sarif.version).toBe('2.1.0');
    expect(run?.tool.driver).toMatchObject({ name: 'SecCheck', version: packageInfo.version });
    expect(run?.results.length).toBeGreaterThan(0);
    expect(run?.results[0]).toHaveProperty('locations');
    expect(run?.tool.driver.rules.length).toBeGreaterThan(0);
    expect(run?.properties.qualityScore).toBe(report.qualityScore);
    expect(report.qualityScore).toBeLessThan(100);
  });
});