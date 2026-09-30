import { describe, expect, it } from 'vitest';
import {
  buildCliReport,
  formatMarkdown,
  formatSarif,
  redactResponseHeaders,
  redactHeaders,
  selectHarInput,
  shouldFail,
  computeFindingFingerprint,
  computeFindingDiff,
  buildAuditBundle,
  verifyAuditBundle,
} from '../src/cli';
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
    expect(run?.results[0]).toHaveProperty('partialFingerprints');
    expect(typeof (run?.results[0] as { partialFingerprints?: { primaryLocationLineHash?: string } })?.partialFingerprints?.primaryLocationLineHash).toBe('string');
  });

  it('computes stable SHA-256 fingerprints for findings', () => {
    const report = buildCliReport({ url: 'https://example.com', headers: {} });
    const finding = report.findings[0];
    expect(finding).toBeDefined();
    if (finding === undefined) return;
    const fp1 = computeFindingFingerprint(finding, report.target);
    const fp2 = computeFindingFingerprint(finding, report.target);
    expect(fp1).toHaveLength(64);
    expect(fp1).toBe(fp2);
  });

  it('detects regressions, fixes, and unchanged findings in diff mode', () => {
    const baseline = buildCliReport({ url: 'https://example.com', headers: {} });
    const improved = buildCliReport({
      url: 'https://example.com',
      headers: {
        'strict-transport-security': 'max-age=31536000; includeSubDomains',
      },
    });

    const diff = computeFindingDiff(baseline, improved);
    expect(diff.fixes.some((f) => f.ruleId === 'HSTS-001')).toBe(true);
    expect(diff.regressions.some((f) => f.ruleId === 'HSTS-005')).toBe(true);
    expect(diff.currentScore).toBeGreaterThan(diff.baselineScore ?? 0);
  });

  it('preserves duplicate rule findings and tracks modified findings in diff', () => {
    const baseline = buildCliReport({
      url: 'https://example.com',
      headers: {
        'server': 'Apache/2.4.51',
        'x-powered-by': 'PHP/8.1.0',
      },
    });

    // Current report fixes one leak (removes x-powered-by), keeps the other, and modifies an evidence
    const current = buildCliReport({
      url: 'https://example.com',
      headers: {
        'server': 'Apache/2.4.52',
      },
    });

    const diff = computeFindingDiff(baseline, current);

    // Baseline had 2 LEAK-001 findings; one was resolved, one was modified/unchanged
    const leakFixes = diff.fixes.filter((f) => f.ruleId === 'LEAK-001');
    expect(leakFixes.length).toBeGreaterThanOrEqual(1);

    // Verify changed or unchanged preserves the other instance without collapsing
    const hasPersistentLeak = diff.unchanged.some((f) => f.ruleId === 'LEAK-001') || diff.changed.some((c) => c.after.ruleId === 'LEAK-001');
    expect(hasPersistentLeak).toBe(true);
  });

  it('generates an audit bundle with an integrity checksum and verified authenticity', () => {
    const report = buildCliReport({ url: 'https://example.com', headers: { 'x-frame-options': 'DENY' } });
    const bundle = buildAuditBundle(report, { 'x-frame-options': 'DENY' });

    expect(bundle.bundleVersion).toBe('1.0.0');
    expect(bundle.target).toBe('https://example.com/');
    expect(bundle.integrityChecksum).toHaveLength(64);
    expect(bundle.redactedHeaders['x-frame-options']).toBe('DENY');
    expect(verifyAuditBundle(bundle)).toBe(true);

    // Tampering with any field must invalidate verification
    const tampered = { ...bundle, score: 99 };
    expect(verifyAuditBundle(tampered)).toBe(false);
  });

  it('never leaks Set-Cookie canary values in --bundle output across mixed-case inputs', () => {
    const canary = 'CANARY_SECRET_COOKIE_VAL_999888';
    const testCases: Array<Record<string, string>> = [
      { 'Set-Cookie': `session=${canary}; Secure; HttpOnly` },
      { 'set-cookie': `id=${canary}; Path=/` },
      { 'SET-COOKIE': `token=${canary}; SameSite=Strict` },
      { 'Authorization': `Bearer ${canary}` },
      { 'Proxy-Authorization': `Basic ${canary}` },
    ];

    for (const headers of testCases) {
      const report = buildCliReport({ url: 'https://example.com', headers });
      const bundle = buildAuditBundle(report, headers);
      const serialized = JSON.stringify(bundle);

      expect(serialized).not.toContain(canary);
      expect(bundle.redactedHeaders['set-cookie'] ?? bundle.redactedHeaders['authorization'] ?? bundle.redactedHeaders['proxy-authorization']).toBe('[redacted]');
    }
  });

  it('redacts sensitive headers via redactHeaders helper directly', () => {
    const raw = {
      'Set-Cookie': 'secret=123',
      'X-Custom': 'safe',
      'AUTHORIZATION': 'secret-auth',
    };
    const clean = redactHeaders(raw);
    expect(clean['set-cookie']).toBe('[redacted]');
    expect(clean['authorization']).toBe('[redacted]');
    expect(clean['x-custom']).toBe('safe');
  });
});