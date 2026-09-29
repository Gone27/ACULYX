import { describe, expect, it } from 'vitest';
import { checkIsolationHeaders } from '../../src/rules/headers/isolation';
import { checkReportingHeaders } from '../../src/rules/headers/reporting';
import { checkPolicyHardeningHeaders } from '../../src/rules/headers/policy-hardening';
import { checkDeprecated } from '../../src/rules/headers/deprecated';
import { checkInfoLeak } from '../../src/rules/headers/info-leak';
import { checkHsts } from '../../src/rules/headers/hsts';
import { checkCsp } from '../../src/rules/headers/csp';
import type { Hop } from '../../src/shared/types';

function makeHop(headers: Record<string, string>, url = 'https://example.com/'): Hop {
  return {
    requestId: 'header-family-test',
    url,
    status: 200,
    headers,
    rawHeaders: Object.entries(headers).map(([name, value]) => ({ name, value })),
    fromCache: false,
    isHstsUpgrade: false,
    capturedAt: 'onResponseStarted',
    headersDiffer: false,
    timestamp: Date.now(),
  };
}

describe('COEP, CORP, and Permissions-Policy signals', () => {
  it('reports opt-in isolation guidance and permissive feature policies', () => {
    const findings = checkIsolationHeaders(makeHop({ 'permissions-policy': 'camera=(*), microphone=(self)' }));
    const ids = findings.map((finding) => finding.ruleId);

    expect(ids).toContain('COEP-001');
    expect(ids).toContain('CORP-001');
    expect(ids).toContain('PERMPOLICY-001');
    expect(findings.find((finding) => finding.ruleId === 'PERMPOLICY-001')?.evidence).toContain('camera');
  });

  it('accepts supported isolation values and restricted permissions policies', () => {
    const findings = checkIsolationHeaders(makeHop({
      'cross-origin-embedder-policy': 'require-corp',
      'cross-origin-resource-policy': 'same-site',
      'permissions-policy': 'camera=(), microphone=(self)',
    }));

    expect(findings).toHaveLength(0);
  });
});

describe('CSP and network reporting signals', () => {
  it('treats Report-Only CSP as monitoring, not enforcement', () => {
    const { findings } = checkCsp(makeHop({
      'content-security-policy-report-only': "default-src 'self'; report-uri /csp-report",
    }));
    expect(findings.find((finding) => finding.ruleId === 'CSP-001')?.title).toContain('Only Content-Security-Policy-Report-Only');
  });

  it('reports absent CSP/reporting configuration', () => {
    const findings = checkReportingHeaders(makeHop({ 'content-security-policy': "default-src 'self'" }));
    expect(findings.map((finding) => finding.ruleId)).toContain('CSP-REPORT-001');
    expect(findings.map((finding) => finding.ruleId)).toContain('REPORT-001');
  });

  it('accepts matching Reporting-Endpoints and NEL group names', () => {
    const findings = checkReportingHeaders(makeHop({
      'content-security-policy': "default-src 'self'; report-to default",
      'reporting-endpoints': 'default="https://reports.example.com/nel"',
      nel: '{"report_to":"default","max_age":86400}',
    }));

    expect(findings).toHaveLength(0);
  });

  it('reports NEL that references an undeclared endpoint group', () => {
    const findings = checkReportingHeaders(makeHop({
      'reporting-endpoints': 'csp="https://reports.example.com/csp"',
      nel: '{"report_to":"nel","max_age":86400}',
    }));

    expect(findings.map((finding) => finding.ruleId)).toContain('REPORT-002');
  });
});

describe('Additional legacy and information-leak headers', () => {
  it('flags obsolete HPKP, P3P, Feature-Policy, Expect-CT, legacy CSP, and X-UA-Compatible headers', () => {
    const findings = checkDeprecated(makeHop({
      'public-key-pins': 'pin-sha256="abc"; max-age=1000',
      p3p: 'CP="NOI DSP COR NID"',
      'feature-policy': 'camera *',
      'x-ua-compatible': 'IE=edge',
      'expect-ct': 'max-age=86400',
      'x-content-security-policy': "default-src 'self'",
      'x-webkit-csp': "default-src 'self'",
    }));
    expect(findings.map((finding) => finding.ruleId)).toEqual(expect.arrayContaining([
      'DEP-002', 'DEP-003', 'DEP-004', 'DEP-005', 'DEP-006', 'DEP-007', 'DEP-008',
    ]));
    expect(findings.every((finding) => finding.severity === 'info')).toBe(true);
  });

  it('requires specific products or header context to fire LEAK-001', () => {
    expect(checkInfoLeak(makeHop({ 'server': 'Microsoft-IIS/10.0' })).length).toBe(1);
    expect(checkInfoLeak(makeHop({ 'x-powered-by': 'PHP/8.1' })).length).toBe(1);
    expect(checkInfoLeak(makeHop({ 'server': 'Express' })).length).toBe(0);
    expect(checkInfoLeak(makeHop({ 'server': 'nginx' })).length).toBe(0);
    expect(checkInfoLeak(makeHop({ 'server': '1.0' })).length).toBe(0);
    expect(checkInfoLeak(makeHop({ 'x-aspnet-version': '4.0.30319' })).length).toBe(1);
    expect(checkInfoLeak(makeHop({ 'x-aspnetmvc-version': '5.2' })).length).toBe(1);
  });

});

describe('Modern policy and HSTS preload guidance', () => {
  it('signals missing optional Document-Policy and Integrity-Policy', () => {
    const findings = checkPolicyHardeningHeaders(makeHop({}));
    expect(findings.map((finding) => finding.ruleId)).toContain('DOC-001');
    expect(findings.map((finding) => finding.ruleId)).toContain('INTEGRITY-001');
  });

  it('distinguishes Integrity-Policy-Report-Only from enforcement', () => {
    const findings = checkPolicyHardeningHeaders(makeHop({
      'integrity-policy-report-only': 'blocked-destinations=(script)',
    }));
    expect(findings.map((finding) => finding.ruleId)).toContain('INTEGRITY-002');
    expect(findings.map((finding) => finding.ruleId)).not.toContain('INTEGRITY-001');
  });

  it('reports incomplete preload directives without claiming list membership', () => {
    const findings = checkHsts(makeHop(
      { 'strict-transport-security': 'max-age=86400; preload' },
      'https://example.com/',
    ));
    expect(findings.map((finding) => finding.ruleId)).toContain('HSTS-004');
    expect(findings.find((finding) => finding.ruleId === 'HSTS-004')?.severity).toBe('info');
  });
});


