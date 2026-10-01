import { describe, it, expect } from 'vitest';
import { selectVisibleFindings } from '../../src/shared/filters';
import type { Finding, Severity } from '../../src/shared/types';

describe('Presentation filter (selectVisibleFindings)', () => {
  const sampleFindings: Finding[] = [
    {
      ruleId: 'CSP-001',
      category: 'header',
      severity: 'high',
      title: 'Missing Content-Security-Policy',
      evidence: '(header absent)',
      recommendation: 'Add CSP',
      reference: 'https://example.com',
    },
    {
      ruleId: 'HSTS-001',
      category: 'transport',
      severity: 'critical',
      title: 'Missing HSTS',
      evidence: '(header absent)',
      recommendation: 'Add HSTS',
      reference: 'https://example.com',
    },
    {
      ruleId: 'XCTO-001',
      category: 'header',
      severity: 'medium',
      title: 'Missing X-Content-Type-Options',
      evidence: '(header absent)',
      recommendation: 'Add nosniff',
      reference: 'https://example.com',
    },
    {
      ruleId: 'REF-001',
      category: 'header',
      severity: 'low',
      title: 'Weak Referrer-Policy',
      evidence: 'no-referrer-when-downgrade',
      recommendation: 'Set strict-origin',
      reference: 'https://example.com',
    },
    {
      ruleId: 'DEP-001',
      category: 'header',
      severity: 'info',
      title: 'Deprecated Header',
      evidence: '1; mode=block',
      recommendation: 'Remove header',
      reference: 'https://example.com',
    },
  ];

  it('returns all findings with hiddenCount 0 when all severities are allowed', () => {
    const allSeverities: Severity[] = ['critical', 'high', 'medium', 'low', 'info', 'pass'];
    const result = selectVisibleFindings(sampleFindings, allSeverities);

    expect(result.visibleFindings).toHaveLength(5);
    expect(result.hiddenCount).toBe(0);
  });

  it('filters out findings below allowed severity and returns accurate hiddenCount', () => {
    const criticalOnly: Severity[] = ['critical'];
    const result = selectVisibleFindings(sampleFindings, criticalOnly);

    expect(result.visibleFindings).toHaveLength(1);
    expect(result.visibleFindings[0]?.ruleId).toBe('HSTS-001');
    expect(result.hiddenCount).toBe(4);
  });

  it('filters high and medium severities correctly', () => {
    const highAndMedium: Severity[] = ['high', 'medium'];
    const result = selectVisibleFindings(sampleFindings, highAndMedium);

    expect(result.visibleFindings).toHaveLength(2);
    expect(result.visibleFindings.map((f) => f.ruleId)).toEqual(['CSP-001', 'XCTO-001']);
    expect(result.hiddenCount).toBe(3);
  });

  it('bypasses filter and returns all findings when showAllOverride is true', () => {
    const criticalOnly: Severity[] = ['critical'];
    const result = selectVisibleFindings(sampleFindings, criticalOnly, true);

    expect(result.visibleFindings).toHaveLength(5);
    expect(result.hiddenCount).toBe(0);
  });

  it('returns all findings when filter array is empty', () => {
    const result = selectVisibleFindings(sampleFindings, []);

    expect(result.visibleFindings).toHaveLength(5);
    expect(result.hiddenCount).toBe(0);
  });

  it('does not mutate original findings list', () => {
    const originalCopy = [...sampleFindings];
    selectVisibleFindings(sampleFindings, ['critical']);

    expect(sampleFindings).toEqual(originalCopy);
  });
});
