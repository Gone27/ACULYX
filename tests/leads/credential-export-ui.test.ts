import { describe, it, expect } from 'vitest';
import {
  formatLeadsReportMarkdown,
  formatLeadsReportJson,
  formatLeadsReportSarif,
} from '../../src/leads/export/export';
import type { Lead, CredentialCheckResult } from '../../src/leads/types';
import { maskSecret, maskLocation } from '../../src/leads/sieve/mask';

describe('Credential Liveness Phase 4: Storage, Exports & User Wording', () => {
  const baseF1Lead: Lead = {
    id: 'LD-EXPORT-1',
    ruleId: 'SEC-001',
    family: 'F1',
    tier: 'observed',
    potential: 'critical',
    confidence: 1.0,
    title: 'GitHub Secret',
    needs: ['verify scopes'],
    doesNotProve: [],
    evidence: {
      preview: maskSecret('ghp_123456789012345678901234567890123456'),
      location: maskLocation('https://example.com/app.js'),
    },
    tags: ['github'],
    scopeStatus: 'in-scope',
    timestamp: 1700000000000,
    origin: 'https://example.com',
    url: 'https://example.com/app.js',
    sourceSensor: 'S2',
  };

  it('exports "Not checked; no vendor API request was sent." when credential has not been checked', () => {
    const md = formatLeadsReportMarkdown([baseF1Lead]);
    expect(md).toContain('Credential Liveness Check');
    expect(md).toContain('Not checked; no vendor API request was sent.');
    // Must never imply inactive or safe
    expect(md).not.toContain('inactive');
    expect(md).not.toContain('safe');
  });

  it('exports provider-accepted result with explicit limits and disclaimer', () => {
    const checkedLead: Lead = {
      ...baseF1Lead,
      credentialCheck: {
        status: 'active_at_check',
        provider: 'github',
        tokenFamily: 'ghp',
        checkedAt: 1700000000000,
        details: 'GitHub accepted this credential at check time.',
      },
    };

    const md = formatLeadsReportMarkdown([checkedLead]);
    expect(md).toContain('[active_at_check]');
    expect(md).toContain('GitHub accepted this credential at check time.');
    expect(md).toContain('This reports only what the provider accepted at the time of the check');
    expect(md).toContain('does not establish the credential\'s full permissions, exploitability, or authorization to use it');
  });

  it('exports sanitized credentialCheck in JSON report without private bodies or secrets', () => {
    const credCheck: CredentialCheckResult = {
      status: 'active_at_check',
      provider: 'stripe',
      tokenFamily: 'sk_live',
      checkedAt: 1700000000000,
      details: 'Stripe accepted this credential at check time.',
      livemode: true,
    };
    const checkedLead: Lead = {
      ...baseF1Lead,
      credentialCheck: credCheck,
    };

    const jsonStr = formatLeadsReportJson([checkedLead]);
    const parsed = JSON.parse(jsonStr) as Lead[];
    expect(parsed).toHaveLength(1);
    const first = parsed[0];
    expect(first).toBeDefined();
    expect(first?.credentialCheck).toBeDefined();
    expect(first?.credentialCheck?.status).toBe('active_at_check');
    expect(first?.credentialCheck?.provider).toBe('stripe');
    expect(first?.credentialCheck?.livemode).toBe(true);
    // Invariant: no rawToken or balance leaks
    expect(jsonStr).not.toContain('rawToken');
    expect(jsonStr).not.toContain('amount');
  });

  it('includes credentialCheck in SARIF report properties', () => {
    const checkedLead: Lead = {
      ...baseF1Lead,
      credentialCheck: {
        status: 'inactive_at_check',
        provider: 'slack',
        tokenFamily: 'xoxb',
        checkedAt: 1700000000000,
        details: 'Slack reported credential is token_revoked.',
      },
    };

    const sarifStr = formatLeadsReportSarif([checkedLead]);
    const parsed = JSON.parse(sarifStr) as { runs: Array<{ results: Array<{ properties: { credentialCheck?: CredentialCheckResult } }> }> };
    const firstRun = parsed.runs[0];
    expect(firstRun).toBeDefined();
    const result = firstRun?.results[0];
    expect(result).toBeDefined();
    expect(result?.properties.credentialCheck).toBeDefined();
    expect(result?.properties.credentialCheck?.status).toBe('inactive_at_check');
  });
});
