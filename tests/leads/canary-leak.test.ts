import { describe, it, expect } from 'vitest';
import { maskSecret, maskLocation } from '../../src/leads/sieve/mask';
import { LeadStore } from '../../src/leads/store/lead-store';
import { formatLeadsReportMarkdown, formatLeadsReportJson, formatLeadsReportSarif } from '../../src/leads/export/export';
import type { Lead } from '../../src/leads/types';

describe('Lead Engine Canary Leak Tests', () => {
  const CANARIES = {
    aws: 'AKIAIOSFODNN7CANARYKEY',
    github: 'ghp_canaryToken1234567890abcdef1234567890',
    jwtSecret: 'CANARY_JWT_SECRET_PAYLOAD_XYZ987',
    dbPass: 'CANARY_PASS_XYZ987',
    oauthState: 'CANARY_OAUTH_STATE_777',
    cookieValue: 'CANARY_COOKIE_SECRET_555',
    pemBlock: 'CANARY_PRIVATE_KEY_MATERIAL_BLOCK',
    reflectedParam: 'CANARY_REFLECTED_PARAM_111',
    jsonPii: 'CANARY_PII_PASSWORD_333',
    nonce: 'CANARY_STATIC_NONCE_444',
  };

  it('ensures maskSecret redacts every canary class without leaking raw token', () => {
    for (const [key, canary] of Object.entries(CANARIES)) {
      const masked = maskSecret(canary);
      expect(masked, `Leaked canary ${key} in maskSecret`).not.toContain(canary);
      expect(masked).not.toContain(canary.slice(4, -4));
    }
  });

  it('ensures LeadStore rejects unmasked evidence and never stores raw canaries', () => {
    const store = new LeadStore();
    const lead: Lead = {
      id: 'LD-SEC-CANARY-01',
      ruleId: 'SEC-001',
      family: 'F1',
      tier: 'observed',
      potential: 'critical',
      confidence: 1.0,
      title: 'AWS Secret Exposure',
      needs: [],
      doesNotProve: [],
      evidence: {
        preview: maskSecret(CANARIES.aws),
        location: maskLocation('https://example.com/bundle.js?token=' + CANARIES.oauthState),
      },
      tags: ['aws', 'secret'],
      scopeStatus: 'in-scope',
      timestamp: Date.now(),
      origin: 'https://example.com',
      url: 'https://example.com/bundle.js',
      sourceSensor: 'S2',
    };

    store.addLead(lead);
    const leads = store.getLeadsForOrigin('https://example.com');
    const serialized = JSON.stringify(leads);

    for (const [key, canary] of Object.entries(CANARIES)) {
      expect(serialized, `Stored raw canary ${key}`).not.toContain(canary);
    }
  });

  it('ensures Lead reports (Markdown and JSON) never leak synthetic canaries', () => {
    const lead: Lead = {
      id: 'LD-SEC-CANARY-02',
      ruleId: 'SEC-002',
      family: 'F1',
      tier: 'strong',
      potential: 'high',
      confidence: 0.9,
      title: 'Database URI Leak',
      needs: [],
      doesNotProve: [],
      evidence: {
        preview: maskSecret('postgres://user:' + CANARIES.dbPass + '@host:5432/db'),
        location: maskLocation('https://example.com/config.js?ref=' + CANARIES.reflectedParam),
      },
      tags: ['db', 'secret'],
      scopeStatus: 'in-scope',
      timestamp: Date.now(),
      origin: 'https://example.com',
      url: 'https://example.com/config.js',
      sourceSensor: 'S2',
    };

    const mdReport = formatLeadsReportMarkdown([lead]);
    const jsonReport = formatLeadsReportJson([lead]);

    for (const [key, canary] of Object.entries(CANARIES)) {
      expect(mdReport, `Markdown leaked canary ${key}`).not.toContain(canary);
      expect(jsonReport, `JSON leaked canary ${key}`).not.toContain(canary);
    }
  });

  it('redacts caller-supplied canaries in title, context, extractedNames, and URL path segments across Markdown, JSON, and SARIF', () => {
    const rawCanary = 'ZIP_CANARY_X91';
    const rawParamCanary = 'auth%5Ftoken=ZIP_CANARY_X91';
    const leadWithCanaries: Lead = {
      id: 'LD-CANARY-PROBE-03',
      ruleId: 'SEC-003',
      family: 'F1',
      tier: 'strong',
      potential: 'critical',
      confidence: 0.95,
      title: `Secret Leak of ${rawCanary} in production`,
      needs: ['manual confirmation of API response'],
      doesNotProve: ['unauthenticated execution'],
      evidence: {
        preview: maskSecret(`token=${rawCanary}`),
        location: maskLocation(`https://example.com/tenant-reset/${rawCanary}?${rawParamCanary}`),
        context: `Observed ${rawCanary} inside script context`,
        extractedNames: [rawCanary, 'api_token'],
      },
      tags: ['secret', 'probe'],
      scopeStatus: 'in-scope',
      timestamp: Date.now(),
      origin: 'https://example.com',
      url: `https://example.com/tenant-reset/${rawCanary}`,
      sourceSensor: 'S2',
    };

    const md = formatLeadsReportMarkdown([leadWithCanaries]);
    const json = formatLeadsReportJson([leadWithCanaries]);
    const sarif = formatLeadsReportSarif([leadWithCanaries]);

    // Zero canary leakage
    expect(md, 'Markdown leaked raw Canary').not.toContain(rawCanary);
    expect(json, 'JSON leaked raw Canary').not.toContain(rawCanary);
    expect(sarif, 'SARIF leaked raw Canary').not.toContain(rawCanary);

    // Markdown must include needs and doesNotProve
    expect(md).toContain('manual confirmation of API response');
    expect(md).toContain('unauthenticated execution');
    expect(md).toContain('HYPOTHESIS');

    // SARIF level must be warning (hypothesis, not error)
    const parsedSarif = JSON.parse(sarif) as {
      runs: Array<{ results: Array<{ level: string; properties?: { potential?: string } }> }>;
    };
    expect(parsedSarif.runs[0]?.results[0]?.level).toBe('warning');
    expect(parsedSarif.runs[0]?.results[0]?.properties?.potential).toBe('critical');
  });
});
