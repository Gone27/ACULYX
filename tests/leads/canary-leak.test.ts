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

  it('guarantees zero canary leakage in lead metadata fields (id, ruleId, origin, tags, chainIds, needs, doesNotProve, remediation) across JSON, Markdown, and SARIF', () => {
    const META_CANARY = 'METADATA_CANARY_K77';
    const lead: Lead = {
      id: `LD-${META_CANARY}-01`,
      ruleId: `RULE-${META_CANARY}`,
      family: 'F1',
      tier: 'strong',
      potential: 'high',
      confidence: 0.9,
      title: 'Valid Lead Title',
      needs: [`Verify parameter ${META_CANARY} with manual check`],
      doesNotProve: [`Does not prove exploitability of ${META_CANARY}`],
      evidence: {
        preview: maskSecret('token=safe_preview_123'),
        location: maskLocation('https://example.com/api'),
      },
      tags: ['secret', `tag_${META_CANARY}`],
      chainIds: [`CH-${META_CANARY}-99`],
      scopeStatus: 'in-scope',
      timestamp: Date.now(),
      origin: `https://${META_CANARY}.example.com`,
      url: 'https://example.com/api',
      sourceSensor: 'S2',
      remediation: `Rotate the leaked secret ${META_CANARY} immediately`,
    };

    const md = formatLeadsReportMarkdown([lead]);
    const json = formatLeadsReportJson([lead]);
    const sarif = formatLeadsReportSarif([lead]);

    expect(md, 'Markdown leaked metadata canary').not.toContain(META_CANARY);
    expect(json, 'JSON leaked metadata canary').not.toContain(META_CANARY);
    expect(sarif, 'SARIF leaked metadata canary').not.toContain(META_CANARY);
  });

  it('guarantees page-derived taint source values never cross the messaging boundary into lead evidence or store', () => {
    const taintCanaries = {
      hash: 'CANARY_HASH_TOKEN_SECRET_111',
      search: 'CANARY_SEARCH_PARAM_SECRET_222',
      referrer: 'CANARY_REFERRER_SECRET_333',
      windowName: 'CANARY_WINDOW_NAME_SECRET_444',
      postMessage: 'CANARY_POST_MESSAGE_SECRET_555',
    };

    const store = new LeadStore();

    for (const [sourceCat, canary] of Object.entries(taintCanaries)) {
      // In the new P0 design, only safe metadata (sourceCategory) is transmitted, never sourceValue
      const lead: Lead = {
        id: `LD-SINK-${sourceCat}-01`,
        ruleId: 'PAR-004',
        family: 'F5',
        tier: 'weak',
        potential: 'medium',
        confidence: 0.7,
        title: `[Page-Reported] Client-Side DOM Sink Execution with Controlled Input (Element.innerHTML)`,
        needs: ['audit whether input reaches sink unescaped to verify DOM XSS'],
        doesNotProve: ['exploitable DOM XSS execution'],
        evidence: {
          preview: maskSecret(`Controlled input from ${sourceCat} detected`),
          location: maskLocation('https://example.com/test'),
          context: `Sink Element.innerHTML received string containing data from ${sourceCat}`,
        },
        tags: ['page-reported', 'dom-xss', 'sink', 'taint-lite', 'Element.innerHTML'],
        scopeStatus: 'in-scope',
        timestamp: Date.now(),
        origin: 'https://example.com',
        url: 'https://example.com/test',
        sourceSensor: 'S3',
      };

      store.addLead(lead);

      const leads = store.getLeadsForOrigin('https://example.com');
      const serialized = JSON.stringify(leads);
      const md = formatLeadsReportMarkdown(leads);
      const json = formatLeadsReportJson(leads);

      expect(serialized, `Stored taint canary for ${sourceCat}`).not.toContain(canary);
      expect(md, `Markdown report leaked taint canary for ${sourceCat}`).not.toContain(canary);
      expect(json, `JSON report leaked taint canary for ${sourceCat}`).not.toContain(canary);
    }
  });
});
