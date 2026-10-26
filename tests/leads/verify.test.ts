import { describe, it, expect, afterEach } from 'vitest';
import type { Lead, HunterConfig } from '../../src/leads/types';
import { crc32, base62Encode, validateCrc32Base62Token } from '../../src/leads/verify/checksums';
import { detectSecrets } from '../../src/leads/detectors/f1-secrets';
import { verifyLeadPassive, applyPassiveVerdicts } from '../../src/leads/verify/passive';
import {
  verifyLeadActive,
  interpretSourceMapProbe,
  interpretBucketProbe,
  interpretCorsProbes,
  planSourceMapUrl,
  planBucketUrl,
  activeCapabilityOf,
  planActiveProbe,
  matchProbePlan,
  type ActiveVerifyDeps,
  type ApprovedProbePlan,
} from '../../src/leads/verify/active';
import { executeHunterProbeWithBody } from '../../src/leads/hunter/hunter';
import { calculateLeadPriority } from '../../src/leads/ranking/ranking';
import { LeadStore } from '../../src/leads/store/lead-store';
import { formatLeadsReportMarkdown, formatLeadsReportJson, formatLeadsReportSarif } from '../../src/leads/export/export';
import { maskSecret, maskLocation } from '../../src/leads/sieve/mask';
import { handleVerifyLead, globalLeadStore } from '../../src/background/leads-handler';
import { DEFAULT_SETTINGS } from '../../src/shared/constants';

function makeLead(over: Partial<Lead> = {}): Lead {
  return {
    id: 'LD-TEST-1',
    ruleId: 'AUTH-003',
    family: 'F4',
    tier: 'observed',
    potential: 'high',
    confidence: 0.95,
    title: 'Test lead',
    needs: [],
    doesNotProve: [],
    evidence: { preview: maskSecret('preview-value-1234'), location: maskLocation('https://app.example.com/') },
    tags: [],
    scopeStatus: 'in-scope',
    timestamp: 1,
    origin: 'https://app.example.com',
    url: 'https://app.example.com/',
    sourceSensor: 'S1',
    ...over,
  };
}

function ghToken(body = 'aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC2'): string {
  return `ghp_${body}${base62Encode(crc32(body), 6)}`;
}

const mapLead = (): Lead =>
  makeLead({
    ruleId: 'MAP-001',
    family: 'F3',
    potential: 'low',
    tags: ['sourcemap'],
    needs: ['fetch map'],
    evidence: { preview: maskLocation('app.js.map'), location: maskLocation('https://app.example.com/app.js') },
    url: 'https://app.example.com/app.js',
  });

describe('offline checksums', () => {
  it('computes standard CRC32', () => {
    expect(crc32('123456789').toString(16)).toBe('cbf43926');
  });
  it('accepts a self-consistent token and rejects a tampered one', () => {
    const good = ghToken();
    expect(validateCrc32Base62Token(good)).toBe(true);
    const bad = good.slice(0, -1) + (good.endsWith('a') ? 'b' : 'a');
    expect(validateCrc32Base62Token(bad)).toBe(false);
  });
  it('returns undefined for formats that carry no checksum', () => {
    expect(validateCrc32Base62Token('AKIAABCDEFGHIJKLMNOP')).toBeUndefined();
  });
});

describe('detection-time facts never leak the raw value', () => {
  it('attaches checksum/entropy facts to a GitHub token lead and stores no raw text', () => {
    const tok = ghToken();
    const leads = detectSecrets(`const cfg = { token: "${tok}" };`, 'https://app.example.com/main.js', 'in-scope');
    const lead = leads.find((l) => l.ruleId === 'SEC-001');
    expect(lead).toBeDefined();
    expect(lead?.facts?.checksumValid).toBe(true);
    expect(lead?.facts?.length).toBe(tok.length);
    expect(JSON.stringify(lead)).not.toContain(tok);
  });
  it('flags a token with a bad checksum and an example-looking context', () => {
    const tok = ghToken();
    const bad = tok.slice(0, -1) + (tok.endsWith('a') ? 'b' : 'a');
    const leads = detectSecrets(`// example: set token to ${bad} in your README`, 'https://app.example.com/a.js', 'in-scope');
    const lead = leads.find((l) => l.ruleId === 'SEC-001');
    expect(lead?.facts?.checksumValid).toBe(false);
    expect(lead?.facts?.exampleContext).toBe(true);
    expect(lead?.facts?.inComment).toBe(true);
  });
  it('judges example-context on the same line only', () => {
    const tok = ghToken();
    const code = `const real = "${tok}";\n// docs example: nothing to see here\n`;
    const lead = detectSecrets(code, 'https://app.example.com/a.js', 'in-scope').find((l) => l.ruleId === 'SEC-001');
    expect(lead?.facts?.exampleContext).toBe(false);
    expect(verifyLeadPassive(lead as Lead).status).toBe('likely');
  });
  it('marks an expired JWT without false_positive veto dismissal', () => {
    const b64 = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url');
    const jwt = `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ sub: 'u1', exp: 1000 })}.c2lnbmF0dXJlLXNpZ25hdHVyZS1zaWduYXR1cmU`;
    const leads = detectSecrets(`var t="${jwt}";`, 'https://app.example.com/a.js', 'in-scope');
    const lead = leads.find((l) => l.ruleId === 'SEC-004');
    expect(lead?.facts?.jwtExpired).toBe(true);
    expect(JSON.stringify(lead)).not.toContain(jwt);

    // P1: Expired claim locally decoded is unverified fact, never a false_positive dismissal
    const v = verifyLeadPassive(lead as Lead);
    expect(v.status).not.toBe('false_positive');
    expect(v.checks.some((c) => c.id === 'jwt-expiry' && c.outcome === 'inconclusive')).toBe(true);
    expect(v.missing.some((m) => m.includes('signature validation'))).toBe(true);
  });
});

describe('passive verdicts and scope taxonomy', () => {
  it('confirms an observed, precondition-free, in-scope condition for registered rule AUTH-003', () => {
    const v = verifyLeadPassive(makeLead());
    expect(v.status).toBe('confirmed');
    expect(v.evidenceStatus).toBe('observed');
    expect(v.scopeStatus).toBe('in-scope');
    expect(v.securityAssessment).toBe('confirmed');
    expect(v.missing).toEqual([]);
  });

  it('defaults unhandled or arbitrary rules to unreviewed/uncertain, never passively confirmed or likely', () => {
    const lead = makeLead({
      ruleId: 'ARBITRARY-RULE',
      tier: 'observed',
      confidence: 0.95,
      needs: [],
      scopeStatus: 'in-scope',
    });
    const v = verifyLeadPassive(lead);
    expect(v.status).toBe('uncertain');
    expect(v.securityAssessment).toBe('unreviewed');
    expect(v.evidenceStatus).toBe('observed');
    expect(v.summary).toContain('unreviewed');
  });

  it('unhandled or arbitrary rule with outstanding preconditions stays uncertain and unreviewed, never likely', () => {
    const lead = makeLead({
      ruleId: 'ARBITRARY-RULE',
      tier: 'observed',
      confidence: 0.95,
      needs: ['manual proof'],
      scopeStatus: 'in-scope',
    });
    const v = verifyLeadPassive(lead);
    expect(v.status).toBe('uncertain');
    expect(v.securityAssessment).toBe('unreviewed');
    expect(v.summary).toContain('unreviewed');
  });

  it('unhandled or arbitrary rule with unknown scope stays uncertain and unreviewed', () => {
    const lead = makeLead({
      ruleId: 'ARBITRARY-RULE',
      tier: 'observed',
      confidence: 0.95,
      needs: [],
      scopeStatus: 'unknown',
    });
    const v = verifyLeadPassive(lead);
    expect(v.status).toBe('uncertain');
    expect(v.securityAssessment).toBe('unreviewed');
  });

  it('says likely (not confirmed) while preconditions are outstanding for registered rule', () => {
    const v = verifyLeadPassive(makeLead({ ruleId: 'AUTH-003', needs: ['prove the page is sensitive'] }));
    expect(v.status).toBe('likely');
    expect(v.securityAssessment).toBe('likely');
    expect(v.missing).toContain('prove the page is sensitive');
  });

  it('says uncertain for weak/whisper heuristics', () => {
    expect(verifyLeadPassive(makeLead({ tier: 'weak', needs: ['x'] })).status).toBe('uncertain');
    expect(verifyLeadPassive(makeLead({ tier: 'whisper' })).status).toBe('uncertain');
  });

  it('says uncertain when detector confidence is low', () => {
    expect(verifyLeadPassive(makeLead({ confidence: 0.5 })).status).toBe('uncertain');
  });

  it('never confirms a page-reported (forgeable) signal', () => {
    const v = verifyLeadPassive(makeLead({ tags: ['page-reported'], tier: 'observed' }));
    expect(v.status).toBe('uncertain');
    expect(v.evidenceStatus).toBe('inconclusive');
  });

  it('labels info-level observations informational, not bugs', () => {
    const v = verifyLeadPassive(makeLead({ potential: 'info' }));
    expect(v.status).toBe('informational');
    expect(v.securityAssessment).toBe('informational');
  });

  it('rules out public-by-design identifiers', () => {
    const v = verifyLeadPassive(makeLead({ ruleId: 'SEC-001-PUB', family: 'F1', tags: ['stripe', 'public-key'], potential: 'info' }));
    expect(v.status).toBe('false_positive');
    expect(v.securityAssessment).toBe('false_positive');
  });

  it('respects a researcher false_positive triage above everything else', () => {
    const v = verifyLeadPassive(makeLead({ triageState: 'false_positive' }));
    expect(v.status).toBe('false_positive');
    expect(v.securityAssessment).toBe('false_positive');
  });

  it('never confirms a credential passively, even when every offline check passes', () => {
    const lead = makeLead({
      ruleId: 'SEC-001',
      family: 'F1',
      tags: ['secret', 'gcp'],
      potential: 'critical',
      facts: { checksumValid: true, entropyBits: 4.8, length: 39, exampleContext: false },
    });
    const v = verifyLeadPassive(lead);
    expect(v.status).toBe('likely');
    expect(v.checks.some((c) => c.id === 'liveness' && c.outcome === 'inconclusive')).toBe(true);
    expect(v.checks.some((c) => c.id === 'token-checksum' && c.detail.includes('format and checksum pattern match'))).toBe(true);
  });

  it('downgrades a secret with an invalid checksum / example context / low entropy to uncertain', () => {
    const base = { ruleId: 'SEC-001', family: 'F1' as const, tags: ['secret'], potential: 'high' as const };
    expect(verifyLeadPassive(makeLead({ ...base, facts: { checksumValid: false } })).status).toBe('uncertain');
    expect(verifyLeadPassive(makeLead({ ...base, facts: { exampleContext: true } })).status).toBe('uncertain');
    expect(verifyLeadPassive(makeLead({ ...base, facts: { entropyBits: 2.1, length: 32 } })).status).toBe('uncertain');
  });

  it('keeps reference-only leads (source map, bucket) uncertain until an active check runs', () => {
    const v = verifyLeadPassive(makeLead({ ruleId: 'MAP-001', family: 'F3', potential: 'low', needs: ['fetch map'] }));
    expect(v.status).toBe('uncertain');
    expect(v.missing.join(' ')).toMatch(/Verify actively/);
  });

  it('treats an Hunter active-verified lead as confirmed on in-scope target', () => {
    const v = verifyLeadPassive(makeLead({ tags: ['cors', 'active-verified', 'hunter'] }));
    expect(v.status).toBe('confirmed');
    expect(v.evidenceStatus).toBe('reproduced');
    expect(v.securityAssessment).toBe('confirmed');
  });

  it('separates evidence observation from scope: unknown scope is never confirmed and retains missing items', () => {
    const v = verifyLeadPassive(makeLead({ scopeStatus: 'unknown' }));
    expect(v.status).toBe('likely');
    expect(v.evidenceStatus).toBe('observed');
    expect(v.scopeStatus).toBe('unknown');
    expect(v.securityAssessment).toBe('unreviewed');
    expect(v.missing.length).toBeGreaterThanOrEqual(1);
    expect(v.missing.join(' ')).toMatch(/Confirm the asset is in program scope/);
  });

  it('separates evidence observation from scope: out-of-scope lead is uncertain, unreviewed, and retains out-of-scope warning', () => {
    const v = verifyLeadPassive(makeLead({ scopeStatus: 'out-of-scope', needs: ['n'] }));
    expect(v.status).toBe('uncertain');
    expect(v.scopeStatus).toBe('out-of-scope');
    expect(v.securityAssessment).toBe('unreviewed');
    expect(v.missing.join(' ')).toMatch(/Out of scope/);
  });

  it('applyPassiveVerdicts keeps an existing active verdict but lets triage override it', () => {
    const active = {
      status: 'confirmed' as const,
      evidenceStatus: 'reproduced' as const,
      scopeStatus: 'in-scope' as const,
      securityAssessment: 'confirmed' as const,
      method: 'active' as const,
      summary: 's',
      checks: [],
      missing: [],
      verifiedAt: 1,
    };
    const [kept] = applyPassiveVerdicts([makeLead({ verdict: active, needs: ['x'] })]);
    expect(kept?.verdict?.method).toBe('active');
    const [overridden] = applyPassiveVerdicts([makeLead({ verdict: active, triageState: 'false_positive' })]);
    expect(overridden?.verdict?.status).toBe('false_positive');
  });
});

describe('ranking uses the verdict', () => {
  it('lifts confirmed, sinks uncertain, zeroes false positives', () => {
    const mk = (status: 'confirmed' | 'uncertain' | 'false_positive'): Lead =>
      makeLead({
        verdict: {
          status,
          evidenceStatus: 'observed',
          scopeStatus: 'in-scope',
          securityAssessment: status === 'confirmed' ? 'confirmed' : (status === 'false_positive' ? 'false_positive' : 'unreviewed'),
          method: 'passive',
          summary: '',
          checks: [],
          missing: [],
          verifiedAt: 1,
        },
      });
    const none = calculateLeadPriority(makeLead());
    expect(calculateLeadPriority(mk('confirmed'))).toBeGreaterThan(none);
    expect(calculateLeadPriority(mk('uncertain'))).toBeLessThan(none);
    expect(calculateLeadPriority(mk('false_positive'))).toBe(0);
  });
});

describe('active interpreters (pure)', () => {
  const out = (status: number, body = '', headers: Record<string, string> = {}) => ({
    entry: {
      id: 'h',
      timestamp: 1,
      confirmedByUser: true,
      scopeStatus: 'in-scope' as const,
      request: { targetUrl: 'https://x', method: 'GET' as const, reason: 'r' },
      response: { status, headers, elapsedMs: 1 },
    },
    body,
  });
  const blocked = {
    entry: {
      id: 'h',
      timestamp: 1,
      confirmedByUser: true,
      scopeStatus: 'unknown' as const,
      request: { targetUrl: 'https://x', method: 'GET' as const, reason: 'r' },
      resultNotes: 'Blocked: Target URL is unknown.',
    },
  };

  it('source map: confirmed only for valid bounded JSON map; HTML fallback and 404 are false positives, 401/403 are uncertain', () => {
    // Valid v3 map with mappings and non-empty sources
    expect(interpretSourceMapProbe(out(200, '{"version":3,"sources":["a.ts"],"mappings":"AAAA","sourcesContent":["x"]}', { 'content-type': 'application/json' })).status).toBe('confirmed');
    // Empty sources array must not confirm (no exposed source paths)
    expect(interpretSourceMapProbe(out(200, '{"version":3,"sources":[],"mappings":""}', { 'content-type': 'application/json' })).status).toBe('uncertain');
    // Missing or invalid mappings string must not confirm
    expect(interpretSourceMapProbe(out(200, '{"version":3,"sources":["a.ts"]}', { 'content-type': 'application/json' })).status).toBe('uncertain');
    expect(interpretSourceMapProbe(out(200, '{"version":3,"sources":["a.ts"],"mappings":123}', { 'content-type': 'application/json' })).status).toBe('uncertain');
    // Malformed object / missing sources / wrong-type schemas
    expect(interpretSourceMapProbe(out(200, '{"version":3,"mappings":""}', { 'content-type': 'application/json' })).status).toBe('uncertain');
    expect(interpretSourceMapProbe(out(200, '{"version":"3","sources":["a.ts"],"mappings":""}', { 'content-type': 'application/json' })).status).toBe('uncertain');
    expect(interpretSourceMapProbe(out(200, '{"version":3,"sources":"a.ts","mappings":""}', { 'content-type': 'application/json' })).status).toBe('uncertain');
    expect(interpretSourceMapProbe(out(200, '{"version":3,"sources":[123],"mappings":""}', { 'content-type': 'application/json' })).status).toBe('uncertain');
    // Truncated / malformed JSON without truncation evidence must not confirm
    expect(interpretSourceMapProbe(out(200, '{"version":3,"sources":["a.ts"] ...truncated', { 'content-type': 'application/json' })).status).toBe('uncertain');
    // A real map is far larger than the bounded sample: a CUT prefix with v3 structure and truncation proof must confirm
    const bigMap = JSON.stringify({ version: 3, sources: Array.from({ length: 400 }, (_, i) => `src/m${i}.ts`), sourcesContent: Array.from({ length: 400 }, () => 'x'.repeat(400)), mappings: 'AAAA;'.repeat(2000) });
    const sample = bigMap.slice(0, 16 * 1024);
    expect(interpretSourceMapProbe(out(206, sample, { 'content-type': 'application/json' })).status).toBe('confirmed');
    expect(interpretSourceMapProbe(out(200, sample, { 'content-type': 'application/json', 'content-length': String(bigMap.length) })).status).toBe('confirmed');
    // ...but a short malformed body that merely starts like a map is not evidence of truncation
    expect(interpretSourceMapProbe(out(200, '{"version":3,"sources":["a.ts"] garbage', { 'content-type': 'application/json' })).status).toBe('uncertain');
    // Non-JSON regex-only matches in HTML fallback
    expect(interpretSourceMapProbe(out(200, '<!doctype html><html>"version": 3, "sources": []</html>', { 'content-type': 'text/html' })).status).toBe('false_positive');
    expect(interpretSourceMapProbe(out(404)).status).toBe('false_positive');
    expect(interpretSourceMapProbe(out(404)).summary).toContain('not found at this URL during this check');
    expect(interpretSourceMapProbe(out(410)).status).toBe('false_positive');
    expect(interpretSourceMapProbe(out(410)).summary).toContain('not found at this URL during this check');
    // 401/403: auth protected, not retrieved in this request, returns uncertain rather than false_positive
    expect(interpretSourceMapProbe(out(403)).status).toBe('uncertain');
    expect(interpretSourceMapProbe(out(401)).status).toBe('uncertain');
    expect(interpretSourceMapProbe(out(500)).status).toBe('uncertain');
    expect(interpretSourceMapProbe(out(0)).status).toBe('uncertain');
    const b = interpretSourceMapProbe(blocked);
    expect(b.status).toBe('uncertain');
    expect(b.ran).toBe(false);
  });

  it('bucket: listing=confirmed, AccessDenied=informational (inconclusive check, never false_positive), NoSuchBucket=likely, else uncertain', () => {
    expect(interpretBucketProbe(out(200, '<?xml?><ListBucketResult>'), 'aws').status).toBe('confirmed');
    const denied = interpretBucketProbe(out(403, '<Error><Code>AccessDenied</Code></Error>'), 'aws');
    expect(denied.status).toBe('informational');
    expect(denied.checks[0]?.outcome).toBe('inconclusive');
    expect(denied.checks[0]?.detail).toContain('AccessDenied');
    expect(denied.checks[0]?.detail).toContain('Object-level read permissions were not tested');
    expect(denied.missing.some((m) => m.includes('object-level read'))).toBe(true);

    expect(interpretBucketProbe(out(404, '<Error><Code>NoSuchBucket</Code></Error>'), 'aws').status).toBe('likely');
    expect(interpretBucketProbe(out(301, 'PermanentRedirect'), 'aws').status).toBe('uncertain');
    expect(interpretBucketProbe(blocked, 'aws').ran).toBe(false);
  });

  it('cors: reproduced=likely (impact still needs data), nothing reproduced=uncertain, no result=not run', () => {
    const hit = { targetUrl: 'u', testedOrigin: 'https://evil.tld', confirmedVulnerable: true, details: 'd' };
    const miss = { targetUrl: 'u', testedOrigin: 'null', confirmedVulnerable: false, details: 'd' };
    expect(interpretCorsProbes([hit]).status).toBe('likely');
    expect(interpretCorsProbes([miss]).status).toBe('uncertain');
    expect(interpretCorsProbes([miss]).missing.some((m) => m.includes('curl -H "Origin: https://evil.tld"'))).toBe(true);
    expect(interpretCorsProbes([]).ran).toBe(false);
  });

  it('plans safe targets only', () => {
    const map = makeLead({ ruleId: 'MAP-001', evidence: { preview: maskLocation('app.js.map') , location: maskLocation('https://app.example.com/static/app.js') }, url: 'https://app.example.com/static/app.js' });
    expect(planSourceMapUrl(map)).toBe('https://app.example.com/static/app.js.map');
    const signed = makeLead({ ruleId: 'MAP-001', evidence: { preview: maskLocation('https://cdn.example.com/a.map?sig=abc'), location: maskLocation('x') } });
    expect(planSourceMapUrl(signed)).toBeUndefined();
    const bucket = makeLead({ ruleId: 'CLD-001', tags: ['cloud-bucket', 'aws'], evidence: { preview: maskSecret('my-bucket'), location: maskLocation('x'), extractedNames: ['my-bucket'] } });
    expect(planBucketUrl(bucket)?.url).toBe('https://my-bucket.s3.amazonaws.com/?max-keys=0');
    const evil = makeLead({ ruleId: 'CLD-001', tags: ['aws'], evidence: { preview: maskSecret('x'), location: maskLocation('x'), extractedNames: ['a/../../b'] } });
    expect(planBucketUrl(evil)).toBeUndefined();
    expect(activeCapabilityOf(map)).toBe('sourcemap');
    expect(activeCapabilityOf(makeLead())).toBe('none');
  });
});

describe('active verification honours every Hunter gate', () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });
  const cfg: HunterConfig = { enabled: true, maxRequestsPerSecond: 100 };

  function depsFor(scope: Lead['scopeStatus'], confirmed: boolean, config: HunterConfig = cfg): ActiveVerifyDeps {
    return {
      resolveScope: () => scope,
      probe: (req, sc, limit) => executeHunterProbeWithBody(req, sc, config, confirmed, limit),
      corsProbe: () => Promise.resolve([]),
    };
  }

  it('sends NO request for unknown scope, out-of-scope, unconfirmed, or disabled Hunter - and keeps the passive verdict', async () => {
    let calls = 0;
    globalThis.fetch = () => { calls++; return Promise.resolve(new Response('x')); };
    for (const d of [
      depsFor('unknown', true),
      depsFor('out-of-scope', true),
      depsFor('in-scope', false),
      depsFor('in-scope', true, { enabled: false, maxRequestsPerSecond: 1 }),
    ]) {
      const v = await verifyLeadActive(mapLead(), d);
      expect(v.status).toBe('uncertain');
      expect(v.method).toBe('passive');
      expect(v.summary).toMatch(/Active check not completed/);
    }
    expect(calls).toBe(0);
  });

  it('confirms a real source map for an in-scope target using a cookie-less, no-redirect, read-only GET', async () => {
    let seen: RequestInit | undefined;
    globalThis.fetch = (_u: string | URL | Request, init?: RequestInit) => {
      seen = init;
      return Promise.resolve(
        new Response('{"version":3,"sources":["a.ts"],"mappings":"AAAA","sourcesContent":["secret code"]}', {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      );
    };
    const v = await verifyLeadActive(mapLead(), depsFor('in-scope', true));
    expect(v.status).toBe('confirmed');
    expect(v.method).toBe('active');
    expect(seen?.method).toBe('GET');
    expect(seen?.credentials).toBe('omit');
    expect(seen?.redirect).toBe('manual');
    // the body sample never reaches the stored verdict
    expect(JSON.stringify(v)).not.toContain('secret code');
  });

  it('dismisses a map URL that actually serves an SPA HTML fallback', async () => {
    globalThis.fetch = () =>
      Promise.resolve(
        new Response('<!doctype html><html></html>', { status: 200, headers: { 'content-type': 'text/html' } }),
      );
    const v = await verifyLeadActive(mapLead(), depsFor('in-scope', true));
    expect(v.status).toBe('false_positive');
  });

  it('never overrides a passive veto', async () => {
    let calls = 0;
    globalThis.fetch = () => {
      calls++;
      return Promise.resolve(new Response('{"version":3,"sources":[]}'));
    };
    const v = await verifyLeadActive({ ...mapLead(), triageState: 'false_positive' }, depsFor('in-scope', true));
    expect(v.status).toBe('false_positive');
    expect(calls).toBe(0);
  });

  it('executes when approvedPlan matches the recomputed plan exactly', async () => {
    let calls = 0;
    globalThis.fetch = () => {
      calls++;
      return Promise.resolve(
        new Response('{"version":3,"sources":["a.ts"],"mappings":"AAAA","sourcesContent":["ok"]}', {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      );
    };
    const lead = mapLead();
    const plan = planActiveProbe(lead);
    expect(plan).toBeDefined();
    if (plan === undefined) throw new Error('plan is undefined');
    const deps = {
      ...depsFor('in-scope', true),
      approvedPlan: {
        capability: plan.capability,
        targetUrl: plan.targetUrl,
        maxRequests: plan.maxRequests,
        method: plan.method,
      },
    };
    const v = await verifyLeadActive(lead, deps);
    expect(v.status).toBe('confirmed');
    expect(calls).toBe(1);
  });

  it('rejects execution without sending requests when approvedPlan differs (tampered or stale)', async () => {
    let calls = 0;
    globalThis.fetch = () => {
      calls++;
      return Promise.resolve(new Response(''));
    };
    const lead = mapLead();
    const deps = {
      ...depsFor('in-scope', true),
      approvedPlan: {
        capability: 'sourcemap' as const,
        targetUrl: 'https://attacker.com/evil.js.map', // Tampered target
        maxRequests: 1,
        method: 'GET',
      },
    };
    const v = await verifyLeadActive(lead, deps);
    expect(v.status).toBe('uncertain');
    expect(v.securityAssessment).toBe('unreviewed');
    expect(v.summary).toContain('does not match');
    expect(v.checks.some((c) => c.id === 'plan-binding' && c.outcome === 'fail')).toBe(true);
    expect(calls).toBe(0); // Zero network probes sent
  });

  it('rejects execution when lead changed between display and execution', async () => {
    let calls = 0;
    globalThis.fetch = () => {
      calls++;
      return Promise.resolve(new Response(''));
    };
    const originalLead = mapLead();
    const plan = planActiveProbe(originalLead);
    expect(plan).toBeDefined();
    if (plan === undefined) throw new Error('plan is undefined');

    // Simulate lead changing in store between display and click
    const changedLead = {
      ...originalLead,
      url: 'https://app.example.com/other.js',
      evidence: { preview: maskLocation('other.js.map'), location: maskLocation('https://app.example.com/other.js') },
    };

    const deps = {
      ...depsFor('in-scope', true),
      approvedPlan: {
        capability: plan.capability,
        targetUrl: plan.targetUrl, // Old URL
        maxRequests: plan.maxRequests,
        method: plan.method,
      },
    };
    const v = await verifyLeadActive(changedLead, deps);
    expect(v.status).toBe('uncertain');
    expect(v.summary).toContain('does not match');
    expect(calls).toBe(0); // Protected from executing against wrong target
  });

  it('says plainly when no safe automated check exists', async () => {
    const v = await verifyLeadActive(makeLead({ needs: ['n'] }), depsFor('in-scope', true));
    expect(v.status).toBe('likely');
    expect(v.summary).toMatch(/no safe automated check/);
  });
});

describe('store, exports and canary safety', () => {
  it('persists sanitized verdict + facts and rejects junk', () => {
    const store = new LeadStore();
    const lead = makeLead({
      verdict: {
        status: 'likely',
        evidenceStatus: 'observed',
        scopeStatus: 'in-scope',
        securityAssessment: 'likely',
        method: 'passive',
        summary: 's',
        checks: [{ id: 'c', kind: 'passive', outcome: 'pass', detail: 'd' }],
        missing: ['m'],
        verifiedAt: 5,
      },
      facts: { checksumValid: true, entropyBits: 4.2, length: 40, jwtAlg: 'HS256' },
    });
    store.addLead(lead);
    const got = store.getLead(lead.id);
    expect(got?.verdict?.status).toBe('likely');
    expect(got?.verdict?.evidenceStatus).toBe('observed');
    expect(got?.verdict?.securityAssessment).toBe('likely');
    expect(got?.facts?.checksumValid).toBe(true);

    const junk = makeLead({ id: 'LD-JUNK', evidence: { preview: maskSecret('junk-preview-0001'), location: maskLocation('https://app.example.com/j') } });
    (junk as unknown as Record<string, unknown>).verdict = { status: 'definitely-a-bug', checks: 'x' };
    (junk as unknown as Record<string, unknown>).facts = { rawSecret: 'AKIAABCDEFGHIJKLMNOP', entropyBits: 'high' };
    store.addLead(junk);
    const j = store.getLead('LD-JUNK');
    expect(j?.verdict).toBeUndefined();
    expect(j?.facts).toBeUndefined();
  });

  it('setVerdict stores an active verdict', () => {
    const store = new LeadStore();
    store.addLead(makeLead());
    expect(
      store.setVerdict('LD-TEST-1', {
        status: 'confirmed',
        evidenceStatus: 'reproduced',
        scopeStatus: 'in-scope',
        securityAssessment: 'confirmed',
        method: 'active',
        summary: 'ok',
        checks: [],
        missing: [],
        verifiedAt: 9,
      }),
    ).toBe(true);
    expect(store.getLead('LD-TEST-1')?.verdict?.method).toBe('active');
    expect(
      store.setVerdict('nope', {
        status: 'confirmed',
        evidenceStatus: 'reproduced',
        scopeStatus: 'in-scope',
        securityAssessment: 'confirmed',
        method: 'active',
        summary: '',
        checks: [],
        missing: [],
        verifiedAt: 1,
      }),
    ).toBe(false);
  });

  it('exports include the verdict and still contain no raw secret', () => {
    const tok = ghToken();
    const leads = detectSecrets(`x="${tok}"`, 'https://app.example.com/a.js', 'in-scope').map((l) => ({ ...l, verdict: verifyLeadPassive(l) }));
    const md = formatLeadsReportMarkdown(leads);
    const json = formatLeadsReportJson(leads);
    const sarif = formatLeadsReportSarif(leads);
    expect(md).toContain('Self-check verdict');
    expect(md).toContain('HYPOTHESIS');
    expect(json).toContain('"verdict"');
    expect(sarif).toContain('"level": "warning"');
    for (const out of [md, json, sarif]) expect(out).not.toContain(tok);
  });

  describe('planActiveProbe', () => {
    it('plans safe read-only sourcemap probe for MAP-001', () => {
      const lead = makeLead({
        ruleId: 'MAP-001',
        url: 'https://app.example.com/bundle.js',
        evidence: { preview: maskLocation('bundle.js.map'), location: maskLocation('https://app.example.com/bundle.js') },
      });
      const plan = planActiveProbe(lead);
      expect(plan).toBeDefined();
      expect(plan?.capability).toBe('sourcemap');
      expect(plan?.targetUrl).toBe('https://app.example.com/bundle.js.map');
      expect(plan?.maxRequests).toBe(1);
      expect(plan?.method).toBe('GET');
      expect(plan?.credentials).toBe('omit');
      expect(plan?.redirect).toBe('manual');
      expect(plan?.testOrigins).toBeUndefined();
      expect(plan?.description).toContain('read-only GET request');
    });

    it('plans safe bucket probe with max-keys=0 for CLD-001', () => {
      const lead = makeLead({
        ruleId: 'CLD-001',
        tags: ['cloud-bucket', 'aws'],
        url: 'https://app.example.com/',
        evidence: {
          preview: maskSecret('https://my-bucket.s3.amazonaws.com/'),
          location: maskLocation('https://app.example.com/'),
          extractedNames: ['my-bucket'],
        },
      });
      const plan = planActiveProbe(lead);
      expect(plan).toBeDefined();
      expect(plan?.capability).toBe('bucket');
      expect(plan?.targetUrl).toBe('https://my-bucket.s3.amazonaws.com/?max-keys=0');
      expect(plan?.maxRequests).toBe(1);
      expect(plan?.method).toBe('GET');
      expect(plan?.credentials).toBe('omit');
      expect(plan?.redirect).toBe('manual');
      expect(plan?.testOrigins).toBeUndefined();
      expect(plan?.description).toContain('max-keys=0');
    });

    it('plans CORS probe explicitly disclosing all 4 origins, request count, and credentials omission', () => {
      const lead = makeLead({
        ruleId: 'COR-001',
        tags: ['cors-reflection'],
        url: 'https://api.target.com/user/profile',
      });
      const plan = planActiveProbe(lead);
      expect(plan).toBeDefined();
      expect(plan?.capability).toBe('cors');
      expect(plan?.targetUrl).toBe('https://api.target.com/user/profile');
      expect(plan?.maxRequests).toBe(4);
      expect(plan?.method).toBe('GET');
      expect(plan?.credentials).toBe('omit');
      expect(plan?.redirect).toBe('manual');
      expect(plan?.testOrigins).toEqual([
        'null',
        'https://evil.tld',
        'https://api.target.com.evil.tld',
        'https://evilapi.target.com',
      ]);
      expect(plan?.description).toContain('up to 4 read-only GET requests');
      expect(plan?.description).toContain('null');
      expect(plan?.description).toContain('https://evil.tld');
      expect(plan?.description).toContain('https://api.target.com.evil.tld');
      expect(plan?.description).toContain('https://evilapi.target.com');
      expect(plan?.description).toContain('no cookies, redirects not followed');
    });

    it('returns undefined for non-actively probeable lead', () => {
      const lead = makeLead({ ruleId: 'AUTH-003' });
      expect(planActiveProbe(lead)).toBeUndefined();
    });

    it('matchProbePlan validates matching and detects discrepancies', () => {
      const plan = planActiveProbe(mapLead());
      expect(plan).toBeDefined();
      if (plan === undefined) throw new Error('plan is undefined');
      const approved: ApprovedProbePlan = {
        capability: plan.capability,
        targetUrl: plan.targetUrl,
        maxRequests: plan.maxRequests,
        method: plan.method,
      };
      expect(matchProbePlan(plan, approved)).toBe(true);
      expect(matchProbePlan(plan, undefined)).toBe(false);
      expect(matchProbePlan(undefined, approved)).toBe(false);
      expect(matchProbePlan(plan, { ...approved, targetUrl: 'https://evil.com' })).toBe(false);
      expect(matchProbePlan(plan, { ...approved, maxRequests: 99 })).toBe(false);
      expect(matchProbePlan(plan, { ...approved, method: 'POST' })).toBe(false);
      expect(matchProbePlan(plan, { ...approved, capability: 'bucket' })).toBe(false);
    });
  });

  describe('passive verdict with unknown scope (the default before a scope profile is set)', () => {
    const lead = (o: Partial<Lead>): Lead => makeLead({ scopeStatus: 'unknown', ...o });
    it('weak evidence stays uncertain, not likely', () => {
      expect(verifyLeadPassive(lead({ tier: 'whisper', confidence: 0.3, needs: ['prove it'] })).status).toBe('uncertain');
    });
    it('page-forgeable signals stay uncertain', () => {
      expect(verifyLeadPassive(lead({ tier: 'observed', confidence: 0.9, tags: ['page-reported'], needs: [] })).status).toBe('uncertain');
    });
    it('secret in example context stays uncertain', () => {
      expect(verifyLeadPassive(lead({ ruleId: 'SEC-001', family: 'F1', facts: { exampleContext: true } })).status).toBe('uncertain');
    });
    it('strong evidence is capped at likely, never confirmed', () => {
      const v = verifyLeadPassive(lead({ tier: 'observed', confidence: 0.95, needs: [] }));
      expect(v.status).toBe('likely');
      expect(v.securityAssessment).not.toBe('confirmed');
    });
  });

  describe('handleVerifyLead background binding', () => {
    it('executes when approvedPlan matches stored lead and updates store verdict', async () => {
      globalThis.fetch = () =>
        Promise.resolve(
          new Response('{"version":3,"sources":["app.ts"],"mappings":"AAAA","sourcesContent":["ok"]}', {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }),
        );
      const lead = mapLead();
      lead.id = 'LD-BG-TEST-1';
      globalLeadStore.addLead(lead);

      const plan = planActiveProbe(lead);
      expect(plan).toBeDefined();
      if (plan === undefined) throw new Error('plan is undefined');
      const settings = {
        ...DEFAULT_SETTINGS,
        hunterConfig: { enabled: true, maxRequestsPerSecond: 10 },
        activeScopeProfileId: 'default',
        scopeProfiles: [
          {
            id: 'default',
            name: 'Default',
            rules: [{ type: 'include' as const, pattern: 'app.example.com' }],
          },
        ],
      };

      const verdict = await handleVerifyLead(lead.id, settings, true, {
        capability: plan.capability,
        targetUrl: plan.targetUrl,
        maxRequests: plan.maxRequests,
        method: plan.method,
      });

      expect(verdict?.status).toBe('confirmed');
      expect(globalLeadStore.getLead(lead.id)?.verdict?.status).toBe('confirmed');
    });

    it('rejects in background if approvedPlan was tampered', async () => {
      let calls = 0;
      globalThis.fetch = () => {
        calls++;
        return Promise.resolve(new Response(''));
      };
      const lead = mapLead();
      lead.id = 'LD-BG-TEST-2';
      lead.url = 'https://app.example.com/other.js';
      lead.evidence = {
        preview: maskLocation('other.js.map'),
        location: maskLocation('https://app.example.com/other.js'),
      };
      globalLeadStore.addLead(lead);

      const settings = {
        ...DEFAULT_SETTINGS,
        hunterConfig: { enabled: true, maxRequestsPerSecond: 10 },
      };

      const verdict = await handleVerifyLead(lead.id, settings, true, {
        capability: 'sourcemap',
        targetUrl: 'https://attacker.example.com/other.map',
        maxRequests: 1,
        method: 'GET',
      });

      expect(verdict?.status).toBe('uncertain');
      expect(verdict?.summary).toContain('does not match');
      expect(calls).toBe(0);
    });
  });
});
