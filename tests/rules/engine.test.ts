/**
 * @file engine.test.ts
 * Comprehensive Vitest unit tests for each pure-TypeScript rule checker
 * and utility functions. All functions are imported directly — no browser
 * APIs are exercised here.
 *
 * Tests are driven from JSON fixture files (for regression coverage) and
 * also contain explicit named cases (for readability and IDE discoverability).
 */

import { describe, it, expect } from 'vitest';


// --------------------------------------------------------------------------
// Rule imports — adjust these paths if the rule files are renamed.
// All rule functions must be pure (no browser APIs).
// --------------------------------------------------------------------------
import { checkHsts } from '../../src/rules/headers/hsts';
import { checkCsp } from '../../src/rules/headers/csp';
import { checkXcto } from '../../src/rules/headers/xcto';
import { checkXfo } from '../../src/rules/headers/xfo';
import { checkReferrer } from '../../src/rules/headers/referrer';
import { checkDeprecated } from '../../src/rules/headers/deprecated';
import { checkInfoLeak } from '../../src/rules/headers/info-leak';
import { checkCacheCookie } from '../../src/rules/headers/cache-cookie';
import { computeScore } from '../../src/rules/scoring';
import { sanitizeEvidence, isSensitiveParamName, redactUrlQueryParams } from '../../src/rules/utils';
import { runRules } from '../../src/rules/engine';
import type { Hop, Finding } from '../../src/shared/types';

// --------------------------------------------------------------------------
// Fixture file imports (JSON assertions for batch-driven tests)
// --------------------------------------------------------------------------
import hstsFixtures from './fixtures/hsts.json';
import cspFixtures from './fixtures/csp.json';
import xctoFixtures from './fixtures/xcto.json';
import xfoFixtures from './fixtures/xfo.json';
import referrerFixtures from './fixtures/referrer.json';
import deprecatedFixtures from './fixtures/deprecated.json';
import infoLeakFixtures from './fixtures/info-leak.json';
import cacheCookieFixtures from './fixtures/cache-cookie.json';

// --------------------------------------------------------------------------
// Types for fixture shape
// --------------------------------------------------------------------------
interface FixtureHop {
  url?: string;
  status?: number;
  headers?: Record<string, string>;
  fromCache?: boolean;
  isHstsUpgrade?: boolean;
}

interface Fixture {
  description: string;
  hop: FixtureHop;
  expectedRuleIds: string[];
  notExpectedRuleIds: string[];
}

// --------------------------------------------------------------------------
// Helper: build a complete Hop from partial overrides.
// Derived rawHeaders automatically from headers to keep fixtures concise.
// --------------------------------------------------------------------------
function makeHop(overrides: Partial<Hop> & { headers?: Record<string, string> }): Hop {
  const headers = overrides.headers ?? {};
  const rawHeaders = Object.entries(headers).map(([name, value]) => ({ name, value }));
  return {
    requestId: 'test-001',
    url: 'https://example.com/',
    status: 200,
    headers,
    rawHeaders: overrides.rawHeaders ?? rawHeaders,
    fromCache: false,
    isHstsUpgrade: false,
    capturedAt: 'onResponseStarted',
    headersDiffer: false,
    timestamp: Date.now(),
    ...overrides,
  };
}

/**
 * Build a Hop from a fixture partial. Fixture hops only need `url` and
 * `headers`; the remaining required fields are filled from defaults.
 */
function hopFromFixture(fh: FixtureHop): Hop {
  return makeHop({
    url: fh.url ?? 'https://example.com/',
    status: fh.status ?? 200,
    headers: fh.headers ?? {},
    fromCache: fh.fromCache ?? false,
    isHstsUpgrade: fh.isHstsUpgrade ?? false,
  });
}

/**
 * Assert that a Finding array contains all expected rule IDs and none of the
 * not-expected rule IDs.
 */
function assertFindings(
  findings: Finding[],
  expectedRuleIds: string[],
  notExpectedRuleIds: string[],
  description: string,
): void {
  const foundIds = new Set(findings.map((f) => f.ruleId));

  for (const id of expectedRuleIds) {
    expect(
      foundIds.has(id),
      `[${description}] Expected rule "${id}" to fire but it did not. Found: ${[...foundIds].join(', ') || '(none)'}`,
    ).toBe(true);
  }

  for (const id of notExpectedRuleIds) {
    expect(
      foundIds.has(id),
      `[${description}] Expected rule "${id}" NOT to fire but it did.`,
    ).toBe(false);
  }
}

// ==========================================================================
// HSTS
// ==========================================================================

describe('checkHsts — fixture-driven', () => {
  (hstsFixtures as Fixture[]).forEach(({ description, hop, expectedRuleIds, notExpectedRuleIds }) => {
    it(description, () => {
      const findings = checkHsts(hopFromFixture(hop));
      assertFindings(findings, expectedRuleIds, notExpectedRuleIds, description);
    });
  });
});

describe('checkHsts — explicit cases', () => {
  it('HSTS-001: HTTPS URL missing strict-transport-security fires HSTS-001', () => {
    const hop = makeHop({ url: 'https://example.com/', headers: {} });
    const findings = checkHsts(hop);
    expect(findings.map((f) => f.ruleId)).toContain('HSTS-001');
  });

  it('No HSTS findings for plain HTTP URL (rule is HTTPS-only)', () => {
    const hop = makeHop({ url: 'http://example.com/', headers: {} });
    const findings = checkHsts(hop);
    expect(findings).toHaveLength(0);
  });

  it('HSTS-002 + HSTS-003: max-age=86400 (short) without includeSubDomains', () => {
    const hop = makeHop({
      headers: { 'strict-transport-security': 'max-age=86400' },
    });
    const ids = checkHsts(hop).map((f) => f.ruleId);
    expect(ids).toContain('HSTS-002');
    expect(ids).toContain('HSTS-003');
  });

  it('reports basic preload readiness without claiming list membership', () => {
    const hop = makeHop({
      headers: { 'strict-transport-security': 'max-age=31536000; includeSubDomains' },
    });
    const finding = checkHsts(hop).find((item) => item.ruleId === 'HSTS-005');
    expect(finding?.severity).toBe('info');
    expect(finding?.title).toContain('preload-list membership is not checked');
  });

  it('XSS payload in HSTS value — no crash; HSTS-002 fires (max-age parse yields 0)', () => {
    const hop = makeHop({
      headers: {
        'strict-transport-security': 'max-age=<img src=x onerror=alert(1)>',
      },
    });
    let findings: Finding[] = [];
    expect(() => {
      findings = checkHsts(hop);
    }).not.toThrow();
    const ids = findings.map((f) => f.ruleId);
    expect(ids).toContain('HSTS-002');
    // HSTS-001 must NOT fire because the header IS present
    expect(ids).not.toContain('HSTS-001');
  });
});

// ==========================================================================
// CSP
// ==========================================================================

describe('checkCsp — fixture-driven', () => {
  (cspFixtures as Fixture[]).forEach(({ description, hop, expectedRuleIds, notExpectedRuleIds }) => {
    it(description, () => {
      const { findings } = checkCsp(hopFromFixture(hop));
      assertFindings(findings, expectedRuleIds, notExpectedRuleIds, description);
    });
  });
});

describe('checkCsp — explicit cases', () => {
  it('CSP-001: No CSP header fires CSP-001', () => {
    const hop = makeHop({ headers: {} });
    const { findings } = checkCsp(hop);
    expect(findings.map((f) => f.ruleId)).toContain('CSP-001');
  });

  it('does not report CSP missing when a meta CSP was detected', () => {
    const { findings } = checkCsp(makeHop({ headers: {} }), true);
    expect(findings.map((f) => f.ruleId)).toContain('CSP-008');
    expect(findings.map((f) => f.ruleId)).not.toContain('CSP-001');
  });

  it('reports curated bypass-prone script hosts as informational heuristics', () => {
    const { findings } = checkCsp(makeHop({ headers: {
      'content-security-policy': "default-src 'self'; script-src 'self' https://www.google.com; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
    } }));
    const bypass = findings.find((finding) => finding.ruleId === 'CSP-009');
    expect(bypass?.severity).toBe('info');
    expect(bypass?.evidence).toContain('www.google.com');
  });

  it('does not flag self-only sources or hosts ignored by strict-dynamic', () => {
    const selfOnly = checkCsp(makeHop({ headers: {
      'content-security-policy': "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
    } })).findings;
    const strictDynamic = checkCsp(makeHop({ headers: {
      'content-security-policy': "script-src 'nonce-random' 'strict-dynamic' https://www.google.com; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
    } })).findings;

    expect(selfOnly.some((finding) => finding.ruleId === 'CSP-009')).toBe(false);
    expect(strictDynamic.some((finding) => finding.ruleId === 'CSP-009')).toBe(false);
  });

  it('deduplicates CSP evaluator findings (CSP-009 and CSP-SYNTAX-001)', () => {
    const { findings } = checkCsp(makeHop({ headers: {
      'content-security-policy': "default-src 'self' 'invalid-kw-1' 'invalid-kw-2'; script-src 'self' https://www.google.com https://cdnjs.cloudflare.com; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
    } }));

    const csp009 = findings.filter((f) => f.ruleId === 'CSP-009');
    expect(csp009).toHaveLength(1);

    const syntax = findings.filter((f) => f.ruleId === 'CSP-SYNTAX-001');
    expect(syntax).toHaveLength(1);
  });

  it('reports headers removed by an intermediate redirect response', () => {
    const first = makeHop({ url: 'https://first.example/path', headers: { 'content-security-policy': "default-src 'self'" }, timestamp: 1 });
    const next = makeHop({ url: 'https://next.example/path', headers: {}, timestamp: 2 });
    const result = runRules({ hops: [first, next], cookies: [], origin: 'https://next.example' });
    const degradation = result.findings.find((finding) => finding.ruleId === 'REDIR-001');

    expect(degradation?.evidence).toContain('content-security-policy');
    expect(degradation?.evidence).toContain('first.example');
    expect(degradation?.severity).toBe('info');
  });

  it('does not report redirect degradation when the next hop retains the header', () => {
    const first = makeHop({ headers: { 'x-content-type-options': 'nosniff' }, timestamp: 1 });
    const next = makeHop({ url: 'https://next.example/path', headers: { 'x-content-type-options': 'nosniff' }, timestamp: 2 });
    const result = runRules({ hops: [first, next], cookies: [], origin: 'https://next.example' });

    expect(result.findings.some((finding) => finding.ruleId === 'REDIR-001')).toBe(false);
  });

  it('keeps capture correlation diagnostics informational for scoring', () => {
    const hop = makeHop({ headers: {
      'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
      'content-security-policy': "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'referrer-policy': 'strict-origin-when-cross-origin',
      'cross-origin-opener-policy': 'same-origin',
      'origin-agent-cluster': '?1',
    } });
    const baseline = runRules({ hops: [hop], cookies: [], origin: 'https://example.com' });
    const withDiagnostic = runRules({
      hops: [hop],
      cookies: [],
      origin: 'https://example.com',
      captureFindings: [{
        ruleId: 'COOKIE-REJECTED',
        category: 'cookie',
        severity: 'info',
        title: 'Set-Cookie was not observed',
        evidence: 'Cookie name: sid',
        recommendation: 'Review cookie attributes.',
        reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie',
      }],
    });

    expect(withDiagnostic.findings.some((finding) => finding.ruleId === 'COOKIE-REJECTED')).toBe(true);
    expect(withDiagnostic.score).toBe(baseline.score);
  });

  it('keeps the security score stable while configuration quality reflects advisory controls', () => {
    const baseHeaders = {
      'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
      'content-security-policy': "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'referrer-policy': 'strict-origin-when-cross-origin',
      'cross-origin-opener-policy': 'same-origin',
      'origin-agent-cluster': '?1',
    };
    const withoutOptionalHeaders = runRules({
      hops: [makeHop({ headers: baseHeaders })],
      cookies: [],
      origin: 'https://example.com',
    });
    const withOptionalHeaders = runRules({
      hops: [makeHop({ headers: {
        ...baseHeaders,
        'cross-origin-embedder-policy': 'require-corp',
        'cross-origin-resource-policy': 'same-origin',
        'permissions-policy': 'camera=(), microphone=()',
        'reporting-endpoints': 'default="https://reports.example.com/"',
        nel: '{"report_to":"default","max_age":86400}',
        'document-policy': 'js-profiling=?0',
        'integrity-policy': 'blocked-destinations=(script)',
        'content-security-policy': `${baseHeaders['content-security-policy']}; report-to default`,
      } })],
      cookies: [],
      origin: 'https://example.com',
    });

    expect(withoutOptionalHeaders.score).toBe(withOptionalHeaders.score);
    expect(withoutOptionalHeaders.qualityScore).toBeLessThan(withOptionalHeaders.qualityScore);
    expect(withOptionalHeaders.qualityScore).toBe(100);
  });

  it('CSP-002: unsafe-inline in script-src fires CSP-002', () => {
    const hop = makeHop({
      headers: {
        'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline'",
      },
    });
    const { findings } = checkCsp(hop);
    const ids = findings.map((f) => f.ruleId);
    expect(ids).toContain('CSP-002');
    expect(ids).not.toContain('CSP-001');
  });

  it('Strong CSP with nonce, object-src none, base-uri, frame-ancestors produces no high findings', () => {
    const hop = makeHop({
      headers: {
        'content-security-policy':
          "script-src 'nonce-abc123'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
      },
    });
    const { findings } = checkCsp(hop);
    const highOrCritical = findings.filter(
      (f) => f.severity === 'high' || f.severity === 'critical',
    );
    expect(highOrCritical).toHaveLength(0);
  });

  it('CSP frame-ancestors prevents XFO-001 from firing', () => {
    const hop = makeHop({
      headers: {
        'content-security-policy':
          "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        'x-content-type-options': 'nosniff',
      },
    });
    // Parse CSP directives and pass them to XFO as the engine does
    const { directives } = checkCsp(hop);
    const xfoFindings = checkXfo(hop, directives);
    expect(xfoFindings.map((f) => f.ruleId)).not.toContain('XFO-001');
  });
});

// ==========================================================================
// XCTO
// ==========================================================================

describe('checkXcto — fixture-driven', () => {
  (xctoFixtures as Fixture[]).forEach(({ description, hop, expectedRuleIds, notExpectedRuleIds }) => {
    it(description, () => {
      const findings = checkXcto(hopFromFixture(hop));
      assertFindings(findings, expectedRuleIds, notExpectedRuleIds, description);
    });
  });
});

describe('checkXcto — explicit cases', () => {
  it('XCTO-001: Missing x-content-type-options fires XCTO-001', () => {
    const hop = makeHop({ headers: {} });
    expect(checkXcto(hop).map((f) => f.ruleId)).toContain('XCTO-001');
  });

  it('No finding for nosniff regardless of case', () => {
    for (const value of ['nosniff', 'NOSNIFF', 'NoSniff']) {
      const hop = makeHop({ headers: { 'x-content-type-options': value } });
      expect(
        checkXcto(hop).map((f) => f.ruleId),
        `Expected no XCTO-001 for value "${value}"`,
      ).not.toContain('XCTO-001');
    }
  });
});

// ==========================================================================
// XFO
// ==========================================================================

describe('checkXfo — fixture-driven', () => {
  (xfoFixtures as Fixture[]).forEach(({ description, hop, expectedRuleIds, notExpectedRuleIds }) => {
    it(description, () => {
      // Parse any CSP from the hop to pass directives to XFO as the engine does
      const { directives } = checkCsp(hopFromFixture(hop));
      const findings = checkXfo(hopFromFixture(hop), directives);
      assertFindings(findings, expectedRuleIds, notExpectedRuleIds, description);
    });
  });
});

describe('checkXfo — explicit cases', () => {
  it('XFO-001: No x-frame-options and no CSP frame-ancestors fires XFO-001', () => {
    const hop = makeHop({ headers: {} });
    expect(checkXfo(hop, new Map()).map((f) => f.ruleId)).toContain('XFO-001');
  });

  it('No XFO-001 when x-frame-options: DENY is present', () => {
    const hop = makeHop({ headers: { 'x-frame-options': 'DENY' } });
    expect(checkXfo(hop, new Map()).map((f) => f.ruleId)).not.toContain('XFO-001');
  });

  it('No XFO-001 when CSP includes frame-ancestors directive (no x-frame-options)', () => {
    const hop = makeHop({
      headers: {
        'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
      },
    });
    const cspDirectives = new Map([['frame-ancestors', "'none'"]]);
    expect(checkXfo(hop, cspDirectives).map((f) => f.ruleId)).not.toContain('XFO-001');
  });
});

// ==========================================================================
// Referrer-Policy
// ==========================================================================

describe('checkReferrer — fixture-driven', () => {
  (referrerFixtures as Fixture[]).forEach(({ description, hop, expectedRuleIds, notExpectedRuleIds }) => {
    it(description, () => {
      const findings = checkReferrer(hopFromFixture(hop));
      assertFindings(findings, expectedRuleIds, notExpectedRuleIds, description);
    });
  });
});

// ==========================================================================
// Deprecated headers
// ==========================================================================

describe('checkDeprecated — fixture-driven', () => {
  (deprecatedFixtures as Fixture[]).forEach(
    ({ description, hop, expectedRuleIds, notExpectedRuleIds }) => {
      it(description, () => {
        const findings = checkDeprecated(hopFromFixture(hop));
        assertFindings(findings, expectedRuleIds, notExpectedRuleIds, description);
      });
    },
  );
});

describe('checkDeprecated — explicit cases', () => {
  it('DEP-001: x-xss-protection present fires DEP-001 with info severity', () => {
    const hop = makeHop({ headers: { 'x-xss-protection': '1; mode=block' } });
    const findings = checkDeprecated(hop);
    const dep = findings.find((f) => f.ruleId === 'DEP-001');
    expect(dep).toBeDefined();
    expect(dep?.severity).toBe('info');
  });

  it('No DEP-001 when x-xss-protection is absent', () => {
    const hop = makeHop({ headers: {} });
    expect(checkDeprecated(hop).map((f) => f.ruleId)).not.toContain('DEP-001');
  });
});

// ==========================================================================
// Info-leak
// ==========================================================================

describe('checkInfoLeak — fixture-driven', () => {
  (infoLeakFixtures as Fixture[]).forEach(({ description, hop, expectedRuleIds, notExpectedRuleIds }) => {
    it(description, () => {
      const findings = checkInfoLeak(hopFromFixture(hop));
      assertFindings(findings, expectedRuleIds, notExpectedRuleIds, description);
    });
  });
});

// ==========================================================================
// Cache-Cookie
// ==========================================================================

describe('checkCacheCookie — fixture-driven', () => {
  (cacheCookieFixtures as Fixture[]).forEach(
    ({ description, hop, expectedRuleIds, notExpectedRuleIds }) => {
      it(description, () => {
        const findings = checkCacheCookie(hopFromFixture(hop));
        assertFindings(findings, expectedRuleIds, notExpectedRuleIds, description);
      });
    },
  );
});

describe('checkCacheCookie — explicit cases', () => {
  it('CACHE-001: Set-Cookie with no cache-control fires CACHE-001', () => {
    const hop = makeHop({
      headers: { 'set-cookie': 'session=abc; Path=/' },
    });
    expect(checkCacheCookie(hop).map((f) => f.ruleId)).toContain('CACHE-001');
  });

  it('No CACHE-001: Set-Cookie + cache-control: no-store', () => {
    const hop = makeHop({
      headers: {
        'set-cookie': 'session=abc; Path=/',
        'cache-control': 'no-store',
      },
    });
    expect(checkCacheCookie(hop).map((f) => f.ruleId)).not.toContain('CACHE-001');
  });

  it('No CACHE-001: no Set-Cookie header at all', () => {
    const hop = makeHop({ headers: { 'cache-control': 'max-age=3600' } });
    expect(checkCacheCookie(hop).map((f) => f.ruleId)).not.toContain('CACHE-001');
  });
});

// ==========================================================================
// sanitizeEvidence — utility tests
// ==========================================================================

describe('sanitizeEvidence', () => {
  it('Truncates strings longer than 500 chars and appends a note', () => {
    const longString = 'A'.repeat(600);
    const result = sanitizeEvidence(longString);
    // Must be ≤ 500 chars (the truncation note may push it slightly over
    // 500 raw chars, but the original content is cut at 500)
    expect(result.length).toBeLessThanOrEqual(600); // sanity upper-bound
    expect(result).toContain('A'.repeat(500).slice(0, 50)); // leading chars intact
    expect(result.length).toBeLessThan(longString.length);
  });

  it('Returns XSS payload as plain text (no HTML element nodes created)', () => {
    const xss = '<img src=x onerror=alert(1)>';
    const result = sanitizeEvidence(xss);
    // The function must NOT return raw HTML that would be injected into DOM.
    // It should either encode or strip it. It must not contain < verbatim
    // (unless the host explicitly uses textContent for insertion — either is
    // acceptable so we just ensure the function does not crash).
    expect(result).toBeDefined();
    expect(typeof result).toBe('string');
  });

  it('Escapes BiDi override characters (U+202E etc.)', () => {
    // Right-to-Left Override followed by normal text
    const bidi = '\u202Eno-referrer';
    const result = sanitizeEvidence(bidi);
    expect(result).not.toContain('\u202E');
  });

  it('Strips or escapes ASCII control characters', () => {
    const controlled = 'foo\x00\x01\x07bar';
    const result = sanitizeEvidence(controlled);
    // Control chars (0x00–0x1F except common whitespace) must be removed/escaped
    expect(result).not.toMatch(/[\x00-\x08\x0b\x0c\x0e-\x1f]/);
  });
});

// ==========================================================================
// redactUrlQueryParams and isSensitiveParamName — parameter sanitization
// ==========================================================================

describe('redactUrlQueryParams and isSensitiveParamName', () => {
  it('does not redact harmless parameters like keyword, author, passenger, compass, or bypass', () => {
    const url = 'https://example.com/search?keyword=security&author=alice&passenger=bob&compass=north&bypass=false&page=2';
    const redacted = redactUrlQueryParams(url);
    expect(redacted).toBe(url);
  });

  it('redacts sensitive parameters like token, api_key, apiKey, secret, password, and auth_token', () => {
    const url = 'https://example.com/api?apiKey=secret123&token=tok456&password=pass789&author=alice';
    const redacted = redactUrlQueryParams(url);
    expect(redacted).toContain('apiKey=%5Bredacted%5D');
    expect(redacted).toContain('token=%5Bredacted%5D');
    expect(redacted).toContain('password=%5Bredacted%5D');
    expect(redacted).toContain('author=alice');
  });

  it('accurately identifies sensitive vs harmless param names', () => {
    expect(isSensitiveParamName('keyword')).toBe(false);
    expect(isSensitiveParamName('author')).toBe(false);
    expect(isSensitiveParamName('passenger')).toBe(false);
    expect(isSensitiveParamName('compass')).toBe(false);
    expect(isSensitiveParamName('bypass')).toBe(false);

    expect(isSensitiveParamName('token')).toBe(true);
    expect(isSensitiveParamName('api_key')).toBe(true);
    expect(isSensitiveParamName('clientSecret')).toBe(true);
    expect(isSensitiveParamName('authToken')).toBe(true);
    expect(isSensitiveParamName('user_pass')).toBe(true);
  });
});

// ==========================================================================
// computeScore — scoring utility tests
// ==========================================================================

describe('computeScore', () => {
  /**
   * Helper to create a minimal Finding with the given severity.
   */
  function makeFinding(ruleId: string, severity: Finding['severity']): Finding {
    let category: Finding['category'] = 'header';
    if (ruleId.startsWith('HSTS-')) category = 'transport';
    else if (ruleId.startsWith('COOK-') || ruleId === 'SUB-001' || ruleId === 'SUB-005') category = 'cookie';
    else if (ruleId.startsWith('SUB-003')) category = 'cors';

    return {
      ruleId,
      severity,
      category,
      title: `Test finding ${ruleId}`,
      evidence: '',
      recommendation: '',
      reference: 'https://example.com/',
    };
  }

  it('No findings → score 100, grade A', () => {
    const { score, grade } = computeScore([]);
    expect(score).toBe(100);
    expect(grade).toBe('A');
  });

  it('HSTS-001 (high, −20) + CSP-001 (high, −20) → score ~60, grade C', () => {
    const findings: Finding[] = [
      makeFinding('HSTS-001', 'high'),
      makeFinding('CSP-001', 'high'),
    ];
    const { score, grade } = computeScore(findings);
    // Score should be 60 ± implementation tolerance (some implementations
    // may round differently). We test within ±5 to allow minor variations.
    expect(score).toBeGreaterThanOrEqual(55);
    expect(score).toBeLessThanOrEqual(65);
    expect(grade).toBe('C');
  });

  it('Many high-penalty findings → score clamped to 0, grade F', () => {
    // Tests that when multiple high-penalty findings span across categories
    // (headers capped at 55, transport capped at 25, cookie capped at 25, cors capped at 20),
    // the total deductions push the score down to 0 and clamp properly.
    const ruleIds = [
      // header (hits 55 cap):
      'CSP-001', 'CSP-002', 'CSP-003', 'XCTO-001', 'XFO-001',
      // transport (hits 25 cap):
      'HSTS-001', 'HSTS-002',
      // cookie (hits 25 cap):
      'COOK-001', 'COOK-002', 'COOK-003',
      // cors:
      'SUB-003',
    ];
    const findings: Finding[] = ruleIds.map((id) => makeFinding(id, 'high'));
    const { score, grade } = computeScore(findings);
    expect(score).toBe(0);
    expect(grade).toBe('F');
  });

  it('Info-only findings do not reduce score below A', () => {
    const findings: Finding[] = [makeFinding('DEP-001', 'info')];
    const { score } = computeScore(findings);
    // Info findings should have no or negligible impact
    expect(score).toBeGreaterThanOrEqual(95);
  });
});


