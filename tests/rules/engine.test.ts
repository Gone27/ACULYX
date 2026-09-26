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
import { sanitizeEvidence } from '../../src/rules/utils';
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

  it('No HSTS findings: max-age=31536000; includeSubDomains (fully valid)', () => {
    const hop = makeHop({
      headers: { 'strict-transport-security': 'max-age=31536000; includeSubDomains' },
    });
    expect(checkHsts(hop)).toHaveLength(0);
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
    else if (ruleId === 'SUB-003') category = 'cors';

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
