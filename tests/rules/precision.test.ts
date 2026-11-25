import { describe, it, expect } from 'vitest';
import { checkCors } from '../../src/rules/headers/cors';
import { checkCookies } from '../../src/rules/cookies/cookies';
import { checkCacheCookie } from '../../src/rules/headers/cache-cookie';
import { checkCsp } from '../../src/rules/headers/csp';
import { runRules, runApiRules } from '../../src/rules/engine';
import { detectAuthLeads } from '../../src/leads/detectors/f4-auth';
import { verifyLeadPassive } from '../../src/leads/verify';
import { ScopeEngine } from '../../src/shared/scope/engine';
import type { Hop, CookieRecord, ApiHop } from '../../src/shared/types';
import type { ScopeProfile } from '../../src/shared/scope/contracts';

function makeHop(headers: Record<string, string>, overrides: Partial<Hop> = {}): Hop {
  return {
    requestId: 'test-req',
    url: 'https://example.com/api/user',
    status: 200,
    headers,
    rawHeaders: Object.entries(headers).map(([name, value]) => ({ name, value })),
    fromCache: false,
    isHstsUpgrade: false,
    capturedAt: 'onResponseStarted',
    headersDiffer: false,
    timestamp: Date.now(),
    redirectCount: 0,
    ...overrides,
  };
}

describe('Bounded Rule Precision Audit', () => {
  describe('CORS Precision & Known-Safe Configurations', () => {
    it('does NOT flag same-origin reflection as a vulnerability', () => {
      const apiHop: ApiHop = {
        ...makeHop({
          'access-control-allow-origin': 'https://example.com',
          'access-control-allow-credentials': 'true',
          'content-type': 'application/json',
        }),
        tabId: 1,
        normalizedPath: 'https://example.com/api/user',
        method: 'GET',
        requestOrigin: 'https://example.com', // same origin!
      };

      const findings = checkCors(apiHop);
      expect(findings).toHaveLength(0);
    });

    it('flags cross-origin reflection as heuristic CORS-001 with limitations', () => {
      const apiHop: ApiHop = {
        ...makeHop({
          'access-control-allow-origin': 'https://evil.com',
          'access-control-allow-credentials': 'true',
          'content-type': 'application/json',
        }),
        tabId: 1,
        normalizedPath: 'https://example.com/api/user',
        method: 'GET',
        requestOrigin: 'https://evil.com',
      };

      const findings = checkCors(apiHop);
      expect(findings).toHaveLength(1);
      const f = findings[0];
      expect(f).toBeDefined();
      if (f !== undefined) {
        expect(f.ruleId).toBe('CORS-001');
        expect(f.confidence).toBe('heuristic');
        expect(f.provenance).toBe('response-header');
        expect(f.limitations).toBeDefined();
        expect(f.limitations?.[0]).toContain('Passive observation');
      }
    });
  });

  describe('Cookie Prefix & Boundary Precision', () => {
    it('accepts compliant __Host- cookie with Secure, Path=/, and no Domain attribute', () => {
      const cookie: CookieRecord = {
        name: '__Host-session',
        domain: 'example.com',
        domainAttributePresent: false,
        path: '/',
        secure: true,
        httpOnly: true,
        sameSite: 'strict',
        session: true,
        expiresAt: null,
        partitioned: false,
        setByJs: false,
        isThirdParty: false,
      };

      const findings = checkCookies([cookie], true);
      expect(findings).toHaveLength(0);
    });

    it('annotates __Host- violation with deterministic confidence and limitations', () => {
      const cookie: CookieRecord = {
        name: '__Host-session',
        domain: 'example.com',
        domainAttributePresent: true, // violation!
        path: '/app',                  // violation!
        secure: false,                 // violation!
        httpOnly: true,
        sameSite: 'lax',
        session: true,
        expiresAt: null,
        partitioned: false,
        setByJs: false,
        isThirdParty: false,
      };

      const findings = checkCookies([cookie], true);
      const hostFinding = findings.find((f) => f.ruleId === 'COOK-005');
      expect(hostFinding).toBeDefined();
      if (hostFinding !== undefined) {
        expect(hostFinding.confidence).toBe('deterministic');
        expect(hostFinding.provenance).toBe('cookie-metadata');
        expect(hostFinding.limitations).toBeDefined();
      }
    });
  });

  describe('Cache & Ambiguous Context Non-Penalization', () => {
    it('emits partial-coverage on cached response with missing headers', () => {
      const cachedHop = makeHop({}, { fromCache: true });
      const output = runRules({
        hops: [cachedHop],
        cookies: [],
        origin: 'https://example.com',
      });

      const cspFinding = output.findings.find((f) => f.ruleId === 'CSP-001');
      expect(cspFinding).toBeDefined();
      if (cspFinding !== undefined) {
        expect(cspFinding.outcome).toBe('partial-coverage');
        expect(cspFinding.limitations).toBeDefined();
        expect(cspFinding.limitations?.[0]).toContain('browser cache');
      }

      // partial-coverage must not penalize the score
      expect(output.score).toBe(100);
      expect(output.grade).toBe('A');
    });

    it('exempts non-sensitive cookies from Cache-Control: no-store requirement', () => {
      const hop = makeHop(
        { 'cache-control': 'public, max-age=86400' },
        {
          rawHeaders: [{ name: 'Set-Cookie', value: 'theme=dark; Path=/' }],
        },
      );
      const findings = checkCacheCookie(hop);
      expect(findings).toHaveLength(0);
    });
  });

  describe('CSP Bypass Host Caveats', () => {
    it('provides honest caveats and informational outcome on bypass-prone hosts', () => {
      const hop = makeHop({
        'content-security-policy': "script-src 'self' https://cdnjs.cloudflare.com",
      });
      const { findings } = checkCsp(hop);
      const bypassFinding = findings.find((f) => f.ruleId === 'CSP-009');
      expect(bypassFinding).toBeDefined();
      if (bypassFinding !== undefined) {
        expect(bypassFinding.severity).toBe('info');
        expect(bypassFinding.confidence).toBe('heuristic');
        expect(bypassFinding.limitations?.[0]).toContain('Passive heuristic analysis only');
      }
    });
  });

  describe('ScopeEngine Integration in Engine', () => {
    const profile: ScopeProfile = {
      id: 'test-profile',
      name: 'Scope Precision Profile',
      rules: [
        { pattern: 'admin.example.com', type: 'exclude' },
        { pattern: '*.example.com', type: 'include' },
        { pattern: 'example.com', type: 'include' },
      ],
    };

    it('populates scopeStatus on runRules findings when ScopeEngine is provided', () => {
      const hop = makeHop({}, { url: 'https://example.com/' });
      const engine = new ScopeEngine(profile);
      const output = runRules({
        hops: [hop],
        cookies: [],
        origin: 'https://example.com',
        scopeEngine: engine,
      });

      expect(output.findings.length).toBeGreaterThan(0);
      for (const finding of output.findings) {
        expect(finding.scopeStatus).toBe('in-scope');
      }
    });

    it('classifies excluded targets as out-of-scope in runRules', () => {
      const hop = makeHop({}, { url: 'https://admin.example.com/' });
      const engine = new ScopeEngine(profile);
      const output = runRules({
        hops: [hop],
        cookies: [],
        origin: 'https://admin.example.com',
        scopeEngine: engine,
      });

      expect(output.findings.length).toBeGreaterThan(0);
      for (const finding of output.findings) {
        expect(finding.scopeStatus).toBe('out-of-scope');
      }
    });

    it('populates scopeStatus on runApiRules findings when ScopeEngine is provided', () => {
      const apiHop: ApiHop = {
        ...makeHop({
          'access-control-allow-origin': '*',
          'content-type': 'application/json',
        }),
        tabId: 1,
        normalizedPath: 'https://api.external.com/data',
        method: 'GET',
        url: 'https://api.external.com/data',
      };
      const engine = new ScopeEngine(profile);
      const findings = runApiRules(apiHop, { scopeEngine: engine });

      expect(findings.length).toBeGreaterThan(0);
      for (const finding of findings) {
        expect(finding.scopeStatus).toBe('unknown');
      }
    });
  });

  describe('CSP Nonce/Hash vs Strict-Dynamic Broad-Source Precision', () => {
    it('flags CSP-004 when nonce is combined with https: scheme without strict-dynamic', () => {
      const hop = makeHop({
        'content-security-policy': "script-src 'nonce-abc123' https:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
      });
      const { findings } = checkCsp(hop);
      const csp004 = findings.find((f) => f.ruleId === 'CSP-004');
      expect(csp004).toBeDefined();
      expect(csp004?.severity).toBe('medium');
      expect(csp004?.evidence).toContain('https:');
    });

    it('flags CSP-004 when hash is combined with * wildcard without strict-dynamic', () => {
      const hop = makeHop({
        'content-security-policy': "script-src 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=' *; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
      });
      const { findings } = checkCsp(hop);
      const csp004 = findings.find((f) => f.ruleId === 'CSP-004');
      expect(csp004).toBeDefined();
      expect(csp004?.severity).toBe('medium');
      expect(csp004?.evidence).toContain('*');
    });

    it('suppresses CSP-004 when strict-dynamic is present alongside host/scheme sources', () => {
      const hop = makeHop({
        'content-security-policy': "script-src 'nonce-abc123' 'strict-dynamic' https:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
      });
      const { findings } = checkCsp(hop);
      const csp004 = findings.find((f) => f.ruleId === 'CSP-004');
      expect(csp004).toBeUndefined();
    });
  });

  describe('P2 Heuristic Calibration & Observed-Configuration Wording', () => {
    it('calibrates CSP-002 and CSP-003 as medium observed-configuration findings with non-conclusive caveats', () => {
      const hop = makeHop({
        'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
      });
      const { findings } = checkCsp(hop);

      const csp002 = findings.find((f) => f.ruleId === 'CSP-002');
      const csp003 = findings.find((f) => f.ruleId === 'CSP-003');
      expect(csp002?.severity).toBe('medium');
      expect(csp002?.impact).toContain('Observed configuration');
      expect(csp002?.limitations?.[0]).toContain('does not prove');

      expect(csp003?.severity).toBe('medium');
      expect(csp003?.confidence).toBe('heuristic');
      expect(csp003?.impact).toContain('Observed configuration');
      expect(csp003?.limitations?.[0]).toContain('does not prove');
    });

    it('treats unsafe-inline paired with legitimate 128-bit+ nonce/hash as info pass negative fixture', () => {
      const hop = makeHop({
        'content-security-policy': "script-src 'nonce-abcdefghijklmnop1234' 'unsafe-inline' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
      });
      const { findings } = checkCsp(hop);
      const csp002 = findings.find((f) => f.ruleId === 'CSP-002');
      expect(csp002?.severity).toBe('info');
      expect(csp002?.outcome).toBe('pass');
    });

    it('keeps optional hardening headers (DOC/INTEGRITY/COEP/CORP) out of penalized score and at info severity', () => {
      const hop = makeHop({
        'strict-transport-security': 'max-age=31536000; includeSubDomains',
        'content-security-policy': "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        'x-content-type-options': 'nosniff',
        'x-frame-options': 'DENY',
        'referrer-policy': 'strict-origin-when-cross-origin',
        'cache-control': 'no-store',
        'cross-origin-opener-policy': 'same-origin',
        'origin-agent-cluster': '?1',
      });
      const output = runRules({
        hops: [hop],
        cookies: [],
        origin: 'https://example.com',
      });

      const actionable = output.findings.filter(
        (f) => f.severity !== 'info' && f.severity !== 'pass' && f.outcome !== 'pass',
      );
      const hardeningInfo = output.findings.filter((f) => f.severity === 'info');

      expect(actionable).toHaveLength(0);
      expect(hardeningInfo.length).toBeGreaterThan(0);
      expect(output.score).toBe(100);
      expect(output.grade).toBe('A');
    });

    it('keeps absent anti-CSRF markup (AUTH-002) as weak unconfirmed heuristic and avoids false positive on GET/tokenized forms', () => {
      const postNoToken = detectAuthLeads({
        url: 'https://example.com/settings',
        forms: [{ action: '/settings/update', method: 'POST', inputs: [{ name: 'theme', type: 'text' }] }],
      }, 'in-scope');
      const csrfLead = postNoToken.find((l) => l.ruleId === 'AUTH-002');
      expect(csrfLead).toBeDefined();
      expect(csrfLead?.tier).toBe('weak');
      expect(csrfLead?.doesNotProve.join(' ')).toContain('SameSite');

      if (csrfLead) {
        const verdict = verifyLeadPassive(csrfLead);
        expect(verdict.securityAssessment).toBe('unreviewed');
        expect(verdict.status).toBe('uncertain');
      }

      // Negative fixtures: GET search form and POST form with hidden CSRF token
      const cleanForms = detectAuthLeads({
        url: 'https://example.com/search',
        forms: [
          { action: '/search', method: 'GET', inputs: [{ name: 'q', type: 'text' }] },
          { action: '/submit', method: 'POST', inputs: [{ name: 'csrf_token', type: 'hidden' }] },
        ],
      }, 'in-scope');
      expect(cleanForms.filter((l) => l.ruleId === 'AUTH-002')).toHaveLength(0);
    });
  });
});
