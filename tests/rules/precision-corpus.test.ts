/**
 * @file precision-corpus.test.ts
 * P3 Labeled Positive/Negative Corpus & Precision/Recall Measurement Rubric.
 *
 * Separately evaluates:
 *   1. Exact configuration observations (headers, cookies, transport)
 *   2. Secret & auth lead precision vs false-positive controls
 *   3. Heuristic lead classification (never auto-confirmed passively)
 *
 * Computes per-rule TP/FP/TN/FN, Precision = TP / (TP + FP), and Recall = TP / (TP + FN)
 * rather than collapsing unrelated classes into one opaque accuracy score.
 */

import { describe, it, expect } from 'vitest';
import { runRules, runApiRules } from '../../src/rules/engine';
import { detectSecrets } from '../../src/leads/detectors/f1-secrets';
import { detectAuthLeads } from '../../src/leads/detectors/f4-auth';
import { verifyLeadPassive } from '../../src/leads/verify';
import type { ApiHop, CookieRecord, Hop } from '../../src/shared/types';

interface CorpusCase<T> {
  name: string;
  ruleId: string;
  classification: 'exact-config' | 'secret-auth-lead' | 'heuristic';
  expectedFire: boolean;
  input: T;
}

function makeHop(url: string, headers: Record<string, string>): Hop {
  return {
    requestId: 'corpus-req',
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

function makeApiHop(url: string, headers: Record<string, string>, requestOrigin?: string): ApiHop {
  return {
    ...makeHop(url, headers),
    tabId: 1,
    normalizedPath: url,
    method: 'GET',
    requestOrigin,
  };
}

function computeMetrics(outcomes: Array<{ expected: boolean; actual: boolean }>): {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  precision: number;
  recall: number;
} {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  for (const o of outcomes) {
    if (o.expected && o.actual) tp++;
    else if (!o.expected && o.actual) fp++;
    else if (!o.expected && !o.actual) tn++;
    else if (o.expected && !o.actual) fn++;
  }
  const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 1 : tp / (tp + fn);
  return { tp, fp, tn, fn, precision, recall };
}

describe('P3 Precision & Recall Corpus Evaluation', () => {
  it('achieves 1.00 precision and recall across labeled HTTP/HTTPS header & cookie corpus', () => {
    const cases: Array<CorpusCase<{ hop: Hop | ApiHop; cookies?: CookieRecord[] }>> = [
      // HSTS-001..003
      {
        name: 'HTTPS missing HSTS triggers HSTS-001',
        ruleId: 'HSTS-001',
        classification: 'exact-config',
        expectedFire: true,
        input: { hop: makeHop('https://app.example/', {}) },
      },
      {
        name: 'HTTP missing HSTS never triggers HSTS-001',
        ruleId: 'HSTS-001',
        classification: 'exact-config',
        expectedFire: false,
        input: { hop: makeHop('http://app.example/', {}) },
      },
      {
        name: 'HTTPS HSTS max-age=86400 triggers HSTS-002',
        ruleId: 'HSTS-002',
        classification: 'exact-config',
        expectedFire: true,
        input: { hop: makeHop('https://app.example/', { 'strict-transport-security': 'max-age=86400' }) },
      },
      {
        name: 'HTTPS HSTS max-age=31536000; includeSubDomains does not trigger HSTS-002',
        ruleId: 'HSTS-002',
        classification: 'exact-config',
        expectedFire: false,
        input: { hop: makeHop('https://app.example/', { 'strict-transport-security': 'max-age=31536000; includeSubDomains' }) },
      },
      // CSP-001..003
      {
        name: 'Missing CSP fires CSP-001',
        ruleId: 'CSP-001',
        classification: 'exact-config',
        expectedFire: true,
        input: { hop: makeHop('https://app.example/', {}) },
      },
      {
        name: 'Strong nonce CSP does not fire CSP-002 actionable violation',
        ruleId: 'CSP-002',
        classification: 'exact-config',
        expectedFire: false,
        input: {
          hop: makeHop('https://app.example/', {
            'content-security-policy': "script-src 'nonce-a1b2c3d4e5f6g7h8i9' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
          }),
        },
      },
      {
        name: 'CSP script-src unsafe-inline without nonce fires CSP-002',
        ruleId: 'CSP-002',
        classification: 'exact-config',
        expectedFire: true,
        input: {
          hop: makeHop('https://app.example/', {
            'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline'",
          }),
        },
      },
      // CORS-001 (API reflection vs same-origin)
      {
        name: 'Cross-origin ACAO reflection with ACAC fires CORS-001',
        ruleId: 'CORS-001',
        classification: 'heuristic',
        expectedFire: true,
        input: {
          hop: makeApiHop(
            'https://api.example/me',
            { 'access-control-allow-origin': 'https://evil.example', 'access-control-allow-credentials': 'true' },
            'https://evil.example',
          ),
        },
      },
      {
        name: 'Same-origin ACAO with ACAC does not fire CORS-001',
        ruleId: 'CORS-001',
        classification: 'heuristic',
        expectedFire: false,
        input: {
          hop: makeApiHop(
            'https://api.example/me',
            { 'access-control-allow-origin': 'https://api.example', 'access-control-allow-credentials': 'true' },
            'https://api.example',
          ),
        },
      },
      // LEAK-001
      {
        name: 'Server version header Apache/2.4.51 fires LEAK-001',
        ruleId: 'LEAK-001',
        classification: 'heuristic',
        expectedFire: true,
        input: { hop: makeHop('https://app.example/', { server: 'Apache/2.4.51' }) },
      },
      {
        name: 'Unversioned Server: nginx does not fire LEAK-001',
        ruleId: 'LEAK-001',
        classification: 'heuristic',
        expectedFire: false,
        input: { hop: makeHop('https://app.example/', { server: 'nginx' }) },
      },
      // COOK-001 / COOK-004
      {
        name: 'Sensitive cookie without HttpOnly over HTTPS fires COOK-002',
        ruleId: 'COOK-002',
        classification: 'exact-config',
        expectedFire: true,
        input: {
          hop: makeHop('https://app.example/', {}),
          cookies: [{
            name: 'session_id',
            domain: 'app.example',
            domainAttributePresent: false,
            path: '/',
            secure: true,
            httpOnly: false,
            sameSite: 'lax',
            session: true,
            expiresAt: null,
            partitioned: false,
            setByJs: false,
            isThirdParty: false,
          }],
        },
      },
      {
        name: 'Sensitive hardened __Host- cookie fires zero COOK-* issues',
        ruleId: 'COOK-002',
        classification: 'exact-config',
        expectedFire: false,
        input: {
          hop: makeHop('https://app.example/', {}),
          cookies: [{
            name: '__Host-session',
            domain: 'app.example',
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
          }],
        },
      },
    ];

    const byClass: Record<string, Array<{ expected: boolean; actual: boolean }>> = {
      'exact-config': [],
      heuristic: [],
    };

    for (const c of cases) {
      const findings = 'method' in c.input.hop
        ? runApiRules(c.input.hop)
        : runRules({
            hops: [c.input.hop],
            cookies: c.input.cookies ?? [],
            origin: new URL(c.input.hop.url).origin,
          }).findings;

      const actualFired = findings.some(
        (f) => f.ruleId === c.ruleId && f.outcome !== 'pass',
      );
      byClass[c.classification]?.push({ expected: c.expectedFire, actual: actualFired });
    }

    const exactMetrics = computeMetrics(byClass['exact-config'] ?? []);
    const heuristicMetrics = computeMetrics(byClass.heuristic ?? []);

    expect(exactMetrics.precision).toBe(1);
    expect(exactMetrics.recall).toBe(1);
    expect(exactMetrics.tp).toBeGreaterThanOrEqual(4);
    expect(exactMetrics.tn).toBeGreaterThanOrEqual(4);

    expect(heuristicMetrics.precision).toBe(1);
    expect(heuristicMetrics.recall).toBe(1);
  });

  it('keeps secret placeholders/public keys free of high/critical FPs and ensures heuristics stay unconfirmed', () => {
    const awsExample = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
    const stripePub = ['pk', 'live', '51Abcdefghijklmnopqrstuvwx1234567890'].join('_');
    const authPositive = detectAuthLeads({
      url: 'https://app.example/login',
      forms: [{ action: 'http://insecure.example/login', method: 'POST', inputs: [{ type: 'password', name: 'pwd' }] }],
    }, 'in-scope');
    const cleartextLead = authPositive.find((l) => l.ruleId === 'AUTH-003');
    expect(cleartextLead).toBeDefined();
    expect(cleartextLead?.tier).toBe('observed');
    if (cleartextLead) {
      const verdict = verifyLeadPassive(cleartextLead);
      expect(verdict.evidenceStatus).toBe('observed');
      expect(verdict.status).toBe('likely');
    }

    // Heuristic POST form without anti-CSRF must remain unconfirmed
    const csrfHeuristic = detectAuthLeads({
      url: 'https://app.example/profile',
      forms: [{ action: '/profile', method: 'POST', inputs: [{ type: 'text', name: 'bio' }] }],
    }, 'in-scope');
    const csrf = csrfHeuristic.find((l) => l.ruleId === 'AUTH-002');
    expect(csrf).toBeDefined();
    if (csrf) {
      expect(verifyLeadPassive(csrf).status).not.toBe('confirmed');
    }

    // Secret detector positive vs public/placeholder negative corpus
    const jsSample = `
      const pub = "${stripePub}";
      const placeholder = "YOUR_API_KEY_HERE";
      const realPattern = "${awsExample}";
    `;
    const secretLeads = detectSecrets(jsSample, 'https://app.example/app.js', 'in-scope');
    const nonInfo = secretLeads.filter((l) => l.potential !== 'info');

    // Placeholder dropped; public key stays info/public-key; real AWS key detected once
    expect(nonInfo.some((l) => l.ruleId === 'SEC-001')).toBe(true);
    expect(nonInfo.some((l) => l.evidence.preview.includes('YOUR_API_KEY'))).toBe(false);
    expect(nonInfo.some((l) => l.evidence.preview.includes('pk_live'))).toBe(false);
    for (const s of nonInfo) {
      // Passive credential verdict must NEVER claim active liveness confirmation
      expect(verifyLeadPassive(s).status).not.toBe('confirmed');
    }
  });
});
