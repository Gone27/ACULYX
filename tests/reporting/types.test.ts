import { describe, it, expect, beforeEach } from 'vitest';
import type {
  ResearcherReviewState,
  FindingReportDetail,
  TriageAnnotation,
  BugBountyReportDraft,
} from '../../src/shared/reporting/types';
import {
  TriageStore,
  ReportBuilder,
  sanitizeUrlForReport,
  redactAllSecrets,
} from '../../src/shared/reporting';
import type { Finding } from '../../src/shared/types';
import { computeScore } from '../../src/rules/scoring';

/**
 * Runtime validator for ResearcherReviewState.
 */
function isResearcherReviewState(val: unknown): val is ResearcherReviewState {
  return (
    val === 'unreviewed' ||
    val === 'needs-manual-verification' ||
    val === 'verified-by-researcher' ||
    val === 'not-reproducible' ||
    val === 'not-a-finding'
  );
}

/**
 * Runtime validator for FindingReportDetail.
 */
function isValidFindingReportDetail(detail: unknown): detail is FindingReportDetail {
  if (typeof detail !== 'object' || detail === null) return false;
  const d = detail as Record<string, unknown>;
  if (!Array.isArray(d['reproductionSteps'])) return false;
  if (!Array.isArray(d['preconditions'])) return false;
  if (typeof d['expectedBehavior'] !== 'string' || d['expectedBehavior'].length === 0) return false;
  if (typeof d['observedBehavior'] !== 'string' || d['observedBehavior'].length === 0) return false;
  if (typeof d['impact'] !== 'string' || d['impact'].length === 0) return false;
  if (typeof d['sanitizedEvidence'] !== 'string') return false;
  if (!Array.isArray(d['limitations'])) return false;
  if (typeof d['remediation'] !== 'string' || d['remediation'].length === 0) return false;
  if (d['scopeNote'] !== undefined && typeof d['scopeNote'] !== 'string') return false;
  if (
    d['scopeStatus'] !== undefined &&
    d['scopeStatus'] !== 'in-scope' &&
    d['scopeStatus'] !== 'out-of-scope' &&
    d['scopeStatus'] !== 'unknown'
  ) {
    return false;
  }
  return true;
}

/**
 * Runtime validator for TriageAnnotation.
 */
function isValidTriageAnnotation(annotation: unknown): annotation is TriageAnnotation {
  if (typeof annotation !== 'object' || annotation === null) return false;
  const a = annotation as Record<string, unknown>;
  if (typeof a['findingId'] !== 'string' || a['findingId'].length === 0) return false;
  if (!isResearcherReviewState(a['state'])) return false;
  if (a['notes'] !== undefined && typeof a['notes'] !== 'string') return false;
  if (typeof a['updatedAt'] !== 'number' || isNaN(a['updatedAt'])) return false;
  return true;
}

/**
 * Runtime validator for BugBountyReportDraft.
 */
function isValidBugBountyReportDraft(draft: unknown): draft is BugBountyReportDraft {
  if (typeof draft !== 'object' || draft === null) return false;
  const b = draft as Record<string, unknown>;
  if (b['id'] !== undefined && typeof b['id'] !== 'string') return false;
  if (typeof b['title'] !== 'string' || b['title'].length === 0) return false;
  if (
    b['severity'] !== 'critical' &&
    b['severity'] !== 'high' &&
    b['severity'] !== 'medium' &&
    b['severity'] !== 'low' &&
    b['severity'] !== 'info' &&
    b['severity'] !== 'pass'
  ) {
    return false;
  }
  if (typeof b['target'] !== 'string' || b['target'].length === 0) return false;
  if (typeof b['summary'] !== 'string' || b['summary'].length === 0) return false;
  if (!Array.isArray(b['reproductionSteps'])) return false;
  if (!Array.isArray(b['preconditions'])) return false;
  if (typeof b['expectedBehavior'] !== 'string') return false;
  if (typeof b['observedBehavior'] !== 'string') return false;
  if (typeof b['impact'] !== 'string') return false;
  if (typeof b['evidence'] !== 'string') return false;
  if (typeof b['remediation'] !== 'string') return false;
  if (!Array.isArray(b['limitations'])) return false;
  if (!isResearcherReviewState(b['reviewState'])) return false;
  if (
    b['scopeStatus'] !== undefined &&
    b['scopeStatus'] !== 'in-scope' &&
    b['scopeStatus'] !== 'out-of-scope' &&
    b['scopeStatus'] !== 'unknown'
  ) {
    return false;
  }
  if (b['createdAt'] !== undefined && typeof b['createdAt'] !== 'number') return false;
  if (b['updatedAt'] !== undefined && typeof b['updatedAt'] !== 'number') return false;
  if (b['ruleId'] !== undefined && typeof b['ruleId'] !== 'string') return false;
  if (b['cweId'] !== undefined && typeof b['cweId'] !== 'string') return false;
  if (b['cvssScore'] !== undefined && typeof b['cvssScore'] !== 'number') return false;
  if (b['references'] !== undefined && !Array.isArray(b['references'])) return false;
  return true;
}

describe('Reporting & Researcher Triage Contracts (R0)', () => {
  describe('ResearcherReviewState', () => {
    it('accepts all five valid review states', () => {
      const states: ResearcherReviewState[] = [
        'unreviewed',
        'needs-manual-verification',
        'verified-by-researcher',
        'not-reproducible',
        'not-a-finding',
      ];

      for (const s of states) {
        expect(isResearcherReviewState(s)).toBe(true);
      }
    });

    it('rejects unrecognized review states', () => {
      expect(isResearcherReviewState('pending')).toBe(false);
      expect(isResearcherReviewState('confirmed')).toBe(false);
      expect(isResearcherReviewState('triaged')).toBe(false);
      expect(isResearcherReviewState('')).toBe(false);
      expect(isResearcherReviewState(null)).toBe(false);
      expect(isResearcherReviewState(undefined)).toBe(false);
    });
  });

  describe('FindingReportDetail', () => {
    it('creates a complete technical report detail with sanitized evidence and limitations', () => {
      const detail: FindingReportDetail = {
        reproductionSteps: [
          '1. Navigate to https://target.example.com/login',
          '2. Observe response headers for missing Content-Security-Policy',
          '3. Inspect document.cookie handling in authenticated session',
        ],
        preconditions: ['Browser with JavaScript enabled', 'Valid session context'],
        expectedBehavior: 'Response must include strict Content-Security-Policy header',
        observedBehavior: 'Content-Security-Policy header is absent from server response',
        impact: 'Lack of CSP enables arbitrary script injection if XSS is present',
        sanitizedEvidence: 'HTTP/1.1 200 OK\\r\\nServer: nginx\\r\\n[Authorization header REDACTED]',
        limitations: [
          'Passive observation only; no active injection payload was executed',
          'Cached responses may omit hop-specific headers',
        ],
        scopeNote: 'Host target.example.com is in-scope under *.example.com program rule',
        remediation: "Deploy Content-Security-Policy: default-src 'self'; script-src 'self'",
        scopeStatus: 'in-scope',
      };

      expect(isValidFindingReportDetail(detail)).toBe(true);
      expect(detail.reproductionSteps).toHaveLength(3);
      expect(detail.limitations).toHaveLength(2);
      expect(detail.scopeStatus).toBe('in-scope');
      expect(detail.sanitizedEvidence).toContain('[Authorization header REDACTED]');
    });

    it('creates a minimal FindingReportDetail without optional scope fields', () => {
      const detail: FindingReportDetail = {
        reproductionSteps: ['1. Request /api/data'],
        preconditions: [],
        expectedBehavior: 'Access-Control-Allow-Origin should not be wildcard with credentials',
        observedBehavior: 'Access-Control-Allow-Origin: * was returned',
        impact: 'Data exposure to untrusted third parties',
        sanitizedEvidence: 'Access-Control-Allow-Origin: *',
        limitations: [],
        remediation: 'Configure explicit trusted origin whitelist',
      };

      expect(isValidFindingReportDetail(detail)).toBe(true);
      expect(detail.scopeNote).toBeUndefined();
      expect(detail.scopeStatus).toBeUndefined();
    });

    it('rejects invalid FindingReportDetail structures', () => {
      expect(isValidFindingReportDetail({ reproductionSteps: [] })).toBe(false);
      expect(isValidFindingReportDetail({ expectedBehavior: 'ok' })).toBe(false);
    });
  });

  describe('TriageAnnotation', () => {
    it('creates a triage annotation decoupled from immutable finding', () => {
      const annotation: TriageAnnotation = {
        findingId: 'f-101',
        state: 'verified-by-researcher',
        notes: 'Manually verified via curl; reproduced missing header on production gateway.',
        updatedAt: 1728400000000,
      };

      expect(isValidTriageAnnotation(annotation)).toBe(true);
      expect(annotation.findingId).toBe('f-101');
      expect(annotation.state).toBe('verified-by-researcher');
      expect(annotation.notes).toBeDefined();
    });

    it('preserves immutable finding when triage state updates', () => {
      const finding: Finding = {
        ruleId: 'CSP-001',
        category: 'header',
        severity: 'high',
        title: 'Missing Content-Security-Policy',
        evidence: 'Header missing',
        recommendation: 'Add CSP',
        reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
        limitations: ['Passive scan limitation'],
        scopeStatus: 'in-scope',
      };

      // Triage state stored in separate annotation object
      const triage1: TriageAnnotation = {
        findingId: 'finding-abc',
        state: 'needs-manual-verification',
        updatedAt: 1000,
      };

      const triage2: TriageAnnotation = {
        ...triage1,
        state: 'verified-by-researcher',
        notes: 'Validated with second researcher',
        updatedAt: 2000,
      };

      // Finding object is unaltered
      expect(finding.ruleId).toBe('CSP-001');
      expect(finding.severity).toBe('high');
      expect(triage1.state).toBe('needs-manual-verification');
      expect(triage2.state).toBe('verified-by-researcher');
    });

    it('rejects malformed TriageAnnotation objects', () => {
      expect(isValidTriageAnnotation({ findingId: '', state: 'unreviewed' })).toBe(false);
      expect(isValidTriageAnnotation({ findingId: 'f-1', state: 'invalid-state', updatedAt: 123 })).toBe(false);
    });
  });

  describe('BugBountyReportDraft', () => {
    it('constructs a full bug bounty report draft with CVSS, CWE, and references', () => {
      const draft: BugBountyReportDraft = {
        id: 'draft-2026-001',
        title: 'Missing Strict-Transport-Security Header on Authentication Portal',
        severity: 'high',
        target: 'https://auth.target.com',
        summary: 'Authentication endpoint does not enforce HSTS, enabling SSL stripping attacks.',
        reproductionSteps: [
          '1. Send HTTP GET request to http://auth.target.com/login',
          '2. Observe lack of Strict-Transport-Security header on TLS redirect',
        ],
        preconditions: ['Attacker capable of MITM position on local network'],
        expectedBehavior: 'Server must send Strict-Transport-Security with max-age >= 31536000',
        observedBehavior: 'No Strict-Transport-Security header present in response',
        impact: 'Man-in-the-middle attackers can downgrade HTTPS connections to HTTP and intercept credentials',
        evidence: 'HTTP/1.1 200 OK\\r\\nDate: Wed, 08 Oct 2026 12:00:00 GMT\\r\\nServer: Apache',
        remediation: 'Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` header.',
        limitations: ['Scanner observed passive response only'],
        scopeStatus: 'in-scope',
        reviewState: 'verified-by-researcher',
        createdAt: 1728400000000,
        updatedAt: 1728400050000,
        ruleId: 'HSTS-001',
        cweId: 'CWE-319',
        cvssScore: 7.4,
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html',
          'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
        ],
      };

      expect(isValidBugBountyReportDraft(draft)).toBe(true);
      expect(draft.id).toBe('draft-2026-001');
      expect(draft.severity).toBe('high');
      expect(draft.cweId).toBe('CWE-319');
      expect(draft.cvssScore).toBe(7.4);
      expect(draft.reviewState).toBe('verified-by-researcher');
    });

    it('constructs a minimal BugBountyReportDraft', () => {
      const draft: BugBountyReportDraft = {
        title: 'Missing X-Frame-Options Header',
        severity: 'medium',
        target: 'https://app.target.com/dashboard',
        summary: 'Dashboard can be embedded in an iframe.',
        reproductionSteps: ['1. Embed https://app.target.com/dashboard in an iframe.'],
        preconditions: [],
        expectedBehavior: 'Frame-ancestors or X-Frame-Options DENY/SAMEORIGIN required',
        observedBehavior: 'Header missing',
        impact: 'Potential Clickjacking on sensitive user actions',
        evidence: 'Response missing X-Frame-Options',
        remediation: 'Set X-Frame-Options: DENY',
        limitations: [],
        reviewState: 'unreviewed',
      };

      expect(isValidBugBountyReportDraft(draft)).toBe(true);
      expect(draft.id).toBeUndefined();
      expect(draft.cweId).toBeUndefined();
      expect(draft.scopeStatus).toBeUndefined();
    });
  });

  describe('Finding Model Extensions (limitations & scopeStatus)', () => {
    it('supports limitations and scopeStatus on Finding interface', () => {
      const findingWithScope: Finding = {
        ruleId: 'CORS-001',
        category: 'cors',
        severity: 'medium',
        title: 'Overly Permissive CORS Origin',
        evidence: 'Access-Control-Allow-Origin: *',
        recommendation: 'Specify exact origins',
        reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS',
        limitations: [
          'Preflight request not directly captured',
          'Vary: Origin presence unconfirmed on cached response',
        ],
        scopeStatus: 'in-scope',
      };

      expect(findingWithScope.limitations).toHaveLength(2);
      expect(findingWithScope.scopeStatus).toBe('in-scope');
    });

    it('permits undefined limitations and scopeStatus for backward compatibility', () => {
      const legacyFinding: Finding = {
        ruleId: 'XCTO-001',
        category: 'header',
        severity: 'low',
        title: 'Missing X-Content-Type-Options',
        evidence: 'Header missing',
        recommendation: 'Add X-Content-Type-Options: nosniff',
        reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
      };

      expect(legacyFinding.limitations).toBeUndefined();
      expect(legacyFinding.scopeStatus).toBeUndefined();
    });
  });

  describe('Scoring Behavior for partial-coverage outcome', () => {
    it('treats outcome === "partial-coverage" as non-penalizing (score 100, no deductions)', () => {
      const partialFinding: Finding = {
        ruleId: 'CSP-001',
        category: 'header',
        severity: 'high',
        title: 'Content-Security-Policy Ambiguous Context',
        evidence: 'Service worker interception active; header verification incomplete',
        recommendation: 'Verify CSP at origin server',
        reference: 'https://example.com/csp',
        outcome: 'partial-coverage',
        limitations: ['Service worker may synthesize synthetic response'],
      };

      const result = computeScore([partialFinding]);
      expect(result.score).toBe(100);
      expect(result.grade).toBe('A');
      expect(result.breakdown).toHaveLength(0);
    });

    it('matches non-penalizing behavior of pass, not-observed, and not-applicable', () => {
      const passFinding: Finding = {
        ruleId: 'HSTS-001',
        category: 'transport',
        severity: 'pass',
        title: 'HSTS correctly deployed',
        evidence: 'max-age=31536000',
        recommendation: '',
        reference: '',
        outcome: 'pass',
      };

      const notObservedFinding: Finding = {
        ruleId: 'COOK-001',
        category: 'cookie',
        severity: 'high',
        title: 'Cookie unobserved in current navigation',
        evidence: '',
        recommendation: '',
        reference: '',
        outcome: 'not-observed',
      };

      const notApplicableFinding: Finding = {
        ruleId: 'HSTS-002',
        category: 'transport',
        severity: 'high',
        title: 'HSTS on HTTP',
        evidence: 'HTTP connection',
        recommendation: '',
        reference: '',
        outcome: 'not-applicable',
      };

      const partialCoverageFinding: Finding = {
        ruleId: 'CACHE-001',
        category: 'header',
        severity: 'high',
        title: 'Cache-Control partial observation',
        evidence: 'Hop 1 missing',
        recommendation: '',
        reference: '',
        outcome: 'partial-coverage',
      };

      const result = computeScore([
        passFinding,
        notObservedFinding,
        notApplicableFinding,
        partialCoverageFinding,
      ]);

      expect(result.score).toBe(100);
      expect(result.grade).toBe('A');
      expect(result.breakdown).toHaveLength(0);
    });

    it('penalizes real violations while ignoring partial-coverage findings in the same batch', () => {
      const violationFinding: Finding = {
        ruleId: 'HSTS-001',
        category: 'transport',
        severity: 'high',
        title: 'Missing HSTS',
        evidence: 'Header missing',
        recommendation: 'Add HSTS',
        reference: 'https://example.com',
        outcome: 'violation',
      };

      const partialFinding: Finding = {
        ruleId: 'CSP-001',
        category: 'header',
        severity: 'high',
        title: 'CSP Partial',
        evidence: 'Partial coverage',
        recommendation: '',
        reference: '',
        outcome: 'partial-coverage',
      };

      const result = computeScore([violationFinding, partialFinding]);
      // HSTS-001 high penalty (around 20 points)
      expect(result.score).toBeLessThan(100);
      expect(result.breakdown).toHaveLength(1);
      expect(result.breakdown[0]?.ruleId).toBe('HSTS-001');
    });
  });

  describe('TriageStore (R2 Implementation)', () => {
    beforeEach(async () => {
      TriageStore._resetMemoryStores();
      await TriageStore.clearAll();
    });

    it('returns null for an unannotated finding', async () => {
      const ann = await TriageStore.getAnnotation('nonexistent-id');
      expect(ann).toBeNull();
    });

    it('sets and retrieves a triage annotation with timestamp', async () => {
      const created = await TriageStore.setAnnotation(
        'HSTS-001',
        'needs-manual-verification',
        'Check redirect hops first',
      );

      expect(created.findingId).toBe('HSTS-001');
      expect(created.state).toBe('needs-manual-verification');
      expect(created.notes).toBe('Check redirect hops first');
      expect(created.updatedAt).toBeGreaterThan(0);

      const fetched = await TriageStore.getAnnotation('HSTS-001');
      expect(fetched).not.toBeNull();
      expect(fetched?.state).toBe('needs-manual-verification');
      expect(fetched?.notes).toBe('Check redirect hops first');
    });

    it('updates an existing annotation without duplicates', async () => {
      await TriageStore.setAnnotation('CSP-001', 'unreviewed');
      const updated = await TriageStore.setAnnotation(
        'CSP-001',
        'verified-by-researcher',
        'Confirmed bypass via unsafe-inline',
      );

      expect(updated.state).toBe('verified-by-researcher');
      expect(updated.notes).toBe('Confirmed bypass via unsafe-inline');

      const fetched = await TriageStore.getAnnotation('CSP-001');
      expect(fetched?.state).toBe('verified-by-researcher');
    });

    it('deletes an existing annotation', async () => {
      await TriageStore.setAnnotation('COOK-001', 'not-a-finding');
      const deleted = await TriageStore.deleteAnnotation('COOK-001');
      expect(deleted).toBe(true);

      const fetched = await TriageStore.getAnnotation('COOK-001');
      expect(fetched).toBeNull();
    });

    it('retrieves batch annotations by list of finding IDs', async () => {
      await TriageStore.setAnnotation('R1', 'verified-by-researcher');
      await TriageStore.setAnnotation('R2', 'not-reproducible');
      await TriageStore.setAnnotation('R3', 'not-a-finding');

      const annotations = await TriageStore.getAnnotations(['R1', 'R3']);
      expect(Object.keys(annotations)).toHaveLength(2);
      expect(annotations['R1']?.state).toBe('verified-by-researcher');
      expect(annotations['R3']?.state).toBe('not-a-finding');
      expect(annotations['R2']).toBeUndefined();
    });

    it('preserves finding immutability during triage changes', async () => {
      const finding: Finding = Object.freeze({
        ruleId: 'XFO-001',
        category: 'header',
        severity: 'high',
        title: 'Missing X-Frame-Options',
        evidence: 'Header absent',
        recommendation: 'Add DENY',
        reference: 'https://example.com',
      });

      await TriageStore.setAnnotation(finding.ruleId, 'verified-by-researcher', 'Exploitable via iframe');

      expect(finding.ruleId).toBe('XFO-001');
      expect((finding as unknown as Record<string, unknown>)['state']).toBeUndefined();
      expect((finding as unknown as Record<string, unknown>)['notes']).toBeUndefined();
    });

    it('enforces incognito session isolation without persisting to local storage', async () => {
      await TriageStore.setAnnotation(
        'INCOGNITO-001',
        'verified-by-researcher',
        'Secret test',
        { isIncognito: true },
      );

      const inIncognito = await TriageStore.getAnnotation('INCOGNITO-001', { isIncognito: true });
      expect(inIncognito).not.toBeNull();
      expect(inIncognito?.notes).toBe('Secret test');

      const inPersistent = await TriageStore.getAnnotation('INCOGNITO-001');
      expect(inPersistent).toBeNull();
    });

    it('redacts sensitive tokens and cookies from triage notes before persistence', async () => {
      const dirtyNote = 'Tested with auth_token=CANARY_SECRET_12345 and Set-Cookie: session=MY_COOKIE_SECRET';
      const annotation = await TriageStore.setAnnotation(
        'LEAK-TEST-001',
        'verified-by-researcher',
        dirtyNote,
      );

      expect(annotation.notes).not.toContain('CANARY_SECRET_12345');
      expect(annotation.notes).not.toContain('MY_COOKIE_SECRET');
      expect(annotation.notes).toContain('[REDACTED]');
    });

    it('enforces maximum length cap on triage notes', async () => {
      const longNote = 'A'.repeat(6000);
      const annotation = await TriageStore.setAnnotation(
        'LEN-TEST-001',
        'verified-by-researcher',
        longNote,
      );

      expect(annotation.notes?.length).toBeLessThanOrEqual(5000);
    });
  });

  describe('ReportBuilder (R2 Implementation)', () => {
    const sampleFinding: Finding = {
      ruleId: 'HSTS-001',
      category: 'transport',
      severity: 'high',
      title: 'Missing Strict-Transport-Security Header',
      evidence: 'Strict-Transport-Security header is absent',
      recommendation: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
      reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
      impact: 'Enables SSL stripping and man-in-the-middle attacks on insecure HTTP requests.',
      sourceUrl: 'https://target.example.com/login',
      scopeStatus: 'in-scope',
      limitations: ['Passive scan; HTTP to HTTPS redirect status unverified.'],
    };

    it('builds a complete BugBountyReportDraft from a finding', () => {
      const draft = ReportBuilder.buildReportDraft(sampleFinding, {
        reviewState: 'verified-by-researcher',
        targetUrl: 'https://target.example.com/login',
      });

      expect(draft.title).toContain('[HIGH] Missing Strict-Transport-Security Header');
      expect(draft.target).toBe('https://target.example.com/login');
      expect(draft.severity).toBe('high');
      expect(draft.reviewState).toBe('verified-by-researcher');
      expect(draft.scopeStatus).toBe('in-scope');
      expect(draft.reproductionSteps.length).toBeGreaterThanOrEqual(4);
      expect(draft.preconditions.length).toBeGreaterThanOrEqual(2);
      expect(draft.expectedBehavior).toContain('Strict-Transport-Security');
      expect(draft.observedBehavior).toContain('Strict-Transport-Security header is absent');
      expect(draft.remediation).toContain('max-age=31536000');
      expect(draft.limitations).toContain('Passive scan; HTTP to HTTPS redirect status unverified.');
      expect(draft.cweId).toBe('CWE-319');
      expect(draft.cvssScore).toBe(6.5);
    });

    it('formats a report draft into clean Markdown adhering to standards', () => {
      const draft = ReportBuilder.buildReportDraft(sampleFinding, {
        reviewState: 'verified-by-researcher',
      });

      const md = ReportBuilder.formatReportAsMarkdown(draft);
      expect(md).toContain('# [HIGH] Missing Strict-Transport-Security Header');
      expect(md).toContain('## Vulnerability Details');
      expect(md).toContain('- **Target:** `https://target.example.com/login`');
      expect(md).toContain('- **Rule ID:** `HSTS-001`');
      expect(md).toContain('- **CWE:** [CWE-319]');
      expect(md).toContain('## Reproduction Steps');
      expect(md).toContain('## Expected vs Observed Behavior');
      expect(md).toContain('## Sanitized Evidence');
      expect(md).toContain('## Security Impact');
      expect(md).toContain('## Remediation');
    });

    it('formats a report draft into valid JSON string', () => {
      const draft = ReportBuilder.buildReportDraft(sampleFinding);
      const jsonStr = ReportBuilder.formatReportAsJson(draft);
      const parsed = JSON.parse(jsonStr) as BugBountyReportDraft;
      expect(parsed.ruleId).toBe('HSTS-001');
      expect(parsed.severity).toBe('high');
    });
  });

  describe('Secret Redaction Invariants (R2 Implementation)', () => {
    it('strips credentials embedded in URLs', () => {
      const dirtyUrl = 'https://admin:superSecretPass123@api.target.com/v1/auth';
      const clean = sanitizeUrlForReport(dirtyUrl);
      expect(clean).not.toContain('superSecretPass123');
      expect(clean).not.toContain('admin:');
      expect(clean).toBe('https://api.target.com/v1/auth');
    });

    it('strips query parameters from URLs by default in reports', () => {
      const dirtyUrl = 'https://target.com/callback?token=eyJhbGciOiJIUzI1NiJ9.test&code=secret123&public=ok';
      const clean = sanitizeUrlForReport(dirtyUrl);
      expect(clean).not.toContain('eyJhbGciOiJIUzI1NiJ9');
      expect(clean).not.toContain('secret123');
      expect(clean).not.toContain('?');
      expect(clean).toBe('https://target.com/callback');
    });

    it('strips URL fragments entirely', () => {
      const dirtyUrl = 'https://target.com/app#access_token=secret_hash_fragment';
      const clean = sanitizeUrlForReport(dirtyUrl);
      expect(clean).not.toContain('secret_hash_fragment');
      expect(clean).not.toContain('#');
    });

    it('redacts sensitive path segments (UUIDs, JWTs, tokens)', () => {
      const dirtyUrl = 'https://target.com/reset/a1b2c3d4e5f60718293a4b5c6d7e8f90';
      const clean = sanitizeUrlForReport(dirtyUrl);
      expect(clean).not.toContain('a1b2c3d4e5f60718293a4b5c6d7e8f90');
      expect(clean).toContain('/reset/[token]');
    });

    it('redacts raw Authorization headers in evidence strings', () => {
      const evidence = 'HTTP/1.1 200 OK\r\nAuthorization: Bearer my_secret_bearer_token_abc\r\nContent-Type: text/html';
      const sanitized = redactAllSecrets(evidence);
      expect(sanitized).not.toContain('my_secret_bearer_token_abc');
      expect(sanitized).toContain('Authorization: [REDACTED]');
    });

    it('redacts raw Set-Cookie lines in evidence strings while preserving flags', () => {
      const evidence = 'Set-Cookie: session_id=CANARY_SESSION_SECRET; Path=/; Secure; HttpOnly';
      const sanitized = redactAllSecrets(evidence);
      expect(sanitized).not.toContain('CANARY_SESSION_SECRET');
      expect(sanitized).toContain('session_id=[REDACTED]');
      expect(sanitized).toContain('Secure; HttpOnly');
    });

    it('redacts raw Cookie request headers in evidence strings', () => {
      const evidence = 'Cookie: token=SECRET_TOKEN; theme=dark';
      const sanitized = redactAllSecrets(evidence);
      expect(sanitized).not.toContain('SECRET_TOKEN');
      expect(sanitized).toContain('token=[REDACTED]');
    });

    it('scrubs synthetic canaries from all report outputs', () => {
      const rawText = 'Leak check: canary_secret_value_xyz should never appear in reports';
      const sanitized = redactAllSecrets(rawText);
      expect(sanitized).not.toContain('canary_secret_value_xyz');
      expect(sanitized).toContain('[REDACTED]');
    });
  });
});
