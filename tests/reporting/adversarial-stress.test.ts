import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  TriageStore,
  ReportBuilder,
  sanitizeUrlForReport,
  redactAllSecrets,
} from '../../src/shared/reporting';
import type { Finding } from '../../src/shared/types';
import type { BugBountyReportDraft, ResearcherReviewState } from '../../src/shared/reporting/types';

describe('Challenger 2 Empirical Stress Test — Secret Redaction & Incognito Isolation', () => {
  // ─── 1. Secret Redaction Stress Tests ─────────────────────────────────────────

  describe('1. Secret Redaction: Direct Utilities (sanitizeUrlForReport & redactAllSecrets)', () => {
    it('redacts URL embedded credentials (admin:secret123@)', () => {
      const raw = 'http://admin:secret123@target.com/path';
      const sanitizedUrl = sanitizeUrlForReport(raw);
      expect(sanitizedUrl).not.toContain('secret123');
      expect(sanitizedUrl).not.toContain('admin:');
      expect(sanitizedUrl).toBe('http://target.com/path');
    });

    it('redacts URL embedded credentials with special characters and ports', () => {
      const raw = 'https://researcher:P%40ssw0rd!_complex@sub.target.com:8443/api/v1';
      const sanitizedUrl = sanitizeUrlForReport(raw);
      expect(sanitizedUrl).not.toContain('P%40ssw0rd');
      expect(sanitizedUrl).not.toContain('researcher');
      expect(sanitizedUrl).toBe('https://sub.target.com:8443/api/v1');
    });

    it('redacts sensitive path tokens (/reset/abc-123-uuid-456/ and UUIDs)', () => {
      // UUID in path
      const uuidUrl = 'https://target.com/reset/550e8400-e29b-41d4-a716-446655440000/';
      const cleanUuid = sanitizeUrlForReport(uuidUrl);
      expect(cleanUuid).not.toContain('550e8400-e29b-41d4-a716-446655440000');
      expect(cleanUuid).toContain('/reset/[id]');

      // Sensitive keyword followed by token segment
      const resetUrl = 'https://target.com/reset/secret-token-abc12345/';
      const cleanReset = sanitizeUrlForReport(resetUrl);
      expect(cleanReset).not.toContain('secret-token-abc12345');
      expect(cleanReset).toContain('/reset/[token]');

      // Direct redactUrlPath test
      const directPath = 'http://target.com/reset/abc-123-uuid-456/';
      const cleanDirect = sanitizeUrlForReport(directPath);
      expect(cleanDirect).not.toContain('abc-123-uuid-456');
    });

    it('redacts JWT tokens in text and URLs', () => {
      const sampleJwt =
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

      // In arbitrary text via redactAllSecrets
      const textWithJwt = `Bearer token: ${sampleJwt} attached in payload`;
      const cleanText = redactAllSecrets(textWithJwt);
      expect(cleanText).not.toContain(sampleJwt);
      expect(cleanText).toContain('[token]');

      // In URL path
      const urlWithJwt = `https://target.com/api/verify/${sampleJwt}`;
      const cleanUrl = sanitizeUrlForReport(urlWithJwt);
      expect(cleanUrl).not.toContain(sampleJwt);
      expect(cleanUrl).toContain('[token]');

      // In URL query param
      const urlWithQueryJwt = `https://target.com/callback?token=${sampleJwt}&public=1`;
      const cleanQueryUrl = sanitizeUrlForReport(urlWithQueryJwt);
      expect(cleanQueryUrl).not.toContain(sampleJwt);
      expect(cleanQueryUrl).toContain('token=%5BREDACTED%5D');
    });

    it('strips URL fragments entirely (#token=secret)', () => {
      const urlWithFrag = 'https://target.com/oauth/callback#token=super_secret_fragment_999&state=secret123';
      const cleanUrl = sanitizeUrlForReport(urlWithFrag);
      expect(cleanUrl).not.toContain('super_secret_fragment_999');
      expect(cleanUrl).not.toContain('secret123');
      expect(cleanUrl).not.toContain('#');
      expect(cleanUrl).toBe('https://target.com/oauth/callback');
    });

    it('redacts raw Authorization and Proxy-Authorization headers', () => {
      const rawAuth = 'Authorization: Bearer secret_bearer_token_xyz987\r\nContent-Type: application/json';
      const cleanAuth = redactAllSecrets(rawAuth);
      expect(cleanAuth).not.toContain('secret_bearer_token_xyz987');
      expect(cleanAuth).toContain('Authorization: [REDACTED]');

      const rawBasic = 'authorization: basic YWRtaW46c2VjcmV0MTIz';
      const cleanBasic = redactAllSecrets(rawBasic);
      expect(cleanBasic).not.toContain('YWRtaW46c2VjcmV0MTIz');
      expect(cleanBasic).toContain('authorization: [REDACTED]');

      const rawProxy = 'Proxy-Authorization: Negotiate secret_kerberos_ticket_000';
      const cleanProxy = redactAllSecrets(rawProxy);
      expect(cleanProxy).not.toContain('secret_kerberos_ticket_000');
      expect(cleanProxy).toContain('Proxy-Authorization: [REDACTED]');
    });

    it('redacts Set-Cookie lines while preserving flags', () => {
      const rawSetCookie = 'Set-Cookie: session=CANARY_SESSION_SECRET_98765; Path=/; Secure; HttpOnly; SameSite=Strict';
      const cleanSetCookie = redactAllSecrets(rawSetCookie);
      expect(cleanSetCookie).not.toContain('CANARY_SESSION_SECRET_98765');
      expect(cleanSetCookie).toContain('session=[REDACTED]');
      expect(cleanSetCookie).toContain('Path=/; Secure; HttpOnly; SameSite=Strict');

      const multiCookie = 'Set-Cookie: auth=SECRET_AUTH_1; Secure\r\nSet-Cookie: tracking=SECRET_TRACK_2; HttpOnly';
      const cleanMulti = redactAllSecrets(multiCookie);
      expect(cleanMulti).not.toContain('SECRET_AUTH_1');
      expect(cleanMulti).not.toContain('SECRET_TRACK_2');
      expect(cleanMulti).toContain('auth=[REDACTED]');
      expect(cleanMulti).toContain('tracking=[REDACTED]');
    });

    it('redacts canary tokens in arbitrary text', () => {
      const canaryString =
        'Testing canary_secret_canary_01 and token_canary_value_02 and password_canary_pass_03 and apiKey_canary_key_04';
      const cleaned = redactAllSecrets(canaryString);
      expect(cleaned).not.toContain('canary_secret_canary_01');
      expect(cleaned).not.toContain('token_canary_value_02');
      expect(cleaned).not.toContain('password_canary_pass_03');
      expect(cleaned).not.toContain('apiKey_canary_key_04');
      expect(cleaned).toContain('[REDACTED]');
    });
  });

  describe('2. Secret Redaction Stress Tests through buildReportDraft', () => {
    const CANARY_URL_CREDS = 'http://admin:secret123@target.com/path';
    const CANARY_URL_RESET = 'http://target.com/reset/abc-123-uuid-456/';
    const CANARY_JWT =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const CANARY_FRAG_URL = 'http://target.com/dashboard#token=super_secret_frag_val';
    const CANARY_AUTH_HEADER = 'Authorization: Bearer super_secret_auth_token_999';
    const CANARY_SET_COOKIE = 'Set-Cookie: session=SUPER_SECRET_COOKIE_VAL_777; Path=/; Secure; HttpOnly';
    const CANARY_TOKEN = 'canary_leak_check_99999';

    it('buildReportDraft sanitizes targetUrl with embedded credentials and fragments', () => {
      const finding: Finding = {
        ruleId: 'HSTS-001',
        category: 'transport',
        severity: 'high',
        title: 'Missing HSTS',
        evidence: 'Strict-Transport-Security header not observed',
        recommendation: 'Add HSTS header',
        reference: 'https://example.com',
      };

      const draft = ReportBuilder.buildReportDraft(finding, {
        targetUrl: 'http://admin:secret123@target.com/path#token=frag_secret_123',
      });

      expect(draft.target).not.toContain('secret123');
      expect(draft.target).not.toContain('admin:');
      expect(draft.target).not.toContain('frag_secret_123');
      expect(draft.target).not.toContain('#');
      expect(draft.target).toBe('http://target.com/path');

      // Check reproductionSteps
      for (const step of draft.reproductionSteps) {
        expect(step).not.toContain('secret123');
        expect(step).not.toContain('admin:');
        expect(step).not.toContain('frag_secret_123');
      }

      // Check title
      expect(draft.title).not.toContain('secret123');
      expect(draft.title).not.toContain('admin:');

      // Check formatReportAsMarkdown
      const md = ReportBuilder.formatReportAsMarkdown(draft);
      expect(md).not.toContain('secret123');
      expect(md).not.toContain('admin:');
      expect(md).not.toContain('frag_secret_123');

      // Check formatReportAsJson
      const json = ReportBuilder.formatReportAsJson(draft);
      expect(json).not.toContain('secret123');
      expect(json).not.toContain('admin:');
      expect(json).not.toContain('frag_secret_123');
    });

    it('buildReportDraft sanitizes targetUrl with sensitive path tokens (/reset/abc-123-uuid-456/)', () => {
      const finding: Finding = {
        ruleId: 'CSP-001',
        category: 'header',
        severity: 'high',
        title: 'Missing CSP',
        evidence: 'CSP header missing',
        recommendation: 'Add CSP',
        reference: 'https://example.com',
        sourceUrl: CANARY_URL_RESET,
      };

      const draft = ReportBuilder.buildReportDraft(finding);

      expect(draft.target).not.toContain('abc-123-uuid-456');
      expect(draft.target).toContain('/reset/[token]');

      const md = ReportBuilder.formatReportAsMarkdown(draft);
      expect(md).not.toContain('abc-123-uuid-456');

      const json = ReportBuilder.formatReportAsJson(draft);
      expect(json).not.toContain('abc-123-uuid-456');
    });

    it('buildReportDraft scrubs JWT tokens, raw Authorization, Set-Cookie lines, and canaries from evidence', () => {
      const dirtyEvidence = [
        'HTTP/1.1 200 OK',
        CANARY_AUTH_HEADER,
        CANARY_SET_COOKIE,
        `X-Custom-Token: ${CANARY_JWT}`,
        `Server-Status: canary_leak_test_token_8888`,
      ].join('\r\n');

      const finding: Finding = {
        ruleId: 'COOK-001',
        category: 'cookie',
        severity: 'high',
        title: 'Insecure Cookie Attributes',
        evidence: dirtyEvidence,
        recommendation: 'Use Secure and HttpOnly flags',
        reference: 'https://example.com',
      };

      const draft = ReportBuilder.buildReportDraft(finding);

      // Verify zero leak of any secret
      expect(draft.evidence).not.toContain('super_secret_auth_token_999');
      expect(draft.evidence).toContain('Authorization: [REDACTED]');

      expect(draft.evidence).not.toContain('SUPER_SECRET_COOKIE_VAL_777');
      expect(draft.evidence).toContain('session=[REDACTED]');

      expect(draft.evidence).not.toContain(CANARY_JWT);
      expect(draft.evidence).toContain('[token]');

      expect(draft.evidence).not.toContain('canary_leak_test_token_8888');
      expect(draft.evidence).toContain('[REDACTED]');

      // Verify observedBehavior derived from evidence is also scrubbed
      expect(draft.observedBehavior).not.toContain('super_secret_auth_token_999');
      expect(draft.observedBehavior).not.toContain('SUPER_SECRET_COOKIE_VAL_777');
      expect(draft.observedBehavior).not.toContain(CANARY_JWT);
      expect(draft.observedBehavior).not.toContain('canary_leak_test_token_8888');

      // Verify reproductionSteps
      for (const step of draft.reproductionSteps) {
        expect(step).not.toContain('super_secret_auth_token_999');
        expect(step).not.toContain('SUPER_SECRET_COOKIE_VAL_777');
        expect(step).not.toContain(CANARY_JWT);
        expect(step).not.toContain('canary_leak_test_token_8888');
      }

      // Check full markdown and json exports
      const md = ReportBuilder.formatReportAsMarkdown(draft);
      expect(md).not.toContain('super_secret_auth_token_999');
      expect(md).not.toContain('SUPER_SECRET_COOKIE_VAL_777');
      expect(md).not.toContain(CANARY_JWT);
      expect(md).not.toContain('canary_leak_test_token_8888');

      const json = ReportBuilder.formatReportAsJson(draft);
      expect(json).not.toContain('super_secret_auth_token_999');
      expect(json).not.toContain('SUPER_SECRET_COOKIE_VAL_777');
      expect(json).not.toContain(CANARY_JWT);
      expect(json).not.toContain('canary_leak_test_token_8888');
    });

    it('buildReportDraft survives adversarial malformed, empty, and unusual inputs', () => {
      const emptyFinding: Finding = {
        ruleId: 'UNKNOWN-999',
        category: 'header',
        severity: 'info',
        title: '',
        evidence: '',
        recommendation: '',
        reference: '',
      };

      const draft = ReportBuilder.buildReportDraft(emptyFinding, {
        targetUrl: '',
      });

      expect(draft.target).toBe('');
      expect(draft.evidence).toBe('Header or attribute not observed');
      expect(() => ReportBuilder.formatReportAsMarkdown(draft)).not.toThrow();
      expect(() => ReportBuilder.formatReportAsJson(draft)).not.toThrow();
    });
  });

  // ─── 2. Incognito Isolation Stress Tests ──────────────────────────────────────

  describe('3. Incognito Isolation Stress Tests (TriageStore)', () => {
    let mockLocalStorageData: Record<string, unknown> = {};
    let localStorageSetSpy: ReturnType<typeof vi.fn>;
    let localStorageGetSpy: ReturnType<typeof vi.fn>;
    let localStorageRemoveSpy: ReturnType<typeof vi.fn>;

    beforeEach(async () => {
      mockLocalStorageData = {};

      localStorageSetSpy = vi.fn((items: Record<string, unknown>) => {
        Object.assign(mockLocalStorageData, items);
        return Promise.resolve();
      });

      localStorageGetSpy = vi.fn((keys: unknown) => {
        if (keys === null) return Promise.resolve({ ...mockLocalStorageData });
        if (typeof keys === 'string') return Promise.resolve({ [keys]: mockLocalStorageData[keys] });
        if (Array.isArray(keys)) {
          const res: Record<string, unknown> = {};
          for (const k of keys as string[]) {
            if (mockLocalStorageData[k] !== undefined) res[k] = mockLocalStorageData[k];
          }
          return Promise.resolve(res);
        }
        return Promise.resolve({});
      });

      localStorageRemoveSpy = vi.fn((keys: string | string[]) => {
        const arr = Array.isArray(keys) ? keys : [keys];
        for (const k of arr) delete mockLocalStorageData[k];
        return Promise.resolve();
      });

      (globalThis as unknown as { chrome: unknown }).chrome = {
        storage: {
          local: {
            get: localStorageGetSpy,
            set: localStorageSetSpy,
            remove: localStorageRemoveSpy,
          },
        },
      };

      TriageStore._resetMemoryStores();
      await TriageStore.clearAll();
      localStorageSetSpy.mockClear();
      localStorageGetSpy.mockClear();
      localStorageRemoveSpy.mockClear();
    });

    it('stores incognito annotations strictly in memory and zero records written to chrome.storage.local', async () => {
      const findingId = 'INCOGNITO-FINDING-001';
      const annotation = await TriageStore.setAnnotation(
        findingId,
        'verified-by-researcher',
        'Incognito private test note',
        { isIncognito: true },
      );

      expect(annotation.findingId).toBe(findingId);
      expect(annotation.state).toBe('verified-by-researcher');
      expect(annotation.notes).toBe('Incognito private test note');

      // CRITICAL INVARIANT: chrome.storage.local.set must NOT be called for incognito!
      expect(localStorageSetSpy).not.toHaveBeenCalled();
      expect(Object.keys(mockLocalStorageData)).toHaveLength(0);

      // Verify retrieved in incognito mode
      const retrievedIncognito = await TriageStore.getAnnotation(findingId, { isIncognito: true });
      expect(retrievedIncognito).not.toBeNull();
      expect(retrievedIncognito?.findingId).toBe(findingId);
      expect(retrievedIncognito?.notes).toBe('Incognito private test note');

      // CRITICAL INVARIANT: Non-incognito caller cannot retrieve incognito annotation
      const retrievedNormal = await TriageStore.getAnnotation(findingId);
      expect(retrievedNormal).toBeNull();
    });

    it('batch retrieval (getAnnotations) isolates incognito records completely', async () => {
      // 1. Create a regular persistent annotation
      await TriageStore.setAnnotation('PERSIST-001', 'unreviewed', 'Normal note');
      expect(localStorageSetSpy).toHaveBeenCalledTimes(1);

      // 2. Create 3 incognito annotations
      await TriageStore.setAnnotation('INCOG-001', 'verified-by-researcher', 'Private 1', { isIncognito: true });
      await TriageStore.setAnnotation('INCOG-002', 'needs-manual-verification', 'Private 2', { isIncognito: true });
      await TriageStore.setAnnotation('INCOG-003', 'not-a-finding', 'Private 3', { isIncognito: true });

      // Local storage must still only have the 1 persistent record!
      expect(localStorageSetSpy).toHaveBeenCalledTimes(1);
      expect(Object.keys(mockLocalStorageData)).toHaveLength(1);
      expect(mockLocalStorageData['triage:PERSIST-001']).toBeDefined();
      expect(mockLocalStorageData['triage:INCOG-001']).toBeUndefined();
      expect(mockLocalStorageData['triage:INCOG-002']).toBeUndefined();
      expect(mockLocalStorageData['triage:INCOG-003']).toBeUndefined();

      // Batch get for incognito retrieves only incognito
      const incognitoBatch = await TriageStore.getAnnotations(undefined, { isIncognito: true });
      expect(Object.keys(incognitoBatch)).toHaveLength(3);
      expect(incognitoBatch['INCOG-001']).toBeDefined();
      expect(incognitoBatch['INCOG-002']).toBeDefined();
      expect(incognitoBatch['INCOG-003']).toBeDefined();
      expect(incognitoBatch['PERSIST-001']).toBeUndefined();

      // Batch get for persistent retrieves only persistent
      const normalBatch = await TriageStore.getAnnotations(undefined, { isIncognito: false });
      expect(Object.keys(normalBatch)).toHaveLength(1);
      expect(normalBatch['PERSIST-001']).toBeDefined();
      expect(normalBatch['INCOG-001']).toBeUndefined();
    });

    it('deleteAnnotation with isIncognito: true removes from memory without touching persistent storage', async () => {
      await TriageStore.setAnnotation('INCOG-DEL', 'needs-manual-verification', undefined, { isIncognito: true });
      expect(localStorageSetSpy).not.toHaveBeenCalled();

      const deleted = await TriageStore.deleteAnnotation('INCOG-DEL', { isIncognito: true });
      expect(deleted).toBe(true);

      // chrome.storage.local.remove must NOT be called for incognito deletion
      expect(localStorageRemoveSpy).not.toHaveBeenCalled();

      const check = await TriageStore.getAnnotation('INCOG-DEL', { isIncognito: true });
      expect(check).toBeNull();
    });

    it('clearAll({ isIncognitoOnly: true }) clears only in-memory incognito store', async () => {
      // Put one in persistent, one in incognito
      await TriageStore.setAnnotation('P-STAY', 'verified-by-researcher', 'Keep me');
      await TriageStore.setAnnotation('I-GO', 'verified-by-researcher', 'Clear me', { isIncognito: true });

      await TriageStore.clearAll({ isIncognitoOnly: true });

      // Incognito record gone
      const incog = await TriageStore.getAnnotation('I-GO', { isIncognito: true });
      expect(incog).toBeNull();

      // Persistent record intact
      const persist = await TriageStore.getAnnotation('P-STAY');
      expect(persist).not.toBeNull();
      expect(persist?.notes).toBe('Keep me');
    });

    it('stress test: 100 concurrent incognito writes result in ZERO persistent storage operations', async () => {
      const promises: Promise<unknown>[] = [];
      for (let i = 0; i < 100; i++) {
        promises.push(
          TriageStore.setAnnotation(
            `CONCURRENT-${i}`,
            'verified-by-researcher',
            `Secret incognito note ${i}`,
            { isIncognito: true },
          ),
        );
      }
      await Promise.all(promises);

      // ZERO calls to persistent storage
      expect(localStorageSetSpy).not.toHaveBeenCalled();
      expect(Object.keys(mockLocalStorageData)).toHaveLength(0);

      // Verify all 100 exist in incognito store
      const allIncog = await TriageStore.getAnnotations(undefined, { isIncognito: true });
      expect(Object.keys(allIncog)).toHaveLength(100);
      for (let i = 0; i < 100; i++) {
        expect(allIncog[`CONCURRENT-${i}`]?.notes).toBe(`Secret incognito note ${i}`);
      }
    });
  });
});
