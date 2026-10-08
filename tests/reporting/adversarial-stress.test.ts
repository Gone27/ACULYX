import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  TriageStore,
  ReportBuilder,
  sanitizeUrlForReport,
  redactAllSecrets,
} from '../../src/shared/reporting';
import type { Finding } from '../../src/shared/types';

describe('Empirical Challenger 2 — Secret Redaction & Incognito Isolation Stress Suite', () => {
  const CANARY_INPUTS = {
    urlCreds: 'http://admin:secret123@target.com/path',
    pathToken: '/reset/abc-123-uuid-456/',
    standardUuidPath: '/reset/550e8400-e29b-41d4-a716-446655440000/',
    jwtToken:
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    urlFragment: 'https://target.com/callback#token=secret_frag_token_123',
    rawFragment: '#token=secret',
    authBearer: 'Authorization: Bearer super_secret_access_token_999',
    authBasic: 'authorization: basic YWRtaW46c2VjcmV0MTIz',
    authProxy: 'Proxy-Authorization: Negotiate secret_kerberos_ticket_000',
    setCookie: 'Set-Cookie: session=CANARY_SESSION_SECRET_777; Path=/; Secure; HttpOnly',
    canaryToken: 'canary_leak_probe_secret_token_888',
  };

  function createFinding(evidence: string, sourceUrl?: string): Finding {
    return {
      ruleId: 'HSTS-001',
      category: 'transport',
      severity: 'high',
      title: 'Missing Strict-Transport-Security Header',
      evidence,
      recommendation: 'Add Strict-Transport-Security: max-age=31536000',
      reference: 'https://example.com',
      sourceUrl: sourceUrl ?? 'https://target.example.com',
    };
  }

  // ─── 1. Secret Redaction Stress Tests ─────────────────────────────────────────

  describe('1. Secret Redaction: Direct Utility Stress Tests', () => {
    it('PASS: redactAllSecrets redacts URL embedded credentials', () => {
      const output = redactAllSecrets(CANARY_INPUTS.urlCreds);
      expect(output).toBe('http://[REDACTED]:[REDACTED]@target.com/path');
      expect(output).not.toContain('secret123');
      expect(output).not.toContain('admin:');
    });

    it('PASS: redactAllSecrets redacts arbitrary path tokens (/reset/abc-123-uuid-456/)', () => {
      const output = redactAllSecrets(CANARY_INPUTS.pathToken);
      expect(output).toBe('/reset/[token]/');
      expect(output).not.toContain('abc-123-uuid-456');
    });

    it('PASS: redactAllSecrets redacts fragments without canary naming pattern (#token=secret)', () => {
      const output = redactAllSecrets(CANARY_INPUTS.rawFragment);
      expect(output).toBe('#[REDACTED]');
      expect(output).not.toContain('secret');
    });

    it('PASS: redactAllSecrets redacts fragment secrets in full URLs', () => {
      const output = redactAllSecrets(CANARY_INPUTS.urlFragment);
      expect(output).toBe('https://target.com/callback#[REDACTED]');
      expect(output).not.toContain('secret_frag_token_123');
    });

    it('PASS: redactAllSecrets successfully redacts JWT tokens', () => {
      const text = `Received header with JWT: ${CANARY_INPUTS.jwtToken} in payload`;
      const output = redactAllSecrets(text);
      expect(output).not.toContain(CANARY_INPUTS.jwtToken);
      expect(output).toContain('[token]');
    });

    it('PASS: redactAllSecrets successfully redacts raw Authorization and Proxy-Authorization headers', () => {
      const bearerOut = redactAllSecrets(CANARY_INPUTS.authBearer);
      expect(bearerOut).not.toContain('super_secret_access_token_999');
      expect(bearerOut).toBe('Authorization: [REDACTED]');

      const basicOut = redactAllSecrets(CANARY_INPUTS.authBasic);
      expect(basicOut).not.toContain('YWRtaW46c2VjcmV0MTIz');
      expect(basicOut).toBe('authorization: [REDACTED]');

      const proxyOut = redactAllSecrets(CANARY_INPUTS.authProxy);
      expect(proxyOut).not.toContain('secret_kerberos_ticket_000');
      expect(proxyOut).toBe('Proxy-Authorization: [REDACTED]');
    });

    it('PASS: redactAllSecrets successfully redacts Set-Cookie lines while preserving flags', () => {
      const output = redactAllSecrets(CANARY_INPUTS.setCookie);
      expect(output).not.toContain('CANARY_SESSION_SECRET_777');
      expect(output).toBe('Set-Cookie: session=[REDACTED]; Path=/; Secure; HttpOnly');
    });

    it('PASS: redactAllSecrets successfully redacts canary tokens matching CANARY_RE', () => {
      const output = redactAllSecrets(CANARY_INPUTS.canaryToken);
      expect(output).not.toContain('canary_leak_probe_secret_token_888');
      expect(output).toBe('[REDACTED]');
    });
  });

  describe('2. Secret Redaction: buildReportDraft Sink Leakage Stress Tests', () => {
    it('PASS: buildReportDraft scrubs URL credentials when present in finding.evidence', () => {
      const finding = createFinding(`Server reflected: ${CANARY_INPUTS.urlCreds}`);
      const draft = ReportBuilder.buildReportDraft(finding);
      const md = ReportBuilder.formatReportAsMarkdown(draft);
      const json = ReportBuilder.formatReportAsJson(draft);

      expect(draft.evidence).not.toContain('secret123');
      expect(draft.evidence).not.toContain('admin:');
      expect(draft.evidence).toContain('http://[REDACTED]:[REDACTED]@target.com/path');
      expect(draft.observedBehavior).not.toContain('secret123');
      expect(draft.reproductionSteps.join('\n')).not.toContain('secret123');
      expect(md).not.toContain('secret123');
      expect(json).not.toContain('secret123');
    });

    it('PASS: buildReportDraft scrubs path tokens when present in finding.evidence', () => {
      const finding = createFinding(`Sensitive endpoint: ${CANARY_INPUTS.pathToken}`);
      const draft = ReportBuilder.buildReportDraft(finding);
      const md = ReportBuilder.formatReportAsMarkdown(draft);
      const json = ReportBuilder.formatReportAsJson(draft);

      expect(draft.evidence).not.toContain('abc-123-uuid-456');
      expect(draft.evidence).toContain('/reset/[token]/');
      expect(draft.observedBehavior).not.toContain('abc-123-uuid-456');
      expect(draft.reproductionSteps.join('\n')).not.toContain('abc-123-uuid-456');
      expect(md).not.toContain('abc-123-uuid-456');
      expect(json).not.toContain('abc-123-uuid-456');
    });

    it('PASS: buildReportDraft scrubs fragment secrets when present in finding.evidence', () => {
      const finding = createFinding(`Redirect target: ${CANARY_INPUTS.urlFragment} or raw ${CANARY_INPUTS.rawFragment}`);
      const draft = ReportBuilder.buildReportDraft(finding);
      const md = ReportBuilder.formatReportAsMarkdown(draft);
      const json = ReportBuilder.formatReportAsJson(draft);

      expect(draft.evidence).not.toContain('secret_frag_token_123');
      expect(draft.evidence).not.toContain('token=secret');
      expect(draft.evidence).toContain('#[REDACTED]');
      expect(md).not.toContain('secret_frag_token_123');
      expect(json).not.toContain('secret_frag_token_123');
    });

    it('PASS: buildReportDraft scrubs credentials, path tokens, and fragments when in targetUrl / sourceUrl', () => {
      // sanitizeUrlForReport is correctly used for target URL
      const finding = createFinding('Clean evidence', 'http://admin:secret123@target.com/reset/abc-123-uuid-456/#token=secret');
      const draft = ReportBuilder.buildReportDraft(finding);

      expect(draft.target).not.toContain('secret123');
      expect(draft.target).not.toContain('admin:');
      expect(draft.target).not.toContain('abc-123-uuid-456');
      expect(draft.target).not.toContain('#');
      expect(draft.target).toBe('http://target.com/reset/[token]/');
    });

    it('PASS: buildReportDraft scrubs JWT, Authorization, Set-Cookie, and canaries from evidence sink', () => {
      const dirtyEvidence = [
        'HTTP/1.1 200 OK',
        CANARY_INPUTS.authBearer,
        CANARY_INPUTS.setCookie,
        `X-Token: ${CANARY_INPUTS.jwtToken}`,
        `Probe: ${CANARY_INPUTS.canaryToken}`,
      ].join('\r\n');

      const finding = createFinding(dirtyEvidence);
      const draft = ReportBuilder.buildReportDraft(finding);
      const md = ReportBuilder.formatReportAsMarkdown(draft);
      const json = ReportBuilder.formatReportAsJson(draft);

      expect(draft.evidence).not.toContain('super_secret_access_token_999');
      expect(draft.evidence).not.toContain('CANARY_SESSION_SECRET_777');
      expect(draft.evidence).not.toContain(CANARY_INPUTS.jwtToken);
      expect(draft.evidence).not.toContain(CANARY_INPUTS.canaryToken);

      expect(md).not.toContain('super_secret_access_token_999');
      expect(json).not.toContain('super_secret_access_token_999');
    });

    it('PASS: sanitizeUrlForReport produces valid URL with single question mark (?) on query strings', () => {
      const raw = 'https://target.com/search?token=secret123&q=query';
      const output = sanitizeUrlForReport(raw);

      expect(output).not.toContain('??');
      expect(output).toBe('https://target.com/search?token=%5BREDACTED%5D&q=query');
    });
  });

  // ─── 3. Incognito Isolation Stress Tests ──────────────────────────────────────

  describe('3. Incognito Isolation: TriageStore Stress Tests', () => {
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

    it('PASS: keeps incognito annotations strictly in memory and zero records written to chrome.storage.local', async () => {
      const findingId = 'INCOG-AUDIT-001';
      const annotation = await TriageStore.setAnnotation(
        findingId,
        'verified-by-researcher',
        'Private session investigation note',
        { isIncognito: true },
      );

      expect(annotation.findingId).toBe(findingId);
      expect(annotation.state).toBe('verified-by-researcher');

      // VERIFIED INVARIANT: zero calls to chrome.storage.local.set
      expect(localStorageSetSpy).not.toHaveBeenCalled();
      expect(Object.keys(mockLocalStorageData)).toHaveLength(0);

      // VERIFIED: retrieved via incognito mode
      const inIncog = await TriageStore.getAnnotation(findingId, { isIncognito: true });
      expect(inIncog).not.toBeNull();
      expect(inIncog?.notes).toBe('Private session investigation note');

      // VERIFIED: non-incognito access sees nothing (isolation barrier intact)
      const inNormal = await TriageStore.getAnnotation(findingId);
      expect(inNormal).toBeNull();
    });

    it('PASS: isolates incognito from persistent annotations in batch queries', async () => {
      await TriageStore.setAnnotation('PERSIST-1', 'unreviewed', 'Public finding note');
      expect(localStorageSetSpy).toHaveBeenCalledTimes(1);

      await TriageStore.setAnnotation('INCOG-1', 'verified-by-researcher', 'Private note 1', { isIncognito: true });
      await TriageStore.setAnnotation('INCOG-2', 'not-a-finding', 'Private note 2', { isIncognito: true });

      // Persistent store still only has 1 record
      expect(localStorageSetSpy).toHaveBeenCalledTimes(1);
      expect(Object.keys(mockLocalStorageData)).toHaveLength(1);

      // Querying incognito returns only incognito
      const incogBatch = await TriageStore.getAnnotations(undefined, { isIncognito: true });
      expect(Object.keys(incogBatch)).toHaveLength(2);
      expect(incogBatch['INCOG-1']).toBeDefined();
      expect(incogBatch['INCOG-2']).toBeDefined();
      expect(incogBatch['PERSIST-1']).toBeUndefined();

      // Querying persistent returns only persistent
      const normalBatch = await TriageStore.getAnnotations(undefined, { isIncognito: false });
      expect(Object.keys(normalBatch)).toHaveLength(1);
      expect(normalBatch['PERSIST-1']).toBeDefined();
      expect(normalBatch['INCOG-1']).toBeUndefined();
    });

    it('PASS: deleteAnnotation with isIncognito: true removes from memory without touching persistent storage', async () => {
      await TriageStore.setAnnotation('INCOG-DEL', 'needs-manual-verification', 'Temp', { isIncognito: true });
      expect(localStorageSetSpy).not.toHaveBeenCalled();

      const deleted = await TriageStore.deleteAnnotation('INCOG-DEL', { isIncognito: true });
      expect(deleted).toBe(true);

      // chrome.storage.local.remove was NOT called
      expect(localStorageRemoveSpy).not.toHaveBeenCalled();
      const check = await TriageStore.getAnnotation('INCOG-DEL', { isIncognito: true });
      expect(check).toBeNull();
    });

    it('PASS: clearAll with isIncognitoOnly: true purges incognito memory while preserving persistent storage', async () => {
      await TriageStore.setAnnotation('KEEP-ME', 'verified-by-researcher', 'Persistent note');
      await TriageStore.setAnnotation('DROP-ME', 'verified-by-researcher', 'Incognito note', { isIncognito: true });

      await TriageStore.clearAll({ isIncognitoOnly: true });

      expect(await TriageStore.getAnnotation('DROP-ME', { isIncognito: true })).toBeNull();
      const preserved = await TriageStore.getAnnotation('KEEP-ME');
      expect(preserved).not.toBeNull();
      expect(preserved?.notes).toBe('Persistent note');
    });

    it('PASS: 100 concurrent asynchronous incognito writes result in ZERO persistent storage operations', async () => {
      const writes = Array.from({ length: 100 }, (_, i) =>
        TriageStore.setAnnotation(
          `CONCURRENT-INCOG-${i}`,
          'verified-by-researcher',
          `Concurrent private test note ${i}`,
          { isIncognito: true },
        ),
      );

      await Promise.all(writes);

      // Invariant: Zero persistent calls or records
      expect(localStorageSetSpy).not.toHaveBeenCalled();
      expect(Object.keys(mockLocalStorageData)).toHaveLength(0);

      const all = await TriageStore.getAnnotations(undefined, { isIncognito: true });
      expect(Object.keys(all)).toHaveLength(100);
      for (let i = 0; i < 100; i++) {
        expect(all[`CONCURRENT-INCOG-${i}`]?.notes).toBe(`Concurrent private test note ${i}`);
      }
    });
  });
});
