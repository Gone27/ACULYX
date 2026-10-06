import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  sanitizeUrlForStorage,
  sanitizeCspPolicyForStorage,
  redactUrlPath,
} from '../../src/rules/utils';
import {
  assertNoSensitiveSecrets,
  SessionStorage,
} from '../../src/shared/storage';
import {
  exportJsonReport,
  exportMarkdownReport,
  exportSarifReport,
  generateSarif,
} from '../../src/shared/export';
import type { TabState } from '../../src/shared/types';

describe('Production Canary Leak Prevention Integration Tests', () => {
  const CANARY_UUID = '550e8400-e29b-41d4-a716-446655440000';
  const CANARY_JWT =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const CANARY_HEX = '4a8f9c2d1e0b3a7f8e9d0c1b2a3f4e5d';
  const CANARY_QUERY_PARAM = 'secret_canary_query_token_99999';
  const CANARY_CREDENTIALS = 'canary_user:canary_pass_88888';

  const URL_UUID = `https://example.com/worker/${CANARY_UUID}.js`;
  const URL_JWT = `https://example.com/api/${CANARY_JWT}`;
  const URL_HEX = `https://example.com/sw/${CANARY_HEX}.js`;
  const URL_QUERY = `https://example.com/sw.js?token=${CANARY_QUERY_PARAM}`;
  const URL_CREDS = `https://${CANARY_CREDENTIALS}@example.com/sw.js`;

  const CSP_UUID = `default-src 'self'; report-uri https://example.com/worker/${CANARY_UUID}.js`;
  const CSP_JWT = `default-src 'self'; report-uri https://example.com/api/${CANARY_JWT}`;
  const CSP_HEX = `default-src 'self'; report-uri https://example.com/sw/${CANARY_HEX}.js`;
  const CSP_QUERY = `default-src 'self'; report-uri https://example.com/report?session=${CANARY_QUERY_PARAM}`;
  const CSP_CREDS = `default-src 'self'; report-uri https://${CANARY_CREDENTIALS}@example.com/report`;

  const createCleanTabState = (): TabState => ({
    tabId: 42,
    origin: 'https://example.com',
    url: 'https://example.com/app',
    hops: [
      {
        requestId: 'hop-1',
        url: 'https://example.com/app',
        status: 200,
        headers: {
          'set-cookie': 'session=[REDACTED]; Path=/; Secure; HttpOnly',
        },
        rawHeaders: [
          { name: 'Set-Cookie', value: 'session=[REDACTED]; Path=/; Secure; HttpOnly' },
        ],
        fromCache: false,
        isHstsUpgrade: false,
        capturedAt: 'onResponseStarted',
        headersDiffer: false,
        timestamp: Date.now(),
      },
    ],
    cookies: [
      {
        name: 'session',
        domain: 'example.com',
        path: '/',
        secure: true,
        httpOnly: true,
        sameSite: 'strict',
        session: true,
        expiresAt: null,
        partitioned: false,
        setByJs: false,
        isThirdParty: false,
        domainAttributePresent: true,
      },
    ],
    findings: [
      {
        ruleId: 'SEC-001',
        title: 'Sample Security Finding',
        severity: 'medium',
        category: 'header',
        impact: 'Potential exposure',
        evidence: 'Sample evidence',
        recommendation: 'Configure securely',
        reference: 'https://example.com/docs',
      },
    ],
    grade: 'A',
    score: 92,
    qualityScore: 88,
    qualityGrade: 'B',
    scoreVersion: '2.0.0',
    scoreBreakdown: [],
    coverage: {
      hopsExpected: 1,
      hopsCaptured: 1,
      hasCache: false,
      hasServiceWorker: true,
      serviceWorkerStatus: 'controlled',
      serviceWorkerUrl: 'https://example.com/sw.js',
      isRestricted: false,
      metaCspFound: true,
      metaCspPolicies: ["default-src 'self'; report-uri https://example.com/report"],
    },
    subdomainTrust: { hasEscalationPath: false, vectors: [] },
    monitoredByUser: true,
    updatedAt: Date.now(),
  });

  describe('TASK 1: Robust URL & Path Token Redactor in utils.ts', () => {
    it('redacts UUIDs to [id]', () => {
      expect(redactUrlPath(`/worker/${CANARY_UUID}.js`)).toBe('/worker/[id]');
      expect(redactUrlPath(`/items/${CANARY_UUID}`)).toBe('/items/[id]');
    });

    it('redacts JWTs to [token]', () => {
      expect(redactUrlPath(`/api/${CANARY_JWT}`)).toBe('/api/[token]');
      expect(redactUrlPath(CANARY_JWT)).toBe('[token]');
    });

    it('redacts 16+ hex characters and 20+ base64/alphanumeric tokens to [token]', () => {
      expect(redactUrlPath(`/sw/${CANARY_HEX}.js`)).toBe('/sw/[token]');
      expect(redactUrlPath('/token/abcdef0123456789')).toBe('/token/[token]');
      expect(redactUrlPath('/hash/a1b2c3d4e5f60718293a4b5c6d7e8f90')).toBe('/hash/[token]');
    });

    it('redacts path segments following sensitive keywords to [token]', () => {
      const keywords = ['reset', 'token', 'verify', 'auth', 'confirm', 'code', 'session', 'credential'];
      for (const kw of keywords) {
        expect(redactUrlPath(`/${kw}/mySecretSecret1`)).toBe(`/${kw}/[token]`);
      }
    });

    it('sanitizeUrlForStorage strips query string, fragment, credentials, and redacts path tokens', () => {
      expect(sanitizeUrlForStorage('')).toBe('');
      expect(sanitizeUrlForStorage(null as unknown as string)).toBe('');
      expect(sanitizeUrlForStorage(URL_QUERY)).toBe('https://example.com/sw.js');
      expect(sanitizeUrlForStorage(URL_CREDS)).toBe('https://example.com/sw.js');
      expect(sanitizeUrlForStorage(URL_UUID)).toBe('https://example.com/worker/[id]');
      expect(sanitizeUrlForStorage(URL_JWT)).toBe('https://example.com/api/[token]');
      expect(sanitizeUrlForStorage(URL_HEX)).toBe('https://example.com/sw/[token]');
      expect(sanitizeUrlForStorage(`/worker/${CANARY_UUID}.js?param=1#frag`)).toBe('/worker/[id]');
    });

    it('sanitizeCspPolicyForStorage cleans report-uri and report-to directives', () => {
      expect(sanitizeCspPolicyForStorage(CSP_QUERY)).toBe(
        "default-src 'self'; report-uri https://example.com/report"
      );
      expect(sanitizeCspPolicyForStorage(CSP_CREDS)).toBe(
        "default-src 'self'; report-uri https://example.com/report"
      );
      expect(sanitizeCspPolicyForStorage(CSP_UUID)).toBe(
        "default-src 'self'; report-uri https://example.com/worker/[id]"
      );
      expect(sanitizeCspPolicyForStorage(CSP_JWT)).toBe(
        "default-src 'self'; report-uri https://example.com/api/[token]"
      );
      expect(sanitizeCspPolicyForStorage(CSP_HEX)).toBe(
        "default-src 'self'; report-uri https://example.com/sw/[token]"
      );
    });
  });

  describe('TASK 2: Secret Storage Guard in storage.ts', () => {
    it('assertNoSensitiveSecrets throws when serviceWorkerUrl contains unredacted canaries', () => {
      const cases = [
        { label: 'UUID path', url: URL_UUID, pattern: /Unredacted sensitive token\/path/ },
        { label: 'JWT path', url: URL_JWT, pattern: /Unredacted sensitive token\/path/ },
        { label: '32-char hex', url: URL_HEX, pattern: /Unredacted sensitive token\/path/ },
        { label: 'query string', url: URL_QUERY, pattern: /Unredacted query string/ },
        { label: 'credentials', url: URL_CREDS, pattern: /Unredacted credentials/ },
      ];

      for (const { label, url, pattern } of cases) {
        const state = createCleanTabState();
        state.coverage.serviceWorkerUrl = url;
        expect(() => assertNoSensitiveSecrets(state), `Failed for ${label}`).toThrowError(pattern);
      }
    });

    it('assertNoSensitiveSecrets throws when metaCspPolicies contains unredacted canaries', () => {
      const cases = [
        { label: 'UUID CSP', policy: CSP_UUID, pattern: /Unredacted sensitive token\/path/ },
        { label: 'JWT CSP', policy: CSP_JWT, pattern: /Unredacted sensitive token\/path/ },
        { label: '32-char hex CSP', policy: CSP_HEX, pattern: /Unredacted sensitive token\/path/ },
        { label: 'query CSP', policy: CSP_QUERY, pattern: /Unredacted query string/ },
        { label: 'credentials CSP', policy: CSP_CREDS, pattern: /Unredacted credentials/ },
      ];

      for (const { label, policy, pattern } of cases) {
        const state = createCleanTabState();
        state.coverage.metaCspPolicies = [policy];
        expect(() => assertNoSensitiveSecrets(state), `Failed for ${label}`).toThrowError(pattern);
      }
    });

    it('passes assertNoSensitiveSecrets after applying sanitizeUrlForStorage and sanitizeCspPolicyForStorage', () => {
      const state = createCleanTabState();
      state.coverage.serviceWorkerUrl = sanitizeUrlForStorage(URL_UUID);
      state.coverage.metaCspPolicies = [
        sanitizeCspPolicyForStorage(CSP_QUERY),
        sanitizeCspPolicyForStorage(CSP_UUID),
      ];

      expect(() => assertNoSensitiveSecrets(state)).not.toThrow();
    });
  });

  describe('TASK 2 & SessionStorage: Rejection of unredacted state and success of sanitized state', () => {
    let mockSessionStore: Record<string, unknown> = {};

    beforeEach(() => {
      mockSessionStore = {};
      (globalThis as unknown as { chrome: unknown }).chrome = {
        storage: {
          session: {
            get: vi.fn((keys: unknown) => {
              if (keys === null) return Promise.resolve({ ...mockSessionStore });
              if (typeof keys === 'string') return Promise.resolve({ [keys]: mockSessionStore[keys] });
              return Promise.resolve({});
            }),
            set: vi.fn((items: Record<string, unknown>) => {
              Object.assign(mockSessionStore, items);
              return Promise.resolve();
            }),
            remove: vi.fn((keys: string | string[]) => {
              const list = Array.isArray(keys) ? keys : [keys];
              for (const k of list) delete mockSessionStore[k];
              return Promise.resolve();
            }),
          },
        },
      };
    });

    it('SessionStorage.setTabState rejects unredacted canary states and succeeds with sanitized states', async () => {
      const unredactedState = createCleanTabState();
      unredactedState.coverage.serviceWorkerUrl = URL_HEX;

      await expect(SessionStorage.setTabState(unredactedState)).rejects.toThrowError(
        /Unredacted sensitive token\/path detected in serviceWorkerUrl/
      );

      // Sanitize the state and verify setTabState now succeeds
      const sanitizedState = createCleanTabState();
      sanitizedState.coverage.serviceWorkerUrl = sanitizeUrlForStorage(URL_HEX);
      sanitizedState.coverage.metaCspPolicies = [sanitizeCspPolicyForStorage(CSP_QUERY)];

      await expect(SessionStorage.setTabState(sanitizedState)).resolves.toBeUndefined();
    });
  });

  describe('TASK 3: Redaction in Export Sinks (SARIF, JSON, Markdown)', () => {
    it('ensures SARIF, JSON, and Markdown exports contain ZERO unredacted canaries', () => {
      // Build a state that contains all raw canary secrets in serviceWorkerUrl and metaCspPolicies
      const leakyState = createCleanTabState();
      leakyState.coverage.serviceWorkerUrl = URL_UUID;
      leakyState.coverage.metaCspPolicies = [
        CSP_QUERY,
        CSP_JWT,
        CSP_HEX,
        CSP_CREDS,
      ];

      // Generate reports using production export modules
      const jsonReport = exportJsonReport(leakyState);
      const markdownReport = exportMarkdownReport(leakyState);
      const sarifReport = exportSarifReport(leakyState);
      const sarifLog = generateSarif(leakyState);
      const sarifLogJson = JSON.stringify(sarifLog);

      const allExports = [
        { format: 'JSON', content: jsonReport },
        { format: 'Markdown', content: markdownReport },
        { format: 'SARIF (string)', content: sarifReport },
        { format: 'SARIF (object)', content: sarifLogJson },
      ];

      const canarySecrets = [
        { name: 'UUID canary', secret: CANARY_UUID },
        { name: 'JWT canary', secret: CANARY_JWT },
        { name: 'Hex token canary', secret: CANARY_HEX },
        { name: 'Query param canary', secret: CANARY_QUERY_PARAM },
        { name: 'Credentials canary', secret: CANARY_CREDENTIALS },
      ];

      for (const { format, content } of allExports) {
        for (const { name, secret } of canarySecrets) {
          expect(
            content.includes(secret),
            `Leak detected! ${format} export contains ${name} (${secret})`
          ).toBe(false);
        }
      }
    });
  });

  describe('P1 URL Query Redaction & Arbitrary Query Secrets Containment', () => {
    const OAUTH_URL =
      'https://example.com/oauth/callback?state=csrf-canary-secret&email=private%40example.com&custom_auth_token=super_secret_opaque_token_12345&session_token=secret_session';
    const OAUTH_STATE_SECRET = 'csrf-canary-secret';
    const OAUTH_EMAIL_SECRET = 'private@example.com';
    const OAUTH_EMAIL_ENCODED = 'private%40example.com';
    const CUSTOM_TOKEN_SECRET = 'super_secret_opaque_token_12345';
    const CUSTOM_TOKEN_KEY = 'custom_auth_token';

    it('sanitizeUrlForStorage completely strips OAuth state, email, custom token, and query params', () => {
      const sanitized = sanitizeUrlForStorage(OAUTH_URL);

      expect(sanitized).toBe('https://example.com/oauth/callback');
      expect(sanitized.includes('?')).toBe(false);
      expect(sanitized.includes('#')).toBe(false);
      expect(sanitized.includes(OAUTH_STATE_SECRET)).toBe(false);
      expect(sanitized.includes(OAUTH_EMAIL_SECRET)).toBe(false);
      expect(sanitized.includes(OAUTH_EMAIL_ENCODED)).toBe(false);
      expect(sanitized.includes(CUSTOM_TOKEN_SECRET)).toBe(false);
      expect(sanitized.includes(CUSTOM_TOKEN_KEY)).toBe(false);
    });

    it('assertNoSensitiveSecrets aborts on arbitrary unredacted query parameters in state.url or hops', () => {
      const stateWithQuery = createCleanTabState();
      stateWithQuery.url = OAUTH_URL;

      expect(() => assertNoSensitiveSecrets(stateWithQuery)).toThrowError(
        /Unredacted query string detected in state.url — storage aborted./,
      );

      const stateWithHopQuery = createCleanTabState();
      const firstHop = stateWithHopQuery.hops[0];
      if (firstHop !== undefined) {
        firstHop.url = `https://api.example.com/data?email=${OAUTH_EMAIL_ENCODED}`;
      }

      expect(() => assertNoSensitiveSecrets(stateWithHopQuery)).toThrowError(
        /Unredacted query string detected in hop\[0\].url — storage aborted./,
      );
    });

    it('assertNoSensitiveSecrets succeeds when URLs are processed via sanitizeUrlForStorage', () => {
      const cleanState = createCleanTabState();
      cleanState.url = sanitizeUrlForStorage(OAUTH_URL);
      const cleanHop = cleanState.hops[0];
      if (cleanHop !== undefined) {
        cleanHop.url = sanitizeUrlForStorage(`https://api.example.com/data?state=${OAUTH_STATE_SECRET}&token=test`);
      }

      expect(() => assertNoSensitiveSecrets(cleanState)).not.toThrow();
      expect(cleanState.url).toBe('https://example.com/oauth/callback');
      expect(cleanHop?.url).toBe('https://api.example.com/data');
    });

    it('guarantees zero OAuth state, email/PII, or custom token query secrets in exports', () => {
      const state = createCleanTabState();
      state.url = sanitizeUrlForStorage(OAUTH_URL);
      const stateHop = state.hops[0];
      if (stateHop !== undefined) {
        stateHop.url = sanitizeUrlForStorage(`https://api.example.com/data?state=${OAUTH_STATE_SECRET}`);
      }

      const json = exportJsonReport(state);
      const md = exportMarkdownReport(state);
      const sarif = exportSarifReport(state);

      const canaries: Array<[string, string]> = [
        ['OAuth state secret', OAUTH_STATE_SECRET],
        ['OAuth email secret', OAUTH_EMAIL_SECRET],
        ['OAuth email encoded', OAUTH_EMAIL_ENCODED],
        ['Custom token secret', CUSTOM_TOKEN_SECRET],
      ];

      for (const [name, secret] of canaries) {
        expect(json.includes(secret), `JSON leak of ${name}`).toBe(false);
        expect(md.includes(secret), `MD leak of ${name}`).toBe(false);
        expect(sarif.includes(secret), `SARIF leak of ${name}`).toBe(false);
      }
    });
  });
});
