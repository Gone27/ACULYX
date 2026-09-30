import { describe, it, expect } from 'vitest';
import {
  detectSensitiveAuthCookie,
  computeFindingChanges,
  checkAuthTransition,
  type AuthBaseline,
} from '../../src/rules/auth-diff';
import type { CookieRecord, Finding } from '../../src/shared/types';

function makeCookie(overrides: Partial<CookieRecord> & { name: string }): CookieRecord {
  const { name, ...rest } = overrides;
  return {
    name,
    domain: 'example.com',
    domainAttributePresent: true,
    path: '/',
    secure: true,
    httpOnly: false,
    sameSite: 'lax',
    session: true,
    expiresAt: null,
    partitioned: false,
    setByJs: false,
    isThirdParty: false,
    ...rest,
  };
}

function makeFinding(ruleId: string, title = 'Sample finding', severity: Finding['severity'] = 'medium'): Finding {
  return {
    ruleId,
    category: 'header',
    severity,
    title,
    evidence: 'test-evidence',
    recommendation: 'Fix it',
    reference: 'https://example.com',
  };
}

describe('Auth Posture Diff — detectSensitiveAuthCookie', () => {
  it('identifies sensitive session cookie', () => {
    const cookies = [
      makeCookie({ name: 'theme', httpOnly: false, session: false }),
      makeCookie({ name: 'session_id', httpOnly: true, session: true }),
    ];
    const detected = detectSensitiveAuthCookie(cookies);
    expect(detected).not.toBeNull();
    expect(detected?.name).toBe('session_id');
  });

  it('rejects consent or analytics cookies even if session-scoped', () => {
    const cookies = [
      makeCookie({ name: 'cookie_consent', httpOnly: false, session: true }),
      makeCookie({ name: '_ga', httpOnly: false, session: true }),
      makeCookie({ name: 'optimizely_session', httpOnly: false, session: true }),
    ];
    expect(detectSensitiveAuthCookie(cookies)).toBeNull();
  });

  it('rejects sensitive name if neither session nor httpOnly', () => {
    // If a cookie is named "token" but persistent and JS-accessible, likely client tracking/state
    const cookies = [
      makeCookie({ name: 'token', httpOnly: false, session: false, expiresAt: Date.now() + 100000 }),
    ];
    expect(detectSensitiveAuthCookie(cookies)).toBeNull();
  });
});

describe('Auth Posture Diff — computeFindingChanges', () => {
  it('correctly categorizes added and removed findings', () => {
    const preFindings = [
      makeFinding('HSTS-001', 'Missing HSTS', 'high'),
      makeFinding('CACHE-001', 'Missing Cache-Control', 'medium'),
    ];
    const postFindings = [
      makeFinding('HSTS-001', 'Missing HSTS', 'high'), // unchanged
      makeFinding('COOK-002', 'HttpOnly missing on session', 'high'), // added
    ];

    const changes = computeFindingChanges(preFindings, postFindings);
    expect(changes).toHaveLength(2);

    const added = changes.find((c) => c.type === 'added');
    expect(added?.ruleId).toBe('COOK-002');

    const removed = changes.find((c) => c.type === 'removed');
    expect(removed?.ruleId).toBe('CACHE-001');
  });
});

describe('Auth Posture Diff — checkAuthTransition', () => {
  const origin = 'https://example.com';

  it('establishes initial baseline on first visit without emitting event', () => {
    const preCookies = [makeCookie({ name: 'theme', httpOnly: false, session: false })];
    const findings = [makeFinding('HSTS-001')];

    const { isAuthEvent, record, newBaseline } = checkAuthTransition(
      origin,
      undefined,
      preCookies,
      findings,
      80,
      'B',
    );

    expect(isAuthEvent).toBe(false);
    expect(record).toBeNull();
    expect(newBaseline.hasSensitiveCookie).toBe(false);
    expect(newBaseline.score).toBe(80);
  });

  it('triggers auth diff when transitioning from pre-auth to post-auth', () => {
    const baseline: AuthBaseline = {
      origin,
      cookies: [makeCookie({ name: 'theme', httpOnly: false, session: false })],
      findings: [makeFinding('HSTS-001')],
      score: 80,
      grade: 'B',
      timestamp: Date.now() - 5000,
      hasSensitiveCookie: false,
    };

    const postCookies = [
      makeCookie({ name: 'theme', httpOnly: false, session: false }),
      makeCookie({ name: 'connect.sid', httpOnly: true, session: true }),
    ];
    const postFindings = [
      makeFinding('HSTS-001'),
      makeFinding('COOK-001', 'Missing Secure flag', 'high'),
    ];

    const { isAuthEvent, record, newBaseline } = checkAuthTransition(
      origin,
      baseline,
      postCookies,
      postFindings,
      60,
      'C',
    );

    expect(isAuthEvent).toBe(true);
    expect(record).not.toBeNull();
    expect(record?.triggeredByCookie).toBe('connect.sid');
    expect(record?.preAuthScore).toBe(80);
    expect(record?.postAuthScore).toBe(60);
    expect(record?.scoreDelta).toBe(-20);
    expect(record?.preAuthGrade).toBe('B');
    expect(record?.postAuthGrade).toBe('C');
    expect(record?.changes).toHaveLength(1);
    expect(record?.changes[0]?.ruleId).toBe('COOK-001');
    expect(record?.changes[0]?.type).toBe('added');
    expect(newBaseline.hasSensitiveCookie).toBe(true);
  });

  it('does NOT trigger repeated auth diff on subsequent hops while logged in', () => {
    const loggedInBaseline: AuthBaseline = {
      origin,
      cookies: [makeCookie({ name: 'connect.sid', httpOnly: true, session: true })],
      findings: [makeFinding('HSTS-001')],
      score: 60,
      grade: 'C',
      timestamp: Date.now() - 2000,
      hasSensitiveCookie: true,
    };

    const currentCookies = [
      makeCookie({ name: 'connect.sid', httpOnly: true, session: true }),
      makeCookie({ name: 'lang', httpOnly: false, session: false }),
    ];

    const { isAuthEvent, record } = checkAuthTransition(
      origin,
      loggedInBaseline,
      currentCookies,
      [makeFinding('HSTS-001')],
      60,
      'C',
    );

    expect(isAuthEvent).toBe(false);
    expect(record).toBeNull();
  });

  it('resets baseline to pre-auth on logout without triggering an auth event', () => {
    const loggedInBaseline: AuthBaseline = {
      origin,
      cookies: [makeCookie({ name: 'connect.sid', httpOnly: true, session: true })],
      findings: [makeFinding('HSTS-001')],
      score: 60,
      grade: 'C',
      timestamp: Date.now() - 2000,
      hasSensitiveCookie: true,
    };

    const loggedOutCookies: CookieRecord[] = [];

    const { isAuthEvent, record, newBaseline } = checkAuthTransition(
      origin,
      loggedInBaseline,
      loggedOutCookies,
      [makeFinding('HSTS-001')],
      80,
      'B',
    );

    expect(isAuthEvent).toBe(false);
    expect(record).toBeNull();
    expect(newBaseline.hasSensitiveCookie).toBe(false);
    expect(newBaseline.score).toBe(80);
  });

  it('persists and hydrates auth baselines via SessionStorage', async () => {
    const { SessionStorage } = await import('../../src/shared/storage');
    const { originAuthBaselines, hydrateFromSession } = await import('../../src/background/lifecycle');

    const storageMock: Record<string, unknown> = {};
    const chromeMock = {
      storage: {
        session: {
          get: (keys: string | string[] | null) => {
            if (keys === null) return Promise.resolve(storageMock);
            if (typeof keys === 'string') return Promise.resolve({ [keys]: storageMock[keys] });
            const res: Record<string, unknown> = {};
            for (const k of keys) res[k] = storageMock[k];
            return Promise.resolve(res);
          },
          set: (items: Record<string, unknown>) => {
            Object.assign(storageMock, items);
            return Promise.resolve();
          },
          remove: (keys: string | string[]) => {
            const list = Array.isArray(keys) ? keys : [keys];
            for (const k of list) delete storageMock[k];
            return Promise.resolve();
          },
        },
      },
    } as unknown as typeof chrome;

    const originalChrome = globalThis.chrome;
    globalThis.chrome = chromeMock;

    try {
      const sampleBaseline: AuthBaseline = {
        origin: 'https://hydrated.example.com',
        cookies: [makeCookie({ name: 'sid', httpOnly: true, session: true })],
        findings: [makeFinding('HSTS-001')],
        score: 75,
        grade: 'B',
        timestamp: Date.now(),
        hasSensitiveCookie: true,
      };

      await SessionStorage.setAuthBaseline('https://hydrated.example.com', sampleBaseline);
      const fetched = await SessionStorage.getAuthBaseline('https://hydrated.example.com');
      expect(fetched).toEqual(sampleBaseline);

      // Verify lifecycle hydration restores into in-memory map
      originAuthBaselines.clear();
      expect(originAuthBaselines.has('https://hydrated.example.com')).toBe(false);

      await hydrateFromSession();
      expect(originAuthBaselines.get('https://hydrated.example.com')).toEqual(sampleBaseline);
    } finally {
      globalThis.chrome = originalChrome;
    }
  });
});
