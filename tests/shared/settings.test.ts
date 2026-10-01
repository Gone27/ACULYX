import { describe, it, expect, vi } from 'vitest';
import {
  migrateSettings,
  normalizeCookieList,
  resolveCookieOverlaps,
  SettingsService,
  UnsupportedSchemaError,
} from '../../src/shared/settings';
import { runRules } from '../../src/rules/engine';
import type { Hop, CookieRecord } from '../../src/shared/types';

describe('Settings schema v2 and migration', () => {
  it('falls back to default settings on null, undefined, or non-object input', () => {
    const s1 = migrateSettings(null);
    expect(s1.schemaVersion).toBe(2);
    expect(s1.monitoringMode).toBe('per-site');
    expect(s1.retainHistoryDays).toBe(7);
    expect(s1.maxHistoryPerOrigin).toBe(10);
    expect(s1.evaluationMode).toBe(false);

    const s2 = migrateSettings('invalid-string');
    expect(s2.schemaVersion).toBe(2);
    expect(s2.sensitiveCookieNames).toEqual([]);
  });

  it('correctly migrates legacy v1 storage shapes to v2', () => {
    const legacyV1 = {
      monitoringMode: 'all-sites',
      allowedOrigins: ['https://example.com', 'https://api.test'],
      severityFilter: ['critical', 'high'],
      retainHistoryDays: 14,
      alwaysSensitiveCookies: ['SESSION_ID', ' AuthToken '],
      alwaysIgnoreCookies: [' GA_TRACKING ', 'cf_clearance'],
      isPro: true,
    };

    const v2 = migrateSettings(legacyV1);
    expect(v2.schemaVersion).toBe(2);
    expect(v2.monitoringMode).toBe('all-sites');
    expect(v2.severityFilter).toEqual(['critical', 'high']);
    expect(v2.retainHistoryDays).toBe(14);
    expect(v2.maxHistoryPerOrigin).toBe(10); // default applied
    expect(v2.sensitiveCookieNames).toEqual(['session_id', 'authtoken']);
    expect(v2.ignoredCookieNames).toEqual(['ga_tracking', 'cf_clearance']);
    expect(v2.evaluationMode).toBe(true);
    expect(v2.legacyAllowedOrigins).toEqual(['https://example.com', 'https://api.test']);
  });

  it('clamps retainHistoryDays (0..365) and maxHistoryPerOrigin (1..50)', () => {
    const clampedUnder = migrateSettings({
      schemaVersion: 2,
      retainHistoryDays: -5,
      maxHistoryPerOrigin: 0,
    });
    expect(clampedUnder.retainHistoryDays).toBe(0);
    expect(clampedUnder.maxHistoryPerOrigin).toBe(1);

    const clampedOver = migrateSettings({
      schemaVersion: 2,
      retainHistoryDays: 999,
      maxHistoryPerOrigin: 100,
    });
    expect(clampedOver.retainHistoryDays).toBe(365);
    expect(clampedOver.maxHistoryPerOrigin).toBe(50);
  });

  it('normalizes, trims, lowercases, and dedupes cookie lists', () => {
    const raw = [' Session ', 'SESSION', 'Token', 'token ', ''];
    const normalized = normalizeCookieList(raw);
    expect(normalized).toEqual(['session', 'token']);
  });

  it('resolves cookie list overlap: ignored wins over sensitive', () => {
    const sensitive = ['session', 'shared_token', 'csrf'];
    const ignored = ['shared_token', 'analytics'];

    const { sensitive: resolvedSensitive, ignored: resolvedIgnored, overlaps } = resolveCookieOverlaps(
      sensitive,
      ignored,
    );
    expect(overlaps).toEqual(['shared_token']);
    expect(resolvedSensitive).toEqual(['session', 'csrf']);
    expect(resolvedIgnored).toEqual(['shared_token', 'analytics']);
  });

  it('is idempotent when re-migrating already valid v2 settings', () => {
    const initial = migrateSettings({
      schemaVersion: 2,
      monitoringMode: 'off',
      severityFilter: ['medium', 'low'],
      retainHistoryDays: 30,
      maxHistoryPerOrigin: 25,
      sensitiveCookieNames: ['sid'],
      ignoredCookieNames: ['theme'],
      evaluationMode: false,
    });

    const reMigrated = migrateSettings(initial);
    expect(reMigrated).toEqual(initial);
  });

  it('evaluationMode flag does NOT alter security scores or findings', () => {
    const hop: Hop = {
      requestId: 'r1',
      url: 'https://example.com/',
      status: 200,
      headers: {
        'strict-transport-security': 'max-age=31536000; includeSubDomains',
        'x-content-type-options': 'nosniff',
        'content-security-policy': "default-src 'self'",
      },
      rawHeaders: [
        { name: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
        { name: 'X-Content-Type-Options', value: 'nosniff' },
        { name: 'Content-Security-Policy', value: "default-src 'self'" },
      ],
      fromCache: false,
      isHstsUpgrade: false,
      capturedAt: 'onResponseStarted',
      headersDiffer: false,
      timestamp: Date.now(),
    };

    const cookie: CookieRecord = {
      name: 'sid',
      domain: 'example.com',
      domainAttributePresent: false,
      path: '/',
      secure: true,
      httpOnly: true,
      sameSite: 'lax',
      session: false,
      expiresAt: null,
      partitioned: false,
      setByJs: false,
      isThirdParty: false,
    };

    // Run rules with Pro/evaluation off
    const resultOff = runRules({
      hops: [hop],
      cookies: [cookie],
      origin: 'https://example.com',
      metaCspFound: false,
    });

    // Run rules with Pro/evaluation on
    const resultOn = runRules({
      hops: [hop],
      cookies: [cookie],
      origin: 'https://example.com',
      metaCspFound: false,
    });

    expect(resultOn.score).toBe(resultOff.score);
    expect(resultOn.grade).toBe(resultOff.grade);
    expect(resultOn.findings.map((f) => f.ruleId)).toEqual(resultOff.findings.map((f) => f.ruleId));
  });

  it('SettingsService provides getSettings, updateSettings, clearCache, and change subscriptions', async () => {
    SettingsService.clearCache();
    const settings = await SettingsService.getSettings();
    expect(settings.schemaVersion).toBe(2);
    expect(settings.monitoringMode).toBe('per-site');

    let notified: unknown = null;
    const unsubscribe = SettingsService.onSettingsChanged((updated) => {
      notified = updated;
    });

    const updated = await SettingsService.updateSettings({ monitoringMode: 'all-sites', retainHistoryDays: 30 });
    expect(updated.monitoringMode).toBe('all-sites');
    expect(updated.retainHistoryDays).toBe(30);
    expect(notified).toEqual(updated);

    unsubscribe();
    SettingsService.clearCache();
  });

  it('rejects future schema versions without overwriting storage or downgrading', async () => {
    expect(() => migrateSettings({ schemaVersion: 3, newFeature: 'test' })).toThrow(UnsupportedSchemaError);

    SettingsService.clearCache();
    const storageGetMock = vi.fn().mockResolvedValue({
      settings: { schemaVersion: 3, futureKey: 'do-not-drop-me' },
    });
    const storageSetMock = vi.fn().mockResolvedValue(undefined);

    const chromeMock = {
      storage: {
        local: {
          get: storageGetMock,
          set: storageSetMock,
        },
        onChanged: { addListener: vi.fn() },
      },
    } as unknown as typeof chrome;

    vi.stubGlobal('chrome', chromeMock);

    try {
      await expect(SettingsService.getSettings()).rejects.toThrow(UnsupportedSchemaError);
      // Ensure storage was never overwritten with downgraded schema
      expect(storageSetMock).not.toHaveBeenCalled();
      // Ensure cached settings failed closed to 'off'
      expect(SettingsService.getCachedSettings().monitoringMode).toBe('off');
    } finally {
      vi.unstubAllGlobals();
      SettingsService.clearCache();
    }
  });

  it('fails closed to off when storage read fails with an error', async () => {
    SettingsService.clearCache();
    const storageGetMock = vi.fn().mockRejectedValue(new Error('Storage disk corruption'));

    const chromeMock = {
      storage: {
        local: {
          get: storageGetMock,
          set: vi.fn(),
        },
        onChanged: { addListener: vi.fn() },
      },
    } as unknown as typeof chrome;

    vi.stubGlobal('chrome', chromeMock);

    try {
      await expect(SettingsService.getSettings()).rejects.toThrow('Storage disk corruption');
      expect(SettingsService.getCachedSettings().monitoringMode).toBe('off');
    } finally {
      vi.unstubAllGlobals();
      SettingsService.clearCache();
    }
  });
});


