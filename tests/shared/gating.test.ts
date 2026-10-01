import { describe, it, expect } from 'vitest';
import { isModeCaptureAllowed, isRestrictedUrl } from '../../src/shared/gating';
import { DEFAULT_SETTINGS } from '../../src/shared/constants';
import type { SettingsV2 } from '../../src/shared/types';

describe('isRestrictedUrl', () => {
  it('identifies blank and invalid URLs as restricted', () => {
    expect(isRestrictedUrl('')).toBe(true);
    expect(isRestrictedUrl('   ')).toBe(true);
  });

  it('identifies internal browser schemes as restricted', () => {
    expect(isRestrictedUrl('chrome://settings')).toBe(true);
    expect(isRestrictedUrl('chrome-extension://abcdef/popup.html')).toBe(true);
    expect(isRestrictedUrl('edge://flags')).toBe(true);
    expect(isRestrictedUrl('devtools://devtools/bundled/inspector.html')).toBe(true);
    expect(isRestrictedUrl('about:blank')).toBe(true);
    expect(isRestrictedUrl('about:config')).toBe(true);
    expect(isRestrictedUrl('data:text/html,<h1>Hello</h1>')).toBe(true);
    expect(isRestrictedUrl('blob:https://example.com/uuid')).toBe(true);
    expect(isRestrictedUrl('view-source:https://example.com/')).toBe(true);
  });

  it('identifies browser web stores as restricted', () => {
    expect(isRestrictedUrl('https://chromewebstore.google.com/detail/xyz')).toBe(true);
    expect(isRestrictedUrl('https://chrome.google.com/webstore/detail/xyz')).toBe(true);
    expect(isRestrictedUrl('https://addons.mozilla.org/en-US/firefox/addon/xyz/')).toBe(true);
  });

  it('treats file: URLs as restricted unless fileAccessAllowed is true', () => {
    expect(isRestrictedUrl('file:///C:/path/file.html')).toBe(true);
    expect(isRestrictedUrl('file:///C:/path/file.html', { fileAccessAllowed: false })).toBe(true);
    expect(isRestrictedUrl('file:///C:/path/file.html', { fileAccessAllowed: true })).toBe(false);
  });

  it('allows normal web URLs', () => {
    expect(isRestrictedUrl('https://example.com/')).toBe(false);
    expect(isRestrictedUrl('http://localhost:3000/api')).toBe(false);
    expect(isRestrictedUrl('https://sub.domain.org/path?q=1')).toBe(false);
  });
});

describe('isModeCaptureAllowed', () => {
  const baseSettings: SettingsV2 = {
    ...DEFAULT_SETTINGS,
    monitoringMode: 'per-site',
  };

  it('blocks restricted URLs with reason restricted-url', () => {
    const res = isModeCaptureAllowed('chrome://extensions', baseSettings, false);
    expect(res).toEqual({ allowed: false, reason: 'restricted-url' });
  });

  it('blocks all capture when mode is off with reason off', () => {
    const offSettings: SettingsV2 = { ...baseSettings, monitoringMode: 'off' };
    const res = isModeCaptureAllowed('https://example.com/', offSettings, false);
    expect(res).toEqual({ allowed: false, reason: 'off' });

    // Even if broad grant is present, off still halts capture
    const resWithBroad = isModeCaptureAllowed('https://example.com/', offSettings, true);
    expect(resWithBroad).toEqual({ allowed: false, reason: 'off' });
  });

  it('flags broad-access-conflict when per-site mode has broadGrantPresent', () => {
    const perSiteSettings: SettingsV2 = { ...baseSettings, monitoringMode: 'per-site' };
    const conflictRes = isModeCaptureAllowed('https://example.com/', perSiteSettings, true);
    expect(conflictRes).toEqual({ allowed: false, reason: 'broad-access-conflict' });

    const okRes = isModeCaptureAllowed('https://example.com/', perSiteSettings, false);
    expect(okRes).toEqual({ allowed: true, reason: 'ok' });
  });

  it('allows capture under all-sites mode regardless of broadGrantPresent flag', () => {
    const allSitesSettings: SettingsV2 = { ...baseSettings, monitoringMode: 'all-sites' };
    const res1 = isModeCaptureAllowed('https://example.com/', allSitesSettings, true);
    expect(res1).toEqual({ allowed: true, reason: 'ok' });

    const res2 = isModeCaptureAllowed('https://example.com/', allSitesSettings, false);
    expect(res2).toEqual({ allowed: true, reason: 'ok' });
  });

  it('remains invariant under evaluationMode and presentation settings', () => {
    const s1: SettingsV2 = {
      ...baseSettings,
      evaluationMode: false,
      severityFilter: ['critical'],
    };
    const s2: SettingsV2 = {
      ...baseSettings,
      evaluationMode: true,
      severityFilter: ['low', 'info'],
    };

    expect(isModeCaptureAllowed('https://example.com/', s1, false))
      .toEqual(isModeCaptureAllowed('https://example.com/', s2, false));
    expect(isModeCaptureAllowed('https://example.com/', s1, true))
      .toEqual(isModeCaptureAllowed('https://example.com/', s2, true));
  });
});
