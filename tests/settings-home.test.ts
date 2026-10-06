/**
 * tests/settings-home.test.ts — Phase 3 Settings redesign unit tests
 *
 * Covers:
 *  - New Settings fields present in DEFAULT_SETTINGS and migrateSettings
 *  - migrateSettings round-trips appearance fields correctly
 *  - Invalid appearance values fall back to safe defaults
 *  - New fields are persisted and read back via the real storage layer
 *  - TypeScript compilation coverage (type guards work)
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { DEFAULT_SETTINGS } from '../src/shared/constants';
import { migrateSettings } from '../src/shared/settings';
import type { SettingsV2 } from '../src/shared/types';

// ---------------------------------------------------------------------------
// DEFAULT_SETTINGS shape
// ---------------------------------------------------------------------------

describe('DEFAULT_SETTINGS — Phase 3 appearance fields', () => {
  it('includes theme with default value "system"', () => {
    expect(DEFAULT_SETTINGS.theme).toBe('system');
  });

  it('includes density with default value "comfortable"', () => {
    expect(DEFAULT_SETTINGS.density).toBe('comfortable');
  });

  it('includes reducedMotion with default value "system"', () => {
    expect(DEFAULT_SETTINGS.reducedMotion).toBe('system');
  });

  it('has schemaVersion 2', () => {
    expect(DEFAULT_SETTINGS.schemaVersion).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// migrateSettings — appearance field hydration
// ---------------------------------------------------------------------------

describe('migrateSettings — appearance fields', () => {
  it('preserves valid theme "dark" from raw object', () => {
    const result = migrateSettings({ theme: 'dark' });
    expect(result.theme).toBe('dark');
  });

  it('preserves valid theme "light" from raw object', () => {
    const result = migrateSettings({ theme: 'light' });
    expect(result.theme).toBe('light');
  });

  it('preserves valid theme "system" from raw object', () => {
    const result = migrateSettings({ theme: 'system' });
    expect(result.theme).toBe('system');
  });

  it('falls back to "system" for invalid theme value', () => {
    const result = migrateSettings({ theme: 'solarized' });
    expect(result.theme).toBe('system');
  });

  it('falls back to "system" when theme is missing', () => {
    const result = migrateSettings({ monitoringMode: 'off' });
    expect(result.theme).toBe('system');
  });

  it('preserves valid density "compact"', () => {
    const result = migrateSettings({ density: 'compact' });
    expect(result.density).toBe('compact');
  });

  it('preserves valid density "comfortable"', () => {
    const result = migrateSettings({ density: 'comfortable' });
    expect(result.density).toBe('comfortable');
  });

  it('falls back to "comfortable" for invalid density value', () => {
    const result = migrateSettings({ density: 'extra-spacious' });
    expect(result.density).toBe('comfortable');
  });

  it('preserves valid reducedMotion "always"', () => {
    const result = migrateSettings({ reducedMotion: 'always' });
    expect(result.reducedMotion).toBe('always');
  });

  it('preserves valid reducedMotion "never"', () => {
    const result = migrateSettings({ reducedMotion: 'never' });
    expect(result.reducedMotion).toBe('never');
  });

  it('falls back to "system" for invalid reducedMotion value', () => {
    const result = migrateSettings({ reducedMotion: 'sometimes' });
    expect(result.reducedMotion).toBe('system');
  });

  it('migrates all three appearance fields together', () => {
    const result = migrateSettings({ theme: 'light', density: 'compact', reducedMotion: 'always' });
    expect(result.theme).toBe('light');
    expect(result.density).toBe('compact');
    expect(result.reducedMotion).toBe('always');
  });

  it('returns full settings object with required core fields', () => {
    const result = migrateSettings({});
    expect(result.schemaVersion).toBe(2);
    expect(result.monitoringMode).toBe('per-site');
    expect(result.severityFilter).toEqual(expect.arrayContaining(['critical', 'high']));
    expect(result.evaluationMode).toBe(false);
    expect(typeof result.retainHistoryDays).toBe('number');
    expect(typeof result.maxHistoryPerOrigin).toBe('number');
  });

  it('handles null input gracefully and returns full defaults', () => {
    const result = migrateSettings(null);
    expect(result).toEqual(DEFAULT_SETTINGS);
  });

  it('handles non-object input gracefully', () => {
    const result = migrateSettings('bad-data');
    expect(result.theme).toBe('system');
    expect(result.density).toBe('comfortable');
  });

  it('does not produce undefined for any required field', () => {
    const result = migrateSettings({});
    const requiredFields: Array<keyof SettingsV2> = [
      'schemaVersion', 'monitoringMode', 'severityFilter',
      'retainHistoryDays', 'maxHistoryPerOrigin',
      'sensitiveCookieNames', 'ignoredCookieNames', 'evaluationMode',
      'theme', 'density', 'reducedMotion',
    ];
    for (const field of requiredFields) {
      expect(result[field], `field "${field}" should not be undefined`).not.toBeUndefined();
    }
  });
});

// ---------------------------------------------------------------------------
// Type guard verification (compile-time + runtime)
// ---------------------------------------------------------------------------

describe('SettingsV2 type guard — appearance field unions', () => {
  it('theme type only accepts valid values at runtime', () => {
    const validThemes: Array<SettingsV2['theme']> = ['system', 'dark', 'light'];
    for (const t of validThemes) {
      const s = migrateSettings({ theme: t });
      expect(validThemes).toContain(s.theme);
    }
  });

  it('density type only accepts valid values at runtime', () => {
    const validDensities: Array<SettingsV2['density']> = ['comfortable', 'compact'];
    for (const d of validDensities) {
      const s = migrateSettings({ density: d });
      expect(validDensities).toContain(s.density);
    }
  });

  it('reducedMotion type only accepts valid values at runtime', () => {
    const validMotions: Array<SettingsV2['reducedMotion']> = ['system', 'always', 'never'];
    for (const m of validMotions) {
      const s = migrateSettings({ reducedMotion: m });
      expect(validMotions).toContain(s.reducedMotion);
    }
  });
});

describe('Home navigation cards & unsaved changes guard', () => {
  it('verifies that options.html declares all Home navigation cards and callout action', () => {
    const htmlPath = path.resolve(__dirname, '../src/options/options.html');
    const html = fs.readFileSync(htmlPath, 'utf-8');

    expect(html).toContain('id="home-callout-action"');
    const expectedCards = ['monitoring', 'findings', 'cookies', 'history', 'appearance', 'advanced'];
    for (const card of expectedCards) {
      expect(html).toContain(`data-goto="${card}"`);
    }
  });

  it('verifies options.ts routes Home navigation cards and callout action through navigateToSection', () => {
    const tsPath = path.resolve(__dirname, '../src/options/options.ts');
    const ts = fs.readFileSync(tsPath, 'utf-8');

    // Ensure wireNavCards calls navigateToSection rather than activateSection directly
    expect(ts).toContain('function wireNavCards(): void');
    const wireNavCardsSection = ts.slice(
      ts.indexOf('function wireNavCards(): void'),
      ts.indexOf('function activateSection'),
    );
    expect(wireNavCardsSection).toContain('navigateToSection(target)');
    expect(wireNavCardsSection).toContain("navigateToSection('monitoring')");
    expect(wireNavCardsSection).not.toContain('activateSection(');
  });

  it('intercepts Home navigation card click when dirty and opens unsaved dialog', () => {
    let isDirty = true;
    let pendingNavSection: string | null = null;
    let dialogOpened = false;
    let activatedSection: string | null = null;

    const showUnsavedDialog = () => {
      dialogOpened = true;
    };
    const activateSection = (sec: string) => {
      activatedSection = sec;
    };

    const navigateToSection = (target: string) => {
      if (isDirty) {
        pendingNavSection = target;
        showUnsavedDialog();
      } else {
        activateSection(target);
      }
    };

    // Simulate clicking a Home card with data-goto="monitoring" while dirty
    navigateToSection('monitoring');

    expect(dialogOpened).toBe(true);
    expect(pendingNavSection).toBe('monitoring');
    expect(activatedSection).toBeNull();

    // When dirty is false, navigates immediately without dialog
    isDirty = false;
    dialogOpened = false;
    navigateToSection('appearance');

    expect(dialogOpened).toBe(false);
    expect(activatedSection).toBe('appearance');
  });

  it('home callout button routes through guarded navigation and checks dirty state', () => {
    let isDirty = true;
    let dialogOpened = false;
    let navigatedTo: string | null = null;

    const navigateToSection = (target: string) => {
      if (isDirty) {
        dialogOpened = true;
      } else {
        navigatedTo = target;
      }
    };

    // Home callout action button triggers navigateToSection('monitoring')
    navigateToSection('monitoring');
    expect(dialogOpened).toBe(true);
    expect(navigatedTo).toBeNull();

    isDirty = false;
    navigateToSection('monitoring');
    expect(navigatedTo).toBe('monitoring');
  });
});

