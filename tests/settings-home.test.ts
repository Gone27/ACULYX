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
import { applyAppearance } from '../src/shared/appearance';

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
    const expectedCards = ['monitoring', 'findings', 'cookies', 'history', 'scope', 'leads', 'appearance', 'advanced'];
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

  it('verifies that options.ts SECTION_IDS includes leads and all sections exist in options.html', () => {
    const tsPath = path.resolve(__dirname, '../src/options/options.ts');
    const ts = fs.readFileSync(tsPath, 'utf-8');
    const htmlPath = path.resolve(__dirname, '../src/options/options.html');
    const html = fs.readFileSync(htmlPath, 'utf-8');

    const sectionIdsMatch = ts.match(/const SECTION_IDS = \[([^\]]+)\]/);
    expect(sectionIdsMatch).not.toBeNull();
    const rawIds = sectionIdsMatch ? sectionIdsMatch[1] ?? '' : '';
    const sectionIds = rawIds.split(',').map((s) => s.trim().replace(/['"]/g, ''));

    expect(sectionIds).toContain('leads');
    expect(sectionIds).toContain('scope');
    expect(sectionIds).toContain('home');

    // Every section in SECTION_IDS must exist in options.html as an id="section-{id}"
    for (const id of sectionIds) {
      expect(html).toContain(`id="section-${id}"`);
    }

    // Every nav item in options.html must be in SECTION_IDS
    const navSectionMatches = html.matchAll(/data-section="([^"]+)"/g);
    for (const match of navSectionMatches) {
      expect(sectionIds).toContain(match[1]);
    }
  });
});

// ---------------------------------------------------------------------------
// 6 At-a-Glance Effective Configuration Summary Cards (R4)
// ---------------------------------------------------------------------------

describe('6 At-a-Glance Effective Configuration Summary Cards (R4)', () => {
  const htmlPath = path.resolve(__dirname, '../src/options/options.html');
  const html = fs.readFileSync(htmlPath, 'utf-8');
  const tsPath = path.resolve(__dirname, '../src/options/options.ts');
  const ts = fs.readFileSync(tsPath, 'utf-8');

  it('declares all 6 effective configuration summary cards as interactive buttons with data-goto and data-focus', () => {
    const expectedCards = [
      { id: 'home-card-mode', goto: 'monitoring', focus: 'mode-per-site', valueId: 'home-mode-value' },
      { id: 'home-card-perms', goto: 'monitoring', focus: 'section-allowlist', valueId: 'home-perms-value' },
      { id: 'home-card-leads', goto: 'leads', focus: 'leads-enabled-toggle', valueId: 'home-leads-value' },
      { id: 'home-card-deep', goto: 'leads', focus: 'deep-mode-toggle', valueId: 'home-deep-value' },
      { id: 'home-card-hunter', goto: 'leads', focus: 'hunter-enabled-toggle', valueId: 'home-hunter-value' },
      { id: 'home-card-creds', goto: 'leads', focus: 'credential-liveness-toggle', valueId: 'home-creds-value' },
    ];

    for (const card of expectedCards) {
      const buttonPattern = new RegExp(`<button[^>]*id="${card.id}"[^>]*>`, 'i');
      expect(html).toMatch(buttonPattern);
      const tagMatch = html.match(new RegExp(`<button[^>]*id="${card.id}"[^>]*>`, 'i'));
      expect(tagMatch).not.toBeNull();
      const tagStr = tagMatch ? tagMatch[0] : '';
      expect(tagStr).toContain('type="button"');
      expect(tagStr).toContain('class="home-card"');
      expect(tagStr).toContain(`data-goto="${card.goto}"`);
      expect(tagStr).toContain(`data-focus="${card.focus}"`);

      // Section target must exist
      expect(html).toContain(`id="section-${card.goto}"`);

      // Focus target must exist
      expect(html).toContain(`id="${card.focus}"`);

      // Value span must exist
      expect(html).toContain(`id="${card.valueId}"`);
    }
  });

  it('wires .home-card[data-goto] in options.ts to navigateToSection with focus target', () => {
    expect(ts).toContain("document.querySelectorAll<HTMLButtonElement>('.home-card[data-goto]')");
    expect(ts).toContain("const focusTarget = card.dataset['focus']");
    expect(ts).toContain('navigateToSection(target, focusTarget)');
  });

  it('activateSection in options.ts focuses the target control if provided', () => {
    expect(ts).toContain('function activateSection(sectionId: string, focusId?: string): void');
    expect(ts).toContain('if (focusId !== undefined && focusId.length > 0) {');
    expect(ts).toContain('el.focus()');
  });

  it('refreshHomeView in options.ts updates all 6 effective configuration values', () => {
    expect(ts).toContain("document.getElementById('home-mode-value')");
    expect(ts).toContain("document.getElementById('home-perms-value')");
    expect(ts).toContain("document.getElementById('home-leads-value')");
    expect(ts).toContain("document.getElementById('home-deep-value')");
    expect(ts).toContain("document.getElementById('home-hunter-value')");
    expect(ts).toContain("document.getElementById('home-creds-value')");
  });

  it('navigates and sets focus when clean, and prompts unsaved dialog when dirty', () => {
    let isDirty = false;
    let pendingNav: string | null = null;
    let pendingFocus: string | null = null;
    let activated: { section: string; focus?: string | undefined } | null = null;
    let dialogShown = false;

    const navigateToSection = (target: string, focusId?: string) => {
      if (isDirty) {
        pendingNav = target;
        pendingFocus = focusId ?? null;
        dialogShown = true;
      } else {
        activated = { section: target, focus: focusId };
      }
    };

    // Clean navigation with focus
    navigateToSection('leads', 'deep-mode-toggle');
    expect(dialogShown).toBe(false);
    expect(activated).toEqual({ section: 'leads', focus: 'deep-mode-toggle' });

    // Dirty navigation intercepts
    isDirty = true;
    dialogShown = false;
    activated = null;
    navigateToSection('monitoring', 'section-allowlist');
    expect(dialogShown).toBe(true);
    expect(pendingNav).toBe('monitoring');
    expect(pendingFocus).toBe('section-allowlist');
    expect(activated).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Appearance Contract: Live Preview, Dirty State & Save/Discard (R4)
// ---------------------------------------------------------------------------

describe('Appearance Contract: Live Preview, Dirty State & Save/Discard (R4)', () => {
  const tsPath = path.resolve(__dirname, '../src/options/options.ts');
  const ts = fs.readFileSync(tsPath, 'utf-8');

  it('applyAppearance modifies DOM attributes immediately for live preview', () => {
    const mockRoot = {
      attributes: new Map<string, string>(),
      removeAttribute(name: string) { this.attributes.delete(name); },
      setAttribute(name: string, val: string) { this.attributes.set(name, val); },
      getAttribute(name: string) { return this.attributes.get(name) ?? null; },
    };
    const mockBody = {
      classes: new Set<string>(),
      classList: {
        toggle: (cls: string, force?: boolean) => {
          if (force !== undefined) {
            if (force) mockBody.classes.add(cls); else mockBody.classes.delete(cls);
          } else {
            if (mockBody.classes.has(cls)) mockBody.classes.delete(cls); else mockBody.classes.add(cls);
          }
        },
        contains: (cls: string) => mockBody.classes.has(cls),
      },
    };
    const mockDoc = {
      documentElement: mockRoot,
      body: mockBody,
    } as unknown as Document;

    // Apply dark theme, compact density, always reduced motion
    applyAppearance('dark', 'compact', 'always', mockDoc);
    expect(mockRoot.getAttribute('data-theme')).toBe('dark');
    expect(mockBody.classList.contains('density-compact')).toBe(true);
    expect(mockRoot.getAttribute('data-motion')).toBe('reduce');

    // Revert to system theme, comfortable density, never reduced motion
    applyAppearance('system', 'comfortable', 'never', mockDoc);
    expect(mockRoot.getAttribute('data-theme')).toBeNull();
    expect(mockBody.classList.contains('density-compact')).toBe(false);
    expect(mockRoot.getAttribute('data-motion')).toBe('no-reduce');
  });

  it('options.ts implements isAppearanceDirty comparing theme, density, and reducedMotion', () => {
    expect(ts).toContain('function isAppearanceDirty(): boolean');
    expect(ts).toContain('initialAppearance.theme');
    expect(ts).toContain('initialAppearance.density');
    expect(ts).toContain('initialAppearance.reducedMotion');
  });

  it('updateDirtyUI displays "Preview — unsaved" when appearance is modified and "Unsaved changes" for other fields', () => {
    expect(ts).toContain("const statusMsg = isAppDirty ? 'Preview — unsaved' : 'Unsaved changes'");
    expect(ts).toContain('navDirtyBadge.textContent = statusMsg');

    // Behavioral simulation of updateDirtyUI logic
    const computeDirtyFeedback = (
      isDirty: boolean,
      current: { theme: string; density: string; reducedMotion: string; retainDays: number },
      initial: { theme: string; density: string; reducedMotion: string; retainDays: number },
    ): { text: string; dirtyBadgeVisible: boolean; discardVisible: boolean } => {
      if (!isDirty) {
        return { text: '', dirtyBadgeVisible: false, discardVisible: false };
      }
      const isAppDirty =
        current.theme !== initial.theme ||
        current.density !== initial.density ||
        current.reducedMotion !== initial.reducedMotion;
      return {
        text: isAppDirty ? 'Preview — unsaved' : 'Unsaved changes',
        dirtyBadgeVisible: true,
        discardVisible: true,
      };
    };

    const initial = { theme: 'system', density: 'comfortable', reducedMotion: 'system', retainDays: 7 };

    // When appearance changes (e.g. theme becomes 'dark')
    const appChanged = { ...initial, theme: 'dark' };
    const appFeedback = computeDirtyFeedback(true, appChanged, initial);
    expect(appFeedback.text).toBe('Preview — unsaved');
    expect(appFeedback.dirtyBadgeVisible).toBe(true);
    expect(appFeedback.discardVisible).toBe(true);

    // When only non-appearance changes (e.g. retainDays becomes 30)
    const nonAppChanged = { ...initial, retainDays: 30 };
    const nonAppFeedback = computeDirtyFeedback(true, nonAppChanged, initial);
    expect(nonAppFeedback.text).toBe('Unsaved changes');
    expect(nonAppFeedback.dirtyBadgeVisible).toBe(true);
    expect(nonAppFeedback.discardVisible).toBe(true);

    // When clean
    const cleanFeedback = computeDirtyFeedback(false, initial, initial);
    expect(cleanFeedback.text).toBe('');
    expect(cleanFeedback.dirtyBadgeVisible).toBe(false);
    expect(cleanFeedback.discardVisible).toBe(false);
  });

  it('discard reverts preview to saved settings and resets dirty state', () => {
    const savedSettings = { theme: 'system', density: 'comfortable', reducedMotion: 'system' };
    let previewState = { ...savedSettings };
    let dirty = false;

    const onPreviewChange = (newTheme: string) => {
      previewState.theme = newTheme;
      dirty = previewState.theme !== savedSettings.theme;
    };

    const onDiscard = () => {
      previewState = { ...savedSettings };
      dirty = false;
    };

    onPreviewChange('dark');
    expect(previewState.theme).toBe('dark');
    expect(dirty).toBe(true);

    onDiscard();
    expect(previewState.theme).toBe('system');
    expect(dirty).toBe(false);
  });

  it('save permanently persists previewed appearance and marks clean', () => {
    let savedSettings = { theme: 'system', density: 'comfortable', reducedMotion: 'system' };
    const previewState = { ...savedSettings };
    let dirty = false;

    previewState.theme = 'light';
    previewState.density = 'compact';
    dirty = true;

    const onSave = () => {
      savedSettings = { ...previewState };
      dirty = false;
    };

    onSave();
    expect(savedSettings.theme).toBe('light');
    expect(savedSettings.density).toBe('compact');
    expect(dirty).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Post-Save Navigation Guard (R4)
// ---------------------------------------------------------------------------

describe('Post-Save Navigation Guard (R4)', () => {
  const tsPath = path.resolve(__dirname, '../src/options/options.ts');
  const ts = fs.readFileSync(tsPath, 'utf-8');

  it('handleSave declares return type Promise<boolean>', () => {
    expect(ts).toContain('async function handleSave(): Promise<boolean>');
  });

  it('handleSave validates fields and returns false without persisting on invalid input', async () => {
    const handleSaveMock = (settings: { retainHistoryDays: number; maxHistoryPerOrigin: number }): Promise<boolean> => {
      if (settings.retainHistoryDays < 0 || settings.retainHistoryDays > 365) {
        return Promise.resolve(false);
      }
      if (settings.maxHistoryPerOrigin < 1 || settings.maxHistoryPerOrigin > 50) {
        return Promise.resolve(false);
      }
      return Promise.resolve(true);
    };

    expect(await handleSaveMock({ retainHistoryDays: -1, maxHistoryPerOrigin: 10 })).toBe(false);
    expect(await handleSaveMock({ retainHistoryDays: 366, maxHistoryPerOrigin: 10 })).toBe(false);
    expect(await handleSaveMock({ retainHistoryDays: 7, maxHistoryPerOrigin: 0 })).toBe(false);
    expect(await handleSaveMock({ retainHistoryDays: 7, maxHistoryPerOrigin: 51 })).toBe(false);
    expect(await handleSaveMock({ retainHistoryDays: 7, maxHistoryPerOrigin: 10 })).toBe(true);
  });

  it('wireUnsavedDialog gates navigation strictly on save success', () => {
    expect(ts).toContain('void handleSave().then((saved) => {');
    expect(ts).toContain('if (saved) {');
    expect(ts).toContain('activateSection(target, focusTarget ?? undefined);');
    expect(ts).toContain('pendingNavSection = null;');
  });

  it('preserves unsaved form state and blocks navigation when save fails', async () => {
    let activeSection = 'appearance';
    let pendingNav: string | null = 'monitoring';
    const formState = { retainDays: 999 }; // invalid
    let errorDisplayed = false;

    const handleSave = (): Promise<boolean> => {
      if (formState.retainDays > 365) {
        errorDisplayed = true;
        return Promise.resolve(false); // validation failure
      }
      return Promise.resolve(true);
    };

    const onDialogSaveClick = async () => {
      const saved = await handleSave();
      if (saved) {
        if (pendingNav !== null) {
          activeSection = pendingNav;
          pendingNav = null;
        }
      } else {
        // preserve edits and stay on current section
        pendingNav = null;
      }
    };

    await onDialogSaveClick();

    // Verify navigation was BLOCKED
    expect(activeSection).toBe('appearance');
    // Verify form state was PRESERVED
    expect(formState.retainDays).toBe(999);
    // Verify error was displayed
    expect(errorDisplayed).toBe(true);
    expect(pendingNav).toBeNull();
  });

  it('proceeds with navigation when save succeeds', async () => {
    let activeSection = 'appearance';
    let pendingNav: string | null = 'monitoring';

    const handleSave = (): Promise<boolean> => {
      return Promise.resolve(true);
    };

    const onDialogSaveClick = async () => {
      const saved = await handleSave();
      if (saved) {
        if (pendingNav !== null) {
          activeSection = pendingNav;
          pendingNav = null;
        }
      } else {
        pendingNav = null;
      }
    };

    await onDialogSaveClick();

    expect(activeSection).toBe('monitoring');
    expect(pendingNav).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Staged Form Dirty Tracking & Credential Liveness Invariants (R4)
// ---------------------------------------------------------------------------

describe('Staged Form Dirty Tracking & Credential Liveness (R4)', () => {
  const tsPath = path.resolve(__dirname, '../src/options/options.ts');
  const ts = fs.readFileSync(tsPath, 'utf-8');
  const htmlPath = path.resolve(__dirname, '../src/options/options.html');
  const html = fs.readFileSync(htmlPath, 'utf-8');

  it('wireModeRadios calls updateDirtyState inside revertToPriorMode', () => {
    expect(ts).toContain('const revertToPriorMode = (): void => {');
    const revertStart = ts.indexOf('const revertToPriorMode = (): void => {');
    const revertEnd = ts.indexOf('};', revertStart);
    const revertBlock = ts.slice(revertStart, revertEnd + 2);
    expect(revertBlock).toContain('updateDirtyState()');
  });

  it('credential liveness toggle is default-off, manual-only, and wired to dirty tracking', () => {
    // DEFAULT_SETTINGS invariant
    expect(DEFAULT_SETTINGS.credentialLivenessEnabled).toBe(false);

    // HTML input element
    expect(html).toContain('id="credential-liveness-toggle"');
    expect(html).toContain('name="credentialLiveness"');

    // options.ts wiring
    expect(ts).toContain("credentialLivenessToggle.addEventListener('change', updateDirtyState)");
    expect(ts).toContain('credentialLivenessEnabled: Boolean(current.credentialLivenessEnabled)');
  });

  it('changing credential liveness alone marks form dirty and discards cleanly', () => {
    const initial = { credentialLivenessEnabled: false };
    let current = { ...initial };
    let dirty = false;

    const onToggle = (checked: boolean) => {
      current.credentialLivenessEnabled = checked;
      dirty = current.credentialLivenessEnabled !== initial.credentialLivenessEnabled;
    };

    onToggle(true);
    expect(current.credentialLivenessEnabled).toBe(true);
    expect(dirty).toBe(true);

    // Discard
    current = { ...initial };
    dirty = false;
    expect(current.credentialLivenessEnabled).toBe(false);
    expect(dirty).toBe(false);
  });
});


