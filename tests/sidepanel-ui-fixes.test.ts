/**
 * tests/sidepanel-ui-fixes.test.ts — Unit tests for ACULYX UI Fix Plan
 *
 * Verifies:
 *  - Radar legibility fixes (CSS ring fill:none, axis strokes, axis labels)
 *  - Radar defensive paint attributes and keyboard accessibility
 *  - In-panel Settings overlay structure, controls, and appearance preview
 *  - Sidepanel header wordmark branding
 *  - Overview recent findings card and flexible scrolling
 *  - Design token font hierarchy and motion system
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

describe('ACULYX UI Fix Plan — Sidepanel Verification', () => {
  const htmlPath = path.resolve(__dirname, '../src/sidepanel/sidepanel.html');
  const cssPath = path.resolve(__dirname, '../src/sidepanel/sidepanel.css');
  const tsPath = path.resolve(__dirname, '../src/sidepanel/sidepanel.ts');
  const tokensPath = path.resolve(__dirname, '../src/shared/design-tokens.css');

  const html = fs.readFileSync(htmlPath, 'utf-8');
  const css = fs.readFileSync(cssPath, 'utf-8');
  const ts = fs.readFileSync(tsPath, 'utf-8');
  const tokens = fs.readFileSync(tokensPath, 'utf-8');

  describe('1. Vulnerability Radar Legibility & Accessibility', () => {
    it('defines .radar-ring with fill: none in sidepanel.css', () => {
      expect(css).toMatch(/\.radar-ring\s*\{[^}]*fill:\s*none/);
      expect(css).toMatch(/\.radar-ring\s*\{[^}]*stroke:/);
    });

    it('defines .radar-axis and .radar-axis-label in sidepanel.css', () => {
      expect(css).toMatch(/\.radar-axis\s*\{[^}]*stroke:/);
      expect(css).toMatch(/\.radar-axis-label\s*\{[^}]*fill:/);
    });

    it('sets defensive SVG paint attributes in renderSidepanelRadar', () => {
      expect(ts).toContain("circle.setAttribute('fill', 'none')");
      expect(ts).toContain("circle.setAttribute('stroke', '#232038')");
      expect(ts).toContain("line.setAttribute('stroke', '#232038')");
      expect(ts).toContain("text.setAttribute('fill', '#7e9ab0')");
    });

    it('makes radar blips keyboard-focusable with role and aria-label', () => {
      expect(ts).toContain("blip.setAttribute('tabindex', '0')");
      expect(ts).toContain("blip.setAttribute('role', 'button')");
      expect(ts).toContain("blip.setAttribute('aria-label',");
      expect(ts).toContain("e.key === 'Enter' || e.key === ' '");
    });

    it('includes radar empty-state container and handling', () => {
      expect(css).toContain('.radar-empty-state');
      expect(ts).toContain('radar-empty-state');
      expect(ts).toContain('radar-empty-icon');
      expect(ts).toContain('radar-empty-text');
    });

    it('pauses radar sweep animation when hidden or inactive', () => {
      expect(ts).toContain("document.addEventListener('visibilitychange'");
      expect(ts).toContain('radarSweepEl.style.animationPlayState');
    });
  });

  describe('2. In-Panel Settings Overlay', () => {
    it('has #view-settings overlay inside sidepanel.html', () => {
      expect(html).toContain('id="view-settings"');
      expect(html).toContain('class="settings-panel-overlay"');
      expect(html).toContain('id="settings-close-btn"');
    });

    it('provides monitoring mode radio controls', () => {
      expect(html).toContain('name="sp-monitoring-mode"');
      expect(html).toContain('id="sp-mode-per-site"');
      expect(html).toContain('id="sp-mode-all-sites"');
      expect(html).toContain('id="sp-mode-off"');
    });

    it('provides investigation feature toggles', () => {
      expect(html).toContain('id="sp-setting-leads"');
      expect(html).toContain('id="sp-setting-deep"');
      expect(html).toContain('id="sp-setting-cred"');
      expect(html).toContain('id="sp-setting-hunter"');
    });

    it('provides appearance selection controls', () => {
      expect(html).toContain('id="sp-setting-theme"');
      expect(html).toContain('id="sp-setting-density"');
      expect(html).toContain('id="sp-setting-motion"');
    });

    it('provides Save, Discard, and full Options page link', () => {
      expect(html).toContain('id="sp-settings-save-btn"');
      expect(html).toContain('id="sp-settings-discard-btn"');
      expect(html).toContain('id="sp-open-full-options-btn"');
    });

    it('implements dirty-state, appearance preview, and confirmation in sidepanel.ts', () => {
      expect(ts).toContain('openInPanelSettings');
      expect(ts).toContain('saveInPanelSettings');
      expect(ts).toContain('discardInPanelSettings');
      expect(ts).toContain('isInPanelSettingsDirty');
      expect(ts).toContain('previewAppearance');
    });
  });

  describe('3. Header Branding & Typography', () => {
    it('embeds aculyx-wordmark.png in the sidepanel header', () => {
      expect(html).toMatch(/<img class="header-wordmark"\s+src="\.\.\/assets\/aculyx-wordmark\.png"\s+alt="ACULYX"/);
    });

    it('defines .header-wordmark styles in sidepanel.css', () => {
      expect(css).toMatch(/\.header-wordmark\s*\{[^}]*max-height:/);
      expect(css).toMatch(/\.header-wordmark\s*\{[^}]*object-fit:\s*contain/);
    });

    it('configures Space Grotesk and IBM Plex Mono font stacks in design-tokens.css', () => {
      expect(tokens).toContain("'Space Grotesk'");
      expect(tokens).toContain("'IBM Plex Mono'");
    });

    it('bundles @font-face declarations and OFL documentation', () => {
      expect(tokens).toContain("@font-face");
      const fontsDocPath = path.resolve(__dirname, '../src/assets/fonts/FONTS.md');
      expect(fs.existsSync(fontsDocPath)).toBe(true);
      const doc = fs.readFileSync(fontsDocPath, 'utf-8');
      expect(doc).toContain('Space Grotesk');
      expect(doc).toContain('IBM Plex Mono');
      expect(doc).toContain('OFL-1.1');
    });
  });

  describe('4. Overview Content & Flexible Scrolling', () => {
    it('sets min-height: 0 on views-container and panel-view for flex scrolling', () => {
      expect(css).toMatch(/\.views-container\s*\{[^}]*min-height:\s*0/);
      expect(css).toMatch(/\.panel-view\s*\{[^}]*min-height:\s*0/);
    });

    it('includes recent findings card in sidepanel.html', () => {
      expect(html).toContain('class="overview-card recent-findings-card"');
      expect(html).toContain('id="overview-recent-list"');
      expect(html).toContain('id="overview-recent-count"');
    });

    it('renders recent findings safely in sidepanel.ts with safe DOM APIs', () => {
      expect(ts).toContain('renderRecentFindings');
      expect(ts).toContain('recent-finding-item');
      expect(ts).toContain('recent-finding-title');
      // Must not use innerHTML
      expect(ts).not.toContain('.innerHTML');
    });
  });

  describe('5. Motion & Interaction Feedback', () => {
    it('defines sliding active tab indicator via ::after', () => {
      expect(css).toContain('.nav-tab::after');
      expect(css).toContain('.nav-tab.active::after');
    });

    it('provides view fade-in animation', () => {
      expect(css).toContain('@keyframes viewFadeIn');
      expect(css).toContain('animation: viewFadeIn');
    });

    it('provides card elevation and button press feedback', () => {
      expect(css).toMatch(/\.lead-card:hover\s*\{[^}]*transform:\s*translateY\(-1px\)/);
      expect(css).toMatch(/\.btn-primary:active[^\{]*\{[^}]*transform:\s*scale\(0\.97\)/);
    });

    it('provides radar blip entrance animation', () => {
      expect(css).toContain('@keyframes blipEntrance');
      expect(css).toMatch(/\.radar-blip\s*\{[^}]*animation:\s*blipEntrance/);
    });
  });
});
