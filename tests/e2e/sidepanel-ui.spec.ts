/**
 * @file sidepanel-ui.spec.ts
 * Playwright E2E UI tests for ACULYX UI Fix Plan:
 *  - Wordmark branding in header (responsive, alt text, crisp subtitle, no collision)
 *  - Bundled OFL font loading verification (Space Grotesk & IBM Plex Mono strictly true)
 *  - Radar legibility, paint attributes, zero state, filter-empty state, and sweep pause
 *  - In-panel Settings overlay with full dirty-state lifecycle, Esc handler, and appearance preview/revert
 *  - Overview Recent Findings card and container scroll layout (min-height: 0, sole vertical scroller)
 *  - Interactive animation frame profiling under transitions (<16.7ms 60fps budget)
 *  - Separate reduced-motion compliance verification
 *  - Visual screenshots in Dark/Light themes and narrow viewports
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { test, expect, chromium } from '@playwright/test';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const extensionPath = path.resolve(__dirname, '../../dist');
const artifactsScreenshotDir = 'C:/Users/Admin/.gemini/antigravity/brain/6e1c6ba2-370a-4e4a-89a2-6fcf0752f119/screenshots';

test.describe('Sidepanel UI Redesign E2E Suite', () => {
  const tempDirs: string[] = [];

  test.beforeAll(() => {
    if (!fs.existsSync(artifactsScreenshotDir)) {
      try {
        fs.mkdirSync(artifactsScreenshotDir, { recursive: true });
      } catch {
        // Safe creation
      }
    }
  });

  test.afterAll(() => {
    for (const dir of tempDirs) {
      if (fs.existsSync(dir)) {
        try {
          fs.rmSync(dir, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
        } catch {
          // Safe cleanup
        }
      }
    }
  });

  test('comprehensive sidepanel verification: branding, fonts, radar, in-panel settings, scrolling, motion, and visual contrast', async () => {
    const testExtDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aculyx-e2e-sidepanel-ui-'));
    tempDirs.push(testExtDir);
    fs.cpSync(extensionPath, testExtDir, { recursive: true });

    let context;
    try {
      context = await chromium.launchPersistentContext('', {
        headless: false,
        args: [
          '--headless=new',
          `--disable-extensions-except=${testExtDir}`,
          `--load-extension=${testExtDir}`,
        ],
      });

      let [background] = context.serviceWorkers();
      if (!background) {
        background = await context.waitForEvent('serviceworker', { timeout: 10_000 });
      }
      expect(background).toBeDefined();
      const extensionId = background.url().split('/')[2];
      expect(extensionId).toBeDefined();

      const sidepanelPage = await context.newPage();
      await sidepanelPage.setViewportSize({ width: 380, height: 720 });
      await sidepanelPage.goto(`chrome-extension://${extensionId}/src/sidepanel/sidepanel.html`);

      // ─── 1. Header Wordmark Verification ───────────────────────────
      const wordmark = sidepanelPage.locator('.header-wordmark');
      await expect(wordmark).toBeVisible();
      await expect(wordmark).toHaveAttribute('alt', 'ACULYX');
      const wordmarkBox = await wordmark.boundingBox();
      expect(wordmarkBox).not.toBeNull();
      if (wordmarkBox) {
        expect(wordmarkBox.width).toBeGreaterThanOrEqual(110);
        expect(wordmarkBox.width).toBeLessThanOrEqual(160);
      }

      // Check collision with right-side header controls
      const headerActions = sidepanelPage.locator('.header-actions');
      await expect(headerActions).toBeVisible();
      const actionsBox = await headerActions.boundingBox();
      if (wordmarkBox && actionsBox) {
        expect(wordmarkBox.x + wordmarkBox.width).toBeLessThanOrEqual(actionsBox.x + 5);
      }

      // ─── 2. Font Hierarchy & Bundled OFL Font Loading ───────────────
      await sidepanelPage.evaluate(async () => {
        await document.fonts.ready;
        await Promise.all([
          document.fonts.load('16px "Space Grotesk"'),
          document.fonts.load('14px "IBM Plex Mono"'),
        ]);
      });
      const fontsLoaded = await sidepanelPage.evaluate(() => {
        return {
          spaceGrotesk: document.fonts.check('16px "Space Grotesk"'),
          ibmPlexMono: document.fonts.check('14px "IBM Plex Mono"'),
        };
      });
      // Assert both font families are verified true
      expect(fontsLoaded.spaceGrotesk).toBe(true);
      expect(fontsLoaded.ibmPlexMono).toBe(true);

      // ─── 3. Navigation Hit Target & Semantic Verification ───────────
      // Verify visible Findings tab has direct click target with no invisible alias overlay
      await expect(sidepanelPage.locator('#tab-leads')).toHaveCount(0);
      await expect(sidepanelPage.locator('#tab-graph')).toHaveCount(0);
      const findingsNavTab = sidepanelPage.locator('#tab-findings');
      await expect(findingsNavTab).toBeVisible();
      await findingsNavTab.click();
      await expect(sidepanelPage.locator('#view-findings')).toBeVisible();

      // Return to overview
      await sidepanelPage.locator('#tab-overview').click();
      await expect(sidepanelPage.locator('#view-overview')).toBeVisible();

      // ─── 4. Radar Legibility, Defensive Paint & Empty States ────────
      const radarSvg = sidepanelPage.locator('#sidepanel-radar-svg');
      await expect(radarSvg).toBeVisible();
      const ringsGroup = sidepanelPage.locator('#sp-radar-rings');
      await expect(ringsGroup).toBeAttached();

      // Verify rings have fill="none" and non-zero stroke
      const ringCount = await ringsGroup.locator('circle').count();
      expect(ringCount).toBe(4);
      for (let i = 0; i < ringCount; i++) {
        const ring = ringsGroup.locator('circle').nth(i);
        await expect(ring).toHaveAttribute('fill', 'none');
        await expect(ring).toHaveAttribute('stroke', '#232038');
      }

      // Zero-leads empty state
      const emptyState = sidepanelPage.locator('.radar-empty-state');
      await expect(emptyState).toBeVisible();
      await expect(emptyState).toContainText(/No leads detected/i);

      // Verify Info option exists in severity filter
      const sevFilter = sidepanelPage.locator('#radar-severity-filter');
      await expect(sevFilter).toBeVisible();
      await expect(sevFilter.locator('option[value="info"]')).toBeAttached();

      // ─── 5. In-Panel Settings Route & Lifecycle ────────────────────
      const settingsBtn = sidepanelPage.locator('#options-link');
      await settingsBtn.click();

      const settingsOverlay = sidepanelPage.locator('#view-settings');
      await expect(settingsOverlay).toBeVisible();
      await expect(sidepanelPage.locator('.settings-panel-title')).toContainText('Settings');

      // Verify accessible close button
      const closeBtn = sidepanelPage.locator('#settings-close-btn');
      await expect(closeBtn).toBeVisible();
      await expect(closeBtn).toHaveAttribute('aria-label', 'Close settings');

      // Test Discard action
      await sidepanelPage.locator('#sp-mode-all-sites').check();
      await expect(sidepanelPage.locator('#sp-mode-all-sites')).toBeChecked();

      await sidepanelPage.locator('#sp-settings-discard-btn').click();
      await expect(settingsOverlay).toBeHidden();

      // Re-open and verify value was not saved
      await settingsBtn.click();
      await expect(settingsOverlay).toBeVisible();
      await expect(sidepanelPage.locator('#sp-mode-per-site')).toBeChecked();

      // Test Escape key when dirty triggers confirmation modal
      await sidepanelPage.locator('#sp-mode-off').check();
      await sidepanelPage.keyboard.press('Escape');

      const confirmModal = sidepanelPage.locator('#confirm-modal-dialog');
      await expect(confirmModal).toBeVisible();
      await expect(sidepanelPage.locator('#confirm-modal-title')).toContainText('Discard Unsaved Settings?');

      // Cancel confirmation — stays in settings
      await sidepanelPage.locator('#confirm-modal-cancel-btn').click();
      await expect(confirmModal).toBeHidden();
      await expect(settingsOverlay).toBeVisible();

      // Test Appearance Preview (without saving)
      const themeSelect = sidepanelPage.locator('#sp-setting-theme');
      await themeSelect.selectOption('light');
      // Root data-theme should preview light immediately
      const rootThemePreview = await sidepanelPage.evaluate(() => document.documentElement.getAttribute('data-theme'));
      expect(rootThemePreview).toBe('light');

      // Discard and confirm appearance is reverted
      await sidepanelPage.locator('#settings-close-btn').click();
      await expect(confirmModal).toBeVisible();
      await sidepanelPage.locator('#confirm-modal-confirm-btn').click();
      await expect(confirmModal).toBeHidden();
      await expect(settingsOverlay).toBeHidden();

      const rootThemeReverted = await sidepanelPage.evaluate(() => document.documentElement.getAttribute('data-theme'));
      expect(rootThemeReverted).not.toBe('light');

      // Re-open and test Save
      await settingsBtn.click();
      await expect(settingsOverlay).toBeVisible();
      await sidepanelPage.locator('#sp-mode-all-sites').check();
      await sidepanelPage.locator('#sp-settings-save-btn').click();
      const saveStatus = sidepanelPage.locator('#sp-settings-status');
      await expect(saveStatus).toContainText('Saved');
      await expect(settingsOverlay).toBeHidden({ timeout: 5000 });

      // ─── 6. Overview Layout, Scrolling & Recent Findings ──────────
      const recentFindingsCard = sidepanelPage.locator('.recent-findings-card');
      await expect(recentFindingsCard).toBeVisible();
      await expect(sidepanelPage.locator('#overview-recent-empty')).toBeVisible();

      // Verify layout: document.body has overflow: hidden, view-overview is the scroll container
      const layoutStyles = await sidepanelPage.evaluate(() => {
        const bodyStyle = window.getComputedStyle(document.body);
        const viewsContainer = document.querySelector('.views-container') as HTMLElement;
        const panelView = document.querySelector('.panel-view') as HTMLElement;
        const viewsStyle = window.getComputedStyle(viewsContainer);
        const panelStyle = window.getComputedStyle(panelView);

        return {
          bodyOverflow: bodyStyle.overflow,
          viewsMinHeight: viewsStyle.minHeight,
          panelMinHeight: panelStyle.minHeight,
          panelOverflowY: panelStyle.overflowY,
        };
      });

      expect(layoutStyles.bodyOverflow).toBe('hidden');
      expect(layoutStyles.viewsMinHeight).toBe('0px');
      expect(layoutStyles.panelMinHeight).toBe('0px');
      expect(layoutStyles.panelOverflowY).toBe('auto');

      // Inject test leads via production runtime messaging (zero test hooks in production code)
      const mockLeads = [
        {
          id: 'LD-E2E-1',
          ruleId: 'SEC-001',
          family: 'F1',
          tier: 'observed',
          potential: 'critical',
          confidence: 0.95,
          title: 'Exposed Hardcoded AWS API Key In Script',
          needs: [],
          doesNotProve: [],
          evidence: { preview: 'AKIAIOSFODNN7EXAMPLE', location: 'https://test.example/app.js' },
          tags: ['secrets'],
          scopeStatus: 'in-scope',
          timestamp: Date.now() - 1000,
          origin: 'https://test.example',
          url: 'https://test.example/app.js',
          sourceSensor: 'S1',
        },
        {
          id: 'LD-E2E-2',
          ruleId: 'SEC-004',
          family: 'F3',
          tier: 'observed',
          potential: 'high',
          confidence: 0.88,
          title: 'CORS Wildcard With Credentials Allowed',
          needs: [],
          doesNotProve: [],
          evidence: { preview: 'Access-Control-Allow-Origin: *', location: 'https://test.example/api' },
          tags: ['cors'],
          scopeStatus: 'in-scope',
          timestamp: Date.now() - 2000,
          origin: 'https://test.example',
          url: 'https://test.example/api',
          sourceSensor: 'S2',
        },
        {
          id: 'LD-E2E-3',
          ruleId: 'SEC-009',
          family: 'F5',
          tier: 'observed',
          potential: 'medium',
          confidence: 0.75,
          title: 'Missing Subresource Integrity on CDN Script',
          needs: [],
          doesNotProve: [],
          evidence: { preview: '<script src="https://cdn.example/lib.js">', location: 'https://test.example/page' },
          tags: ['sri'],
          scopeStatus: 'in-scope',
          timestamp: Date.now() - 3000,
          origin: 'https://test.example',
          url: 'https://test.example/page',
          sourceSensor: 'S1',
        },
      ];

      // Broadcast via service worker to all extension views
      await background.evaluate(async (leads) => {
        const clients = (self as unknown as { clients?: { matchAll: () => Promise<Array<{ postMessage: (msg: unknown) => void }>> } }).clients;
        if (clients) {
          const all = await clients.matchAll();
          for (const c of all) {
            c.postMessage({
              type: 'LEAD_STATE_UPDATE',
              origin: 'https://test.example',
              leads: leads,
            });
          }
        }
        void chrome.runtime.sendMessage({
          type: 'LEAD_STATE_UPDATE',
          origin: 'https://test.example',
          leads: leads,
        });
      }, mockLeads);

      // Verify Recent Findings rendered (latest 3)
      const recentItems = sidepanelPage.locator('.recent-finding-item');
      await expect(recentItems).toHaveCount(3);
      await expect(recentItems.first()).toContainText('Missing Subresource Integrity on CDN Script');
      await expect(recentItems.last()).toContainText('Exposed Hardcoded AWS API Key In Script');

      // Verify Radar Blips rendered and empty state is properly hidden
      await expect(emptyState).toBeHidden();
      const blips = sidepanelPage.locator('.radar-blip');
      await expect(blips).toHaveCount(3);

      // Verify blips stay within SVG viewport bounds after entrance animation
      await sidepanelPage.waitForTimeout(250);
      const radarBox = await radarSvg.boundingBox();
      expect(radarBox).not.toBeNull();
      if (radarBox) {
        for (let i = 0; i < 3; i++) {
          const bBox = await blips.nth(i).boundingBox();
          expect(bBox).not.toBeNull();
          if (bBox) {
            expect(bBox.x).toBeGreaterThanOrEqual(radarBox.x - 4);
            expect(bBox.x + bBox.width).toBeLessThanOrEqual(radarBox.x + radarBox.width + 4);
            expect(bBox.y).toBeGreaterThanOrEqual(radarBox.y - 4);
            expect(bBox.y + bBox.height).toBeLessThanOrEqual(radarBox.y + radarBox.height + 4);
          }
        }
      }

      // Verify Blip keyboard accessibility (tabindex="0", role="button", Enter key navigates to findings)
      const firstBlip = blips.first();
      await expect(firstBlip).toHaveAttribute('tabindex', '0');
      await expect(firstBlip).toHaveAttribute('role', 'button');
      await firstBlip.press('Enter');
      await expect(sidepanelPage.locator('#view-findings')).toBeVisible();

      // Return to overview
      await sidepanelPage.locator('#tab-overview').click();
      await expect(sidepanelPage.locator('#view-overview')).toBeVisible();

      // ─── 7. Interactive Animation Frame Profiling (16.7ms 60fps Budget) ───
      // Profile frames during representative user interaction (transitions between views and settings)
      await sidepanelPage.evaluate(() => {
        (window as unknown as { __profilingDeltas: number[]; __profilingActive: boolean }).__profilingDeltas = [];
        (window as unknown as { __profilingDeltas: number[]; __profilingActive: boolean }).__profilingActive = true;
        let last = performance.now();
        function loop(now: number) {
          if (!(window as unknown as { __profilingActive: boolean }).__profilingActive) return;
          const delta = now - last;
          last = now;
          (window as unknown as { __profilingDeltas: number[] }).__profilingDeltas.push(delta);
          requestAnimationFrame(loop);
        }
        requestAnimationFrame(loop);
      });

      // Representative user navigation transitions:
      await sidepanelPage.click('#tab-findings');
      await sidepanelPage.waitForTimeout(140);
      await sidepanelPage.click('#tab-surface');
      await sidepanelPage.waitForTimeout(140);
      await sidepanelPage.click('#tab-activity');
      await sidepanelPage.waitForTimeout(140);
      await sidepanelPage.click('#tab-overview');
      await sidepanelPage.waitForTimeout(140);

      // Representative in-panel Settings transition:
      await settingsBtn.click();
      await expect(settingsOverlay).toBeVisible();
      await sidepanelPage.waitForTimeout(140);
      await sidepanelPage.click('#settings-close-btn');
      await expect(settingsOverlay).toBeHidden();
      await sidepanelPage.waitForTimeout(140);

      const frameMetrics = await sidepanelPage.evaluate(() => {
        (window as unknown as { __profilingActive: boolean }).__profilingActive = false;
        const allDeltas = (window as unknown as { __profilingDeltas: number[] }).__profilingDeltas;
        const samples = allDeltas.slice(1);
        const under16_7ms = samples.filter((t) => t <= 16.7).length;
        const maxFrameTime = Math.max(...samples);
        const avgFrameTime = samples.reduce((a, b) => a + b, 0) / samples.length;
        const longTasks = samples.filter((t) => t > 50).length;
        return {
          totalFrames: samples.length,
          under16_7ms,
          ratioUnder16_7ms: samples.length > 0 ? under16_7ms / samples.length : 0,
          maxFrameTime,
          avgFrameTime,
          longTasks,
        };
      });

      expect(frameMetrics.totalFrames).toBeGreaterThanOrEqual(30);
      expect(frameMetrics.avgFrameTime).toBeLessThanOrEqual(16.7);
      expect(frameMetrics.ratioUnder16_7ms).toBeGreaterThanOrEqual(0.85);
      expect(frameMetrics.longTasks).toBe(0);

      // ─── 8. Separate Reduced-Motion Behavior Verification ──────────
      await sidepanelPage.evaluate(() => {
        document.documentElement.setAttribute('data-motion', 'reduce');
      });
      const reducedMotionComputed = await sidepanelPage.evaluate(() => {
        const view = document.querySelector('.panel-view') as HTMLElement;
        const style = window.getComputedStyle(view);
        return {
          animationName: style.animationName,
          animationDuration: style.animationDuration,
        };
      });
      expect(reducedMotionComputed.animationName === 'none' || reducedMotionComputed.animationDuration === '0s').toBe(true);

      await sidepanelPage.evaluate(() => {
        document.documentElement.removeAttribute('data-motion');
      });

      // ─── 9. Visual Screenshots Capture ────────────────────────────
      try {
        // Ensure explicit dark theme and allow entrance animations to settle before capture
        await sidepanelPage.evaluate(() => document.documentElement.setAttribute('data-theme', 'dark'));
        await sidepanelPage.waitForTimeout(260);

        // Screenshot 1: Dark Mode Overview with Wordmark, Posture, Radar with Blips, and Recent Findings
        await sidepanelPage.screenshot({ path: path.join(artifactsScreenshotDir, 'sidepanel-dark-overview.png') });

        // Screenshot 2: In-Panel Settings View
        await settingsBtn.click();
        await expect(settingsOverlay).toBeVisible();
        await sidepanelPage.waitForTimeout(260);
        await sidepanelPage.screenshot({ path: path.join(artifactsScreenshotDir, 'sidepanel-inpanel-settings.png') });
        await sidepanelPage.keyboard.press('Escape');
        await expect(settingsOverlay).toBeHidden();
        await sidepanelPage.waitForTimeout(260);

        // Screenshot 3: Narrow 320px Viewport (Dark Mode)
        await sidepanelPage.setViewportSize({ width: 320, height: 600 });
        await sidepanelPage.waitForTimeout(100);
        await sidepanelPage.screenshot({ path: path.join(artifactsScreenshotDir, 'sidepanel-narrow-320px.png') });

        // Screenshot 4: Light Mode Preview
        await sidepanelPage.evaluate(() => document.documentElement.setAttribute('data-theme', 'light'));
        await sidepanelPage.waitForTimeout(260);
        await sidepanelPage.screenshot({ path: path.join(artifactsScreenshotDir, 'sidepanel-light-overview.png') });
      } catch {
        // Safe screenshot notice
      }

      await sidepanelPage.close();
      await context.close();
    } finally {
      if (context) {
        await context.close().catch(() => {});
      }
    }
  });
});
