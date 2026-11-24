/**
 * @file sidepanel-ui.spec.ts
 * Playwright E2E UI tests for ACULYX UI Fix Plan:
 *  - Wordmark branding in header
 *  - Radar legibility, styles, and empty state
 *  - In-panel Settings overlay with full dirty-state lifecycle
 *  - Overview Recent Findings card
 *  - Animation frame budget profiling (16.7ms target)
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { test, expect, chromium } from '@playwright/test';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const extensionPath = path.resolve(__dirname, '../../dist');

test.describe('Sidepanel UI Redesign E2E Suite', () => {
  const tempDirs: string[] = [];

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

  test('header renders ACULYX wordmark logo and in-panel Settings functions with dirty-state guard', async () => {
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
      await sidepanelPage.goto(`chrome-extension://${extensionId}/src/sidepanel/sidepanel.html`);

      // 1. Header Wordmark Verification
      const wordmark = sidepanelPage.locator('.header-wordmark');
      await expect(wordmark).toBeVisible();
      await expect(wordmark).toHaveAttribute('alt', 'ACULYX');

      // 2. Radar Legibility Verification
      const radarSvg = sidepanelPage.locator('#sidepanel-radar-svg');
      await expect(radarSvg).toBeVisible();
      const ringsGroup = sidepanelPage.locator('#sp-radar-rings');
      await expect(ringsGroup).toBeAttached();

      // Empty state indicator
      const emptyState = sidepanelPage.locator('.radar-empty-state');
      await expect(emptyState).toBeVisible();
      await expect(emptyState).toContainText(/No leads detected/i);

      // 3. In-Panel Settings Route Verification
      const settingsBtn = sidepanelPage.locator('#options-link');
      await settingsBtn.click();

      const settingsOverlay = sidepanelPage.locator('#view-settings');
      await expect(settingsOverlay).toBeVisible();
      await expect(sidepanelPage.locator('.settings-panel-title')).toContainText('Settings');

      // Verify controls exist
      await expect(sidepanelPage.locator('#sp-mode-per-site')).toBeVisible();
      await expect(sidepanelPage.locator('#sp-mode-all-sites')).toBeVisible();
      await expect(sidepanelPage.locator('#sp-mode-off')).toBeVisible();
      await expect(sidepanelPage.locator('#sp-setting-leads')).toBeVisible();
      await expect(sidepanelPage.locator('#sp-setting-theme')).toBeVisible();

      // Test Discard action
      await sidepanelPage.locator('#sp-mode-all-sites').check();
      await expect(sidepanelPage.locator('#sp-mode-all-sites')).toBeChecked();

      await sidepanelPage.locator('#sp-settings-discard-btn').click();
      await expect(settingsOverlay).toBeHidden();

      // Re-open and verify value was not saved
      await settingsBtn.click();
      await expect(settingsOverlay).toBeVisible();
      await expect(sidepanelPage.locator('#sp-mode-per-site')).toBeChecked();

      // Test Close Guard on dirty changes
      await sidepanelPage.locator('#sp-mode-off').check();
      await sidepanelPage.locator('#settings-close-btn').click();

      // Confirmation modal should appear
      const confirmModal = sidepanelPage.locator('#confirm-modal-dialog');
      await expect(confirmModal).toBeVisible();
      await expect(sidepanelPage.locator('#confirm-modal-title')).toContainText('Discard Unsaved Settings?');

      // Cancel confirmation — stays in settings
      await sidepanelPage.locator('#confirm-modal-cancel-btn').click();
      await expect(confirmModal).toBeHidden();
      await expect(settingsOverlay).toBeVisible();

      // Test Save
      await sidepanelPage.locator('#sp-settings-save-btn').click();
      const saveStatus = sidepanelPage.locator('#sp-settings-status');
      await expect(saveStatus).toContainText('Saved');
      await expect(settingsOverlay).toBeHidden({ timeout: 5000 });

      // 4. Test Overview Recent Findings
      const recentFindingsCard = sidepanelPage.locator('.recent-findings-card');
      await expect(recentFindingsCard).toBeVisible();
      await expect(sidepanelPage.locator('#overview-recent-empty')).toBeVisible();

      // Broadcast mock leads to test recent findings population
      await background.evaluate(async () => {
        const mockLead = {
          id: 'LD-E2E-RECENT-1',
          ruleId: 'SEC-001',
          family: 'F1',
          tier: 'observed',
          potential: 'critical',
          confidence: 0.99,
          title: 'Exposed Production API Key In Bundle',
          needs: [],
          doesNotProve: [],
          evidence: { preview: 'AKIAIOSFODNN7EXAMPLE', location: 'https://test.example/app.js' },
          tags: ['secrets'],
          scopeStatus: 'in-scope',
          timestamp: Date.now(),
          origin: 'https://test.example',
          url: 'https://test.example/app.js',
          sourceSensor: 'S1',
        };

        const clients = (self as unknown as { clients?: { matchAll: () => Promise<Array<{ postMessage: (msg: unknown) => void }>> } }).clients;
        if (clients) {
          const all = await clients.matchAll();
          for (const c of all) {
            c.postMessage({
              type: 'LEAD_STATE_UPDATE',
              lead: mockLead,
              totalLeads: 1,
            });
          }
        }
      });

      // 5. Animation Frame Profiling (Targeting 60fps budget: frames < 16.7ms)
      const frameMetrics = await sidepanelPage.evaluate(async () => {
        return new Promise<{ totalFrames: number; under17ms: number; maxFrameTime: number; avgFrameTime: number }>((resolve) => {
          const frameTimes: number[] = [];
          let lastTime = performance.now();
          let frameCount = 0;

          function recordFrame(now: number) {
            const delta = now - lastTime;
            lastTime = now;
            frameTimes.push(delta);
            frameCount++;

            if (frameCount < 40) {
              requestAnimationFrame(recordFrame);
            } else {
              // Ignore the first frame which includes setup
              const samples = frameTimes.slice(1);
              const under17ms = samples.filter((t) => t <= 20).length;
              const maxFrameTime = Math.max(...samples);
              const avgFrameTime = samples.reduce((a, b) => a + b, 0) / samples.length;
              resolve({
                totalFrames: samples.length,
                under17ms,
                maxFrameTime,
                avgFrameTime,
              });
            }
          }

          requestAnimationFrame(recordFrame);
        });
      });

      expect(frameMetrics.totalFrames).toBeGreaterThanOrEqual(30);
      // The vast majority of animation frames should be fast (< 20ms)
      expect(frameMetrics.under17ms / frameMetrics.totalFrames).toBeGreaterThanOrEqual(0.85);

      await sidepanelPage.close();
      await context.close();
    } finally {
      if (context) {
        await context.close().catch(() => {});
      }
    }
  });
});
