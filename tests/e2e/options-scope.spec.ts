/**
 * @file options-scope.spec.ts
 * Playwright E2E test for Scope Profiles in Options UI and tab reclassification.
 *
 * Verifies:
 * 1. Scope profile creation, naming, rule definition (include/exclude), and saving via Options UI.
 * 2. Persistence across full options page reload.
 * 3. Immediate tab reclassification in background service worker state upon settings transition.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { test, expect, chromium } from '@playwright/test';
import { startServer } from '../server/index';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const extensionPath = path.resolve(__dirname, '../../dist');

test.describe('Scope Profiles UI & Tab Reclassification E2E', () => {
  test('creates, saves, and reloads scope profiles in options UI, immediately reclassifying open tab', async () => {
    const { server, baseUrl } = await startServer(3466, '127.0.0.1');

    const testExtDir = path.resolve(__dirname, '../../dist-e2e-scope-test');
    fs.cpSync(extensionPath, testExtDir, { recursive: true });
    const testManifestPath = path.join(testExtDir, 'manifest.json');
    const manifestJson = JSON.parse(fs.readFileSync(testManifestPath, 'utf8')) as {
      host_permissions?: string[];
      [key: string]: unknown;
    };
    manifestJson.host_permissions = ['http://127.0.0.1/*'];
    fs.writeFileSync(testManifestPath, JSON.stringify(manifestJson, null, 2));

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

      // 1. Open test page
      const page = await context.newPage();
      await page.goto(`${baseUrl}/good-headers`);

      const targetTabId = await background.evaluate(async (targetUrl: string) => {
        const tabs = await chrome.tabs.query({});
        const match = tabs.find((t) => t.url !== undefined && t.url.startsWith(targetUrl));
        return match?.id ?? null;
      }, baseUrl);
      expect(targetTabId).not.toBeNull();

      // 2. Open popup and trigger monitor flow
      const popup = await context.newPage();
      await popup.addInitScript(() => {
        let granted = false;
        const perms = chrome.permissions as unknown as {
          contains: (details: chrome.permissions.Permissions, cb?: (r: boolean) => void) => Promise<boolean> | void;
          request: (details: chrome.permissions.Permissions, cb?: (r: boolean) => void) => Promise<boolean> | void;
          getAll: (cb?: (p: chrome.permissions.Permissions) => void) => Promise<chrome.permissions.Permissions> | void;
        };
        perms.contains = (_d, cb) => {
          if (typeof cb === 'function') { cb(granted); return; }
          return Promise.resolve(granted);
        };
        perms.request = (_d, cb) => {
          granted = true;
          if (typeof cb === 'function') { cb(true); return; }
          return Promise.resolve(true);
        };
        perms.getAll = (cb) => {
          const res = { origins: granted ? ['http://127.0.0.1/*'] : [] };
          if (typeof cb === 'function') { cb(res); return; }
          return Promise.resolve(res);
        };
      });

      await popup.goto(`chrome-extension://${extensionId}/src/popup/popup.html?tabId=${targetTabId}`);
      const monitorBtn = popup.locator('#monitor-btn');
      await monitorBtn.click();
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(1000);
      await popup.close();

      // Check initial tab state in background: no active scope profile
      const initialTabState = await background.evaluate(async (tabId: number) => {
        const dump = await chrome.storage.session.get(`tab:${tabId}`);
        return dump[`tab:${tabId}`] as { scopeStatus?: string } | undefined;
      }, targetTabId as number);

      expect(initialTabState?.scopeStatus).toBeUndefined();

      // 3. Open Options Page and configure Scope Profile
      const optionsPage = await context.newPage();
      await optionsPage.goto(`chrome-extension://${extensionId}/src/options/options.html`);

      // Navigate to Scope section
      const scopeNavBtn = optionsPage.locator('.nav-item[data-section="scope"]');
      await scopeNavBtn.click();
      await expect(optionsPage.locator('#section-scope')).toBeVisible();

      // Click "+ New Profile"
      const addProfileBtn = optionsPage.locator('#btn-add-scope-profile');
      await addProfileBtn.click();

      // Locate newly created profile card
      const profileCard = optionsPage.locator('.scope-profile-card').first();
      await expect(profileCard).toBeVisible();

      // Rename profile
      const nameInput = profileCard.locator('input[placeholder="Program / Profile Name"]');
      await nameInput.fill('Local Bounty Scope');

      // Add inclusion rule for 127.0.0.1
      const ruleInput = profileCard.locator('input[placeholder="*.domain.com or host:port"]');
      await ruleInput.fill('127.0.0.1:3466');
      const addRuleBtn = profileCard.locator('button', { hasText: 'Add Rule' });
      await addRuleBtn.click();

      // Ensure rule appears in table
      await expect(profileCard.locator('code', { hasText: '127.0.0.1:3466' })).toBeVisible();

      // Ensure active profile select has this profile selected
      const activeSelect = optionsPage.locator('#active-scope-profile-select');
      await expect(activeSelect).not.toHaveValue('');

      // Save changes
      const saveBtn = optionsPage.locator('#save-btn');
      await saveBtn.click();
      await expect(optionsPage.locator('#save-status')).toContainText(/saved/i, { timeout: 5000 });

      // 4. Reload options page and verify persistence
      await optionsPage.reload();
      await scopeNavBtn.click();
      await expect(optionsPage.locator('.scope-profile-card')).toBeVisible();
      await expect(optionsPage.locator('input[placeholder="Program / Profile Name"]').first()).toHaveValue('Local Bounty Scope');
      await expect(optionsPage.locator('code', { hasText: '127.0.0.1:3466' })).toBeVisible();
      await optionsPage.close();

      // 5. Verify background reclassification of the already-open tab
      await page.waitForTimeout(1000);
      const rescoredTabState = await background.evaluate(async (tabId: number) => {
        const dump = await chrome.storage.session.get(`tab:${tabId}`);
        return dump[`tab:${tabId}`] as { scopeStatus?: string; scopeReason?: string } | undefined;
      }, targetTabId as number);

      expect(rescoredTabState).toBeDefined();
      expect(rescoredTabState?.scopeStatus).toBe('in-scope');
      expect(rescoredTabState?.scopeReason).toContain('Target matches inclusion rule');

      await page.close();
    } finally {
      if (context) await context.close();
      server.close();
      fs.rmSync(testExtDir, { recursive: true, force: true });
    }
  });
});
