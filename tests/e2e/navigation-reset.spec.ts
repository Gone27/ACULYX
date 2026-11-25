/**
 * @file navigation-reset.spec.ts
 * Real Chromium E2E test reproducing and verifying the fix for P1:
 *   "Findings from a local test site must not remain associated with a browser tab
 *    after that tab navigates to another origin."
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, expect, chromium, type BrowserContext } from '@playwright/test';
import { startServer, type TestServerHandle } from '../server';
import type { SettingsService } from '../../src/shared/settings';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const extensionPath = path.resolve(__dirname, '../../dist');

interface BackgroundGlobals {
  __SettingsService?: typeof SettingsService;
}

interface LeadSummary {
  leads: Array<{ ruleId: string; origin: string; url: string }>;
}

test.describe('P1 Cross-Origin Navigation Lead Isolation E2E', () => {
  let serverA: TestServerHandle;
  let serverB: TestServerHandle;
  let tempExtDir: string;

  test.beforeAll(async () => {
    [serverA, serverB] = await Promise.all([
      startServer(0, '127.0.0.1'),
      startServer(0, 'localhost'),
    ]);
  });

  test.afterAll(async () => {
    await Promise.all([
      new Promise<void>((resolve) => serverA.server.close(() => resolve())),
      new Promise<void>((resolve) => serverB.server.close(() => resolve())),
    ]);
    if (tempExtDir && fs.existsSync(tempExtDir)) {
      fs.rmSync(tempExtDir, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
    }
  });

  test('navigating same tab from origin A (synthetic credential) to origin B does not leak origin A leads', async () => {
    tempExtDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aculyx-nav-reset-e2e-'));
    fs.cpSync(extensionPath, tempExtDir, { recursive: true });

    // Grant ONLY test origins in the disposable unpacked copy (mirroring per-site grants; never modifies source manifest)
    const manifestPath = path.join(tempExtDir, 'manifest.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as {
      host_permissions?: string[];
      optional_host_permissions?: string[];
    };
    manifest.host_permissions = ['http://127.0.0.1/*', 'http://localhost/*'];
    manifest.optional_host_permissions = (manifest.optional_host_permissions ?? []).filter((h) => h !== '<all_urls>');
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

    let context: BrowserContext | undefined;
    try {
      context = await chromium.launchPersistentContext('', {
        headless: false,
        args: [
          '--headless=new',
          `--disable-extensions-except=${tempExtDir}`,
          `--load-extension=${tempExtDir}`,
          '--no-sandbox',
        ],
      });

      let [background] = context.serviceWorkers();
      if (!background) {
        background = await context.waitForEvent('serviceworker', { timeout: 10_000 });
      }
      expect(background).toBeDefined();
      const extensionId = background.url().split('/')[2];
      expect(extensionId).toBeDefined();

      const extPage = await context.newPage();
      await extPage.goto(`chrome-extension://${extensionId}/src/options/options.html`);

      // Configure per-site mode and test scope via background SettingsService + broadcast
      const updatedSettings = await background.evaluate(async () => {
        const service = (self as unknown as BackgroundGlobals).__SettingsService;
        if (service === undefined) throw new Error('SettingsService not exposed on background');
        const settings = await service.getSettings();
        settings.monitoringMode = 'per-site';
        settings.leadsEnabled = true;
        settings.scopeProfiles = [{
          id: 'nav-reset-scope',
          name: 'Local Navigation Reset Scope',
          rules: [
            { pattern: '127.0.0.1', type: 'include' },
            { pattern: 'localhost', type: 'include' },
          ],
        }];
        settings.activeScopeProfileId = 'nav-reset-scope';
        await service.updateSettings(settings);
        return settings;
      });
      const settingsAck: unknown = await extPage.evaluate(async (settings): Promise<unknown> => {
        return await chrome.runtime.sendMessage({ type: 'SETTINGS_CHANGED', settings });
      }, updatedSettings);
      expect(settingsAck).toMatchObject({ success: true });
      await extPage.reload();
      await extPage.waitForTimeout(500);

      async function queryTabLeads(tid: number | undefined, orig: string): Promise<LeadSummary> {
        const raw: unknown = await extPage.evaluate(async ({ tabIdArg, originArg }): Promise<unknown> => {
          return await chrome.runtime.sendMessage({
            type: 'GET_LEADS_STATE',
            ...(tabIdArg !== undefined ? { tabId: tabIdArg } : {}),
            origin: originArg,
          });
        }, { tabIdArg: tid, originArg: orig });
        return raw as LeadSummary;
      }

      // Step 1: Navigate Tab 1 to origin A synthetic credential fixture
      const page = await context.newPage();
      await page.goto(`${serverA.baseUrl}/lead-lab/credential-setting`, { waitUntil: 'networkidle' });

      const originA = new URL(serverA.baseUrl).origin;
      const originB = new URL(serverB.baseUrl).origin;

      const tabId = await extPage.evaluate(async (urlA) => {
        const tabs = await chrome.tabs.query({});
        const match = tabs.find((t) => typeof t.url === 'string' && t.url.startsWith(urlA));
        return match?.id ?? -1;
      }, serverA.baseUrl);
      expect(tabId).toBeGreaterThan(0);

      // Poll until SEC-001 lead is collected and associated with tabId on origin A
      await expect.poll(async () => {
        const res = await queryTabLeads(tabId, originA);
        return res.leads.some((l) => l.ruleId === 'SEC-001' && l.origin === originA);
      }, { timeout: 6_000 }).toBe(true);

      // Step 2: Navigate the SAME tab across origins to origin B (/good-headers)
      await page.goto(`${serverB.baseUrl}/good-headers`, { waitUntil: 'load' });
      await page.waitForTimeout(500);

      // Query current-tab lead state for origin B on tabId — MUST NOT contain origin A's SEC-001 lead
      const stateOnB = await queryTabLeads(tabId, originB);

      const leakedFromOriginA = stateOnB.leads.filter((l) => l.origin === originA);
      expect(leakedFromOriginA).toHaveLength(0);

      // Step 3: Verify origin A's persistent history is STILL preserved when queried by origin A directly
      const originAHistory = await queryTabLeads(undefined, originA);
      expect(originAHistory.leads.some((l) => l.ruleId === 'SEC-001' && l.origin === originA)).toBe(true);

      // Step 4: Open a fresh Tab 2 on origin B and confirm zero origin A findings
      const freshTabB = await context.newPage();
      await freshTabB.goto(`${serverB.baseUrl}/good-headers`, { waitUntil: 'load' });
      await freshTabB.waitForTimeout(400);
      const tabIdB = await extPage.evaluate(async (urlB) => {
        const tabs = await chrome.tabs.query({});
        const match = tabs.find((t) => typeof t.url === 'string' && t.url.startsWith(urlB) && t.active);
        return match?.id ?? -1;
      }, serverB.baseUrl);
      if (tabIdB > 0) {
        const freshStateB = await queryTabLeads(tabIdB, originB);
        expect(freshStateB.leads.filter((l) => l.origin === originA)).toHaveLength(0);
      }

      await freshTabB.close();
      await page.close();
      await extPage.close();
    } finally {
      if (context) {
        await context.close().catch(() => {});
      }
    }
  });
});
