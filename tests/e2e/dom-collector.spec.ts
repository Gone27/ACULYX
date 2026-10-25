import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { test, expect, chromium, type BrowserContext } from '@playwright/test';
import { startServer } from '../server/index';
import type { Lead } from '../../src/leads/types';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const extensionPath = path.resolve(__dirname, '../../dist');

interface SettingsStub {
  monitoringMode: 'per-site' | 'all-sites' | 'off';
  leadsEnabled: boolean;
  [key: string]: unknown;
}

interface BackgroundWindow {
  __SettingsService?: {
    getSettings: () => Promise<SettingsStub>;
    updateSettings: (s: SettingsStub) => Promise<void>;
  };
  __sensorInjectionFailures?: { s2: number; s3: number };
  __globalLeadStore?: {
    getAllLeads: () => Lead[];
  };
}

test.describe('P0 DOM Collector Content Script E2E Verification', () => {
  test('executes standalone classic dom-collector in browser page, extracting leads with zero injection failures', async () => {
    const { server, baseUrl } = await startServer(3460, '127.0.0.1');

    const testExtDir = path.resolve(__dirname, `../../test-results/dist-e2e-dom-${Date.now()}`);
    fs.cpSync(extensionPath, testExtDir, { recursive: true });
    const testManifestPath = path.join(testExtDir, 'manifest.json');
    const manifestJson = JSON.parse(fs.readFileSync(testManifestPath, 'utf8')) as {
      host_permissions?: string[];
      optional_host_permissions?: string[];
      [key: string]: unknown;
    };
    manifestJson.host_permissions = ['<all_urls>'];
    delete manifestJson.optional_host_permissions;
    fs.writeFileSync(testManifestPath, JSON.stringify(manifestJson, null, 2));

    const userDataDir = path.join(__dirname, `../../test-results/playwright-dom-${Date.now()}`);
    let context: BrowserContext | undefined;

    try {
      context = await chromium.launchPersistentContext(userDataDir, {
        headless: false,
        args: [
          '--headless=new',
          `--disable-extensions-except=${testExtDir}`,
          `--load-extension=${testExtDir}`,
          '--no-sandbox',
        ],
      });

      let background = context.serviceWorkers()[0];
      if (background === undefined) {
        background = await context.waitForEvent('serviceworker', { timeout: 10_000 });
      }
      expect(background).toBeDefined();

      // Configure extension settings in service worker: set monitoringMode to 'all-sites' and enable leads
      await background.evaluate(async () => {
        const bg = self as unknown as BackgroundWindow;
        const service = bg.__SettingsService;
        if (service !== undefined) {
          const current = await service.getSettings();
          current.monitoringMode = 'all-sites';
          current.leadsEnabled = true;
          await service.updateSettings(current);
        }
      });

      // 1. Visit Positive Fixture
      const page = await context.newPage();
      await page.goto(`${baseUrl}/lead-lab/dom-positive`);
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(2000); // Allow document_idle DOM collector injection and message dispatch

      // 2. Assert sensor injection failures remain strictly zero
      const failures = await background.evaluate(() => {
        const bg = self as unknown as BackgroundWindow;
        return bg.__sensorInjectionFailures ?? { s2: -1, s3: -1 };
      });
      expect(failures.s2, 'S2 dom-collector injection failures must remain zero').toBe(0);

      // 3. Assert the expected lead reaches the globalLeadStore
      const leads = await background.evaluate(() => {
        const bg = self as unknown as BackgroundWindow;
        const store = bg.__globalLeadStore;
        return store !== undefined ? store.getAllLeads() : [];
      });

      expect(leads.length).toBeGreaterThanOrEqual(1);
      const authLead = leads.find((l: Lead) => l.ruleId === 'AUTH-003');
      expect(authLead).toBeDefined();
      if (authLead !== undefined) {
        expect(authLead.title).toContain('Cleartext HTTP');
      }

      // 4. Visit Negative Fixture and verify non-matching content does not create unexpected leads
      await page.goto(`${baseUrl}/lead-lab/dom-negative`);
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(2000);

      const afterNegativeLeads = await background.evaluate(() => {
        const bg = self as unknown as BackgroundWindow;
        const store = bg.__globalLeadStore;
        return store !== undefined ? store.getAllLeads() : [];
      });

      const negativeUrlLeads = afterNegativeLeads.filter(
        (l: Lead) => typeof l.url === 'string' && l.url.includes('/lead-lab/dom-negative'),
      );
      expect(negativeUrlLeads, 'Negative fixture must create zero leads').toHaveLength(0);

      await page.close();
    } finally {
      if (context !== undefined) {
        await context.close();
      }
      server.close();
      if (fs.existsSync(userDataDir)) {
        try {
          fs.rmSync(userDataDir, { recursive: true, force: true });
        } catch {
          // ignore cleanup errors
        }
      }
      if (fs.existsSync(testExtDir)) {
        try {
          fs.rmSync(testExtDir, { recursive: true, force: true });
        } catch {
          // ignore cleanup errors
        }
      }
    }
  });
});
