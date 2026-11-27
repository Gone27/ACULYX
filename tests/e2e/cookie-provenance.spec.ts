/**
 * @file cookie-provenance.spec.ts
 * Real Chromium E2E test verifying Appendix A #3:
 *   Cookie evidence provenance distinguishes raw Set-Cookie setter routes from
 *   subsequent same-origin navigations reading persisted cookies from the browser jar.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, expect, chromium, type BrowserContext } from '@playwright/test';
import { startServer, type TestServerHandle } from '../server';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const extensionPath = path.resolve(__dirname, '../../dist');

interface TabStateSummary {
  url?: string;
  findings: Array<{ ruleId: string; evidence: string; sourceUrl?: string }>;
  cookies: Array<{ name: string; evidenceSource?: string; setterUrl?: string }>;
}

test.describe('Cookie Setter-Route Provenance E2E', () => {
  let server: TestServerHandle;
  let tempExtDir: string;

  test.beforeAll(async () => {
    server = await startServer(0, '127.0.0.1');
  });

  test.afterAll(async () => {
    await new Promise<void>((resolve) => server.server.close(() => resolve()));
    if (tempExtDir && fs.existsSync(tempExtDir)) {
      fs.rmSync(tempExtDir, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
    }
  });

  test('attributes COOK-004 to Set-Cookie setter route and marks follow-up routes as persisted cookie-jar provenance', async () => {
    tempExtDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aculyx-cookie-prov-e2e-'));
    fs.cpSync(extensionPath, tempExtDir, { recursive: true });

    const manifestPath = path.join(tempExtDir, 'manifest.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as {
      host_permissions?: string[];
      optional_host_permissions?: string[];
    };
    manifest.host_permissions = ['http://127.0.0.1/*'];
    delete manifest.optional_host_permissions;
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
      const extensionId = background.url().split('/')[2];
      expect(extensionId).toBeDefined();

      const extPage = await context.newPage();
      await extPage.goto(`chrome-extension://${extensionId}/src/options/options.html`);

      const origin = new URL(server.baseUrl).origin;
      const setterUrl = `${origin}/cookie-test`;
      const followUpUrl = `${origin}/good-headers`;

      async function getTabState(tid: number): Promise<TabStateSummary | null> {
        const raw: unknown = await extPage.evaluate(async (tabIdArg): Promise<unknown> => {
          return await chrome.runtime.sendMessage({
            type: 'REQUEST_STATE',
            tabId: tabIdArg,
          });
        }, tid);
        return (raw as { state?: TabStateSummary | null }).state ?? null;
      }

      // Step 1: Visit setter route (/cookie-test)
      const page = await context.newPage();
      await page.goto(setterUrl, { waitUntil: 'networkidle' });

      const tabId = await extPage.evaluate(async (base) => {
        const tabs = await chrome.tabs.query({});
        const match = tabs.find((t) => typeof t.url === 'string' && t.url.startsWith(base));
        return match?.id ?? -1;
      }, server.baseUrl);
      expect(tabId).toBeGreaterThan(0);

      await expect.poll(async () => {
        const st = await getTabState(tabId);
        return st?.cookies.some((c) => c.name === 'test_session' && c.evidenceSource === 'set-cookie-header') ?? false;
      }, { timeout: 6_000 }).toBe(true);

      const setterState = await getTabState(tabId);
      const setterCook = setterState?.findings.find((f) => f.ruleId === 'COOK-004');
      expect(setterCook?.sourceUrl).toBe(setterUrl);
      expect(setterCook?.evidence).toContain(`Set-Cookie header on ${setterUrl}`);

      // Step 2: Visit follow-up route (/good-headers) on same origin where cookie persists in jar without Set-Cookie
      await page.goto(followUpUrl, { waitUntil: 'networkidle' });

      await expect.poll(async () => {
        const st = await getTabState(tabId);
        return st?.url?.startsWith(followUpUrl) === true &&
          st.cookies.some((c) => c.name === 'test_session' && c.evidenceSource === 'cookie-jar');
      }, { timeout: 6_000 }).toBe(true);

      const followUpState = await getTabState(tabId);
      const followUpCookie = followUpState?.cookies.find((c) => c.name === 'test_session');
      expect(followUpCookie?.evidenceSource).toBe('cookie-jar');
      expect(followUpCookie?.setterUrl).toBe(setterUrl);

      const followUpFinding = followUpState?.findings.find((f) => f.ruleId === 'COOK-004');
      expect(followUpFinding?.sourceUrl).toBe(setterUrl);
      expect(followUpFinding?.evidence).toContain('browser cookie jar');
      expect(followUpFinding?.evidence).toContain(`originally set on ${setterUrl}`);

      await page.close();
      await extPage.close();
    } finally {
      if (context) {
        await context.close().catch(() => {});
      }
    }
  });
});
