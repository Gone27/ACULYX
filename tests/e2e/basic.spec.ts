/**
 * @file basic.spec.ts
 * Playwright e2e smoke tests for the header-security test server.
 *
 * These tests verify:
 *  1. The test server correctly delivers headers for each scenario route.
 *  2. XSS payloads embedded in response headers do not trigger script execution
 *     in the browser page (extension popup rendering is verified manually or
 *     via the unit tests in engine.test.ts).
 *
 * Prerequisites:
 *  - Extension must be built: `pnpm build`
 *  - Playwright browsers installed: `pnpm exec playwright install chromium`
 *  - Run with: `pnpm test:e2e`
 *
 * NOTE: Loading the Chrome extension in a persistent Playwright context
 * requires `chromium.launchPersistentContext`. Full header-analysis e2e
 * (verifying popup content) requires the extension to be loaded; those tests
 * are marked with a skip comment and left as future work.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { test, expect, chromium } from '@playwright/test';
import { startServer } from '../server/index';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const extensionPath = path.resolve(__dirname, '../../dist');

// ==========================================================================
// Test suite: Test server header scenarios
// ==========================================================================

test.describe('Extension e2e (requires built dist/)', () => {
  // ------------------------------------------------------------------------
  // /good-headers — expects all security headers present
  // ------------------------------------------------------------------------

  test('test server serves /good-headers with correct headers', async () => {
    const { server, baseUrl } = await startServer(3457);
    try {
      const browser = await chromium.launch();
      const context = await browser.newContext();
      const page = await context.newPage();

      const response = await page.goto(`${baseUrl}/good-headers`);

      expect(response).not.toBeNull();
      expect(response?.headers()['x-content-type-options']).toBe('nosniff');
      expect(response?.headers()['referrer-policy']).toBe('strict-origin-when-cross-origin');
      expect(response?.headers()['x-frame-options']).toBe('DENY');
      expect(response?.headers()['cache-control']).toBe('no-store');
      expect(response?.headers()['strict-transport-security']).toBe(
        'max-age=31536000; includeSubDomains',
      );

      await browser.close();
    } finally {
      server.close();
    }
  });

  // ------------------------------------------------------------------------
  // /no-headers — expects no security headers
  // ------------------------------------------------------------------------

  test('test server serves /no-headers with no security headers', async () => {
    const { server, baseUrl } = await startServer(3458);
    try {
      const browser = await chromium.launch();
      const context = await browser.newContext();
      const page = await context.newPage();

      const response = await page.goto(`${baseUrl}/no-headers`);

      expect(response).not.toBeNull();
      expect(response?.headers()['content-security-policy']).toBeUndefined();
      expect(response?.headers()['strict-transport-security']).toBeUndefined();
      expect(response?.headers()['x-content-type-options']).toBeUndefined();
      expect(response?.headers()['x-frame-options']).toBeUndefined();
      expect(response?.headers()['referrer-policy']).toBeUndefined();

      await browser.close();
    } finally {
      server.close();
    }
  });

  // ------------------------------------------------------------------------
  // /xss-in-headers — XSS payloads in header values must not execute
  // ------------------------------------------------------------------------

  test('test server /xss-in-headers does not execute scripts', async () => {
    const { server, baseUrl } = await startServer(3459);
    let scriptExecuted = false;

    try {
      const browser = await chromium.launch();
      const context = await browser.newContext();
      const page = await context.newPage();

      // If any XSS fires (e.g. from an alert()) it would surface as a dialog.
      page.on('dialog', async (dialog) => {
        scriptExecuted = true;
        // Dismiss immediately to avoid hanging the test
        await dialog.dismiss();
      });

      await page.goto(`${baseUrl}/xss-in-headers`);

      // Allow time for any deferred scripts to execute
      await page.waitForTimeout(500);

      expect(scriptExecuted).toBe(false);

      await browser.close();
    } finally {
      server.close();
    }
  });

  // ------------------------------------------------------------------------
  // /bad-csp — weak CSP headers are present
  // ------------------------------------------------------------------------

  test('test server /bad-csp returns a CSP with unsafe-inline', async () => {
    const { server, baseUrl } = await startServer(3460);
    try {
      const browser = await chromium.launch();
      const context = await browser.newContext();
      const page = await context.newPage();

      const response = await page.goto(`${baseUrl}/bad-csp`);

      expect(response).not.toBeNull();
      const csp = response?.headers()['content-security-policy'] ?? '';
      expect(csp).toContain('unsafe-inline');
      expect(csp).toContain('unsafe-eval');

      await browser.close();
    } finally {
      server.close();
    }
  });

  // ------------------------------------------------------------------------
  // /version-leak — server and x-powered-by expose version strings
  // ------------------------------------------------------------------------

  test('test server /version-leak returns versioned Server and X-Powered-By', async () => {
    const { server, baseUrl } = await startServer(3461);
    try {
      const browser = await chromium.launch();
      const context = await browser.newContext();
      const page = await context.newPage();

      const response = await page.goto(`${baseUrl}/version-leak`);

      expect(response).not.toBeNull();
      expect(response?.headers()['server']).toBe('Apache/2.4.51');
      expect(response?.headers()['x-powered-by']).toBe('PHP/8.1.0');

      await browser.close();
    } finally {
      server.close();
    }
  });

  // ------------------------------------------------------------------------
  // /hsts-short — HSTS with short max-age
  // ------------------------------------------------------------------------

  test('test server /hsts-short returns HSTS with max-age=86400', async () => {
    const { server, baseUrl } = await startServer(3462);
    try {
      const browser = await chromium.launch();
      const context = await browser.newContext();
      const page = await context.newPage();

      const response = await page.goto(`${baseUrl}/hsts-short`);

      expect(response).not.toBeNull();
      const hsts = response?.headers()['strict-transport-security'] ?? '';
      expect(hsts).toBe('max-age=86400');

      await browser.close();
    } finally {
      server.close();
    }
  });

  // ------------------------------------------------------------------------
  // /cookie-test — Set-Cookie without Cache-Control: no-store
  // ------------------------------------------------------------------------

  test('test server /cookie-test sets a cookie without no-store cache-control', async () => {
    const { server, baseUrl } = await startServer(3463);
    try {
      const browser = await chromium.launch();
      const context = await browser.newContext();
      const page = await context.newPage();

      // Chromium strips Set-Cookie from response.headers() for security.
      // Use page.route() to intercept the raw response headers instead.
      let capturedSetCookie = '';
      let capturedCacheControl = '';
      await page.route('**/cookie-test', async (route) => {
        const response = await route.fetch();
        capturedSetCookie    = response.headers()['set-cookie'] ?? '';
        capturedCacheControl = response.headers()['cache-control'] ?? '';
        await route.fulfill({ response });
      });

      await page.goto(`${baseUrl}/cookie-test`);

      // Cookie must have landed in the browser jar
      const cookies = await context.cookies(`${baseUrl}/cookie-test`);
      const sessionCookie = cookies.find((c) => c.name === 'test_session');
      expect(sessionCookie).toBeDefined();
      expect(sessionCookie?.httpOnly).toBe(true);

      // Set-Cookie header must be present (captured via route interception)
      expect(capturedSetCookie).toContain('test_session=REDACTED_IN_TEST');

      // Cache-Control must NOT contain no-store (so CACHE-001 fires on this response)
      expect(capturedCacheControl).not.toContain('no-store');

      await browser.close();
    } finally {
      server.close();
    }
  });
});

// ==========================================================================
// Test suite: Real Chrome extension loading & UI inspection
// ==========================================================================

test.describe('Extension Loading & Storage Redaction E2E', () => {
  test('loads built extension in persistent context, renders UI, and verifies zero cookie canary leak in session storage', async () => {
    const { server, baseUrl } = await startServer(3464, '127.0.0.1');

    // Prepare a test extension directory with host permissions so Chromium's network layer
    // dispatches webRequest events during automated headless execution.
    const testExtDir = path.resolve(__dirname, '../../dist-e2e-test');
    fs.cpSync(extensionPath, testExtDir, { recursive: true });
    const testManifestPath = path.join(testExtDir, 'manifest.json');
    const manifestJson = JSON.parse(fs.readFileSync(testManifestPath, 'utf8')) as {
      host_permissions?: string[];
      [key: string]: unknown;
    };
    manifestJson.host_permissions = ['<all_urls>'];
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

      // Wait for extension background service worker
      let [background] = context.serviceWorkers();
      if (!background) {
        background = await context.waitForEvent('serviceworker', { timeout: 10_000 });
      }

      expect(background).toBeDefined();
      const extensionId = background.url().split('/')[2];
      expect(extensionId).toBeDefined();

      // 1. Visit options page and verify evaluation mode label
      const optionsPage = await context.newPage();
      await optionsPage.goto(`chrome-extension://${extensionId}/src/options/options.html`);
      await expect(optionsPage.locator('.brand')).toContainText('SecCheck');
      await expect(optionsPage.locator('#section-pro')).toContainText('Evaluation Mode');
      await optionsPage.close();

      // 2. Visit popup page and verify UI elements
      const popupPage = await context.newPage();
      await popupPage.goto(`chrome-extension://${extensionId}/src/popup/popup.html`);
      await expect(popupPage.locator('.popup-title')).toContainText('SecCheck');
      await expect(popupPage.locator('#settings-link')).toBeVisible();
      await expect(popupPage.locator('#open-graph-btn')).toBeAttached();
      await popupPage.close();

      // 3. Visit sidepanel page directly (Firefox fallback mode) and verify graph UI
      const sidepanelPage = await context.newPage();
      await sidepanelPage.goto(`chrome-extension://${extensionId}/src/sidepanel/sidepanel.html?apex=example.com`);
      await expect(sidepanelPage.locator('#tier-badge')).toBeVisible();
      await sidepanelPage.close();

      // 4. Exercise real monitor flow on the test route
      const page = await context.newPage();
      await page.goto(`${baseUrl}/cookie-test`);

      // Find the tabId of the target test page
      const targetTabId = await background.evaluate(async (targetUrl: string) => {
        const tabs = await chrome.tabs.query({});
        const match = tabs.find((t) => t.url !== undefined && t.url.startsWith(targetUrl));
        return match?.id ?? null;
      }, baseUrl);
      expect(targetTabId).not.toBeNull();

      // Open popup targeting the test tab
      const monitorPopup = await context.newPage();
      // Configure initial unmonitored state in popup: checkPermission returns false until user clicks monitor
      await monitorPopup.addInitScript(() => {
        let permissionGranted = false;
        const perms = chrome.permissions as unknown as {
          contains: (details: chrome.permissions.Permissions, callback: (result: boolean) => void) => Promise<boolean> | void;
          request: (details: chrome.permissions.Permissions, callback?: (result: boolean) => void) => Promise<boolean> | void;
        };
        const origContains = perms.contains.bind(perms);
        perms.contains = (
          details: chrome.permissions.Permissions,
          callback: (result: boolean) => void,
        ): void => {
          if (details.origins !== undefined && details.origins.some((o: string) => o.includes('127.0.0.1'))) {
            callback(permissionGranted);
            return;
          }
          void origContains(details, callback);
        };
        perms.request = (
          _details: chrome.permissions.Permissions,
          callback?: (result: boolean) => void,
        ): void => {
          permissionGranted = true;
          if (callback) callback(true);
        };
      });

      await monitorPopup.goto(`chrome-extension://${extensionId}/src/popup/popup.html?tabId=${targetTabId}`);

      // Verify that the monitor section is initially visible for the unmonitored origin
      const monitorSection = monitorPopup.locator('#monitor-section');
      await expect(monitorSection).toBeVisible();

      // Click "Monitor this site" to execute the real UI permission request flow
      const monitorBtn = monitorPopup.locator('#monitor-btn');
      await monitorBtn.click();

      // Verify that the UI state updated and monitor section is now hidden
      await expect(monitorSection).toBeHidden();

      // Wait for tab reload triggered by monitor button to finish and background to capture the hop
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(1500);

      // 5. Query session storage from service worker to verify captured tab state and secret redaction
      const storageDump = await background.evaluate(async () => {
        return await chrome.storage.session.get(null);
      });
      const serialized = JSON.stringify(storageDump);

      // Verify that the tab was captured and state stored
      const tabStateKey = `tab:${targetTabId}`;
      expect(storageDump).toHaveProperty(tabStateKey);
      const tabState = (storageDump as Record<string, {
        monitoredByUser: boolean;
        hops: Array<{
          headers: Record<string, string>;
          rawHeaders: Array<{ name: string; value: string }>;
        }>;
      }>)[tabStateKey];

      expect(tabState).toBeDefined();
      if (tabState === undefined) throw new Error('tabState is undefined');
      expect(tabState.monitoredByUser).toBe(true);
      expect(tabState.hops.length).toBeGreaterThanOrEqual(1);

      // Verify that the cookie header was captured and sanitized in both headers and rawHeaders
      const capturedHop = tabState.hops[0];
      expect(capturedHop).toBeDefined();
      if (capturedHop === undefined) throw new Error('capturedHop is undefined');
      expect(capturedHop.headers['set-cookie']).toBeDefined();
      expect(capturedHop.headers['set-cookie']).toContain('[REDACTED]');
      expect(capturedHop.headers['set-cookie']).not.toContain('REDACTED_IN_TEST');
      expect(capturedHop.headers['set-cookie']).not.toContain('V2_SYNTHETIC_CANARY');

      // Verify zero canary or secret values anywhere in serialized session storage
      expect(serialized).not.toContain('V2_SYNTHETIC_CANARY');
      expect(serialized).not.toContain('REDACTED_IN_TEST');

      await monitorPopup.close();
      await page.close();
    } finally {
      if (context) await context.close();
      server.close();
      fs.rmSync(testExtDir, { recursive: true, force: true });
    }
  });
});
