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

import { test, expect, chromium } from '@playwright/test';
import { startServer } from '../server/index';

// NOTE (Phase 3): Path imports and extensionPath for persistent-context loading will go here.

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
