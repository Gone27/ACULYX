/**
 * @file playwright.config.ts
 * Playwright test configuration for header-security extension e2e tests.
 *
 * Assumptions:
 *  - Tests live under tests/e2e/
 *  - Each test manages its own Express server instance on a unique port.
 *  - Full extension loading (persistent context) requires: pnpm build first.
 */

import { defineConfig } from '@playwright/test';

export default defineConfig({
  /** Directory to scan for test files. */
  testDir: './tests/e2e',

  /** Maximum time (ms) for a single test to complete. */
  timeout: 30_000,

  /** Maximum time (ms) for the entire test run. 0 = no global limit. */
  globalTimeout: 0,

  /**
   * Retry failing tests once in CI to reduce flakiness from port contention.
   * Set to 0 locally for faster feedback.
   */
  retries: process.env['CI'] ? 1 : 0,

  /** Output format: 'list' is compact and CI-friendly. */
  reporter: 'list',

  use: {
    /** Run tests in headless Chromium by default. */
    headless: true,

    /**
     * Extra time (ms) for each action/assertion inside a test.
     * Covers slow CI environments.
     */
    actionTimeout: 10_000,

    /**
     * Capture a screenshot on failure for debugging.
     * Artefacts are written to the default Playwright output dir.
     */
    screenshot: 'only-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: {
        // browserName is implied by the project name above, but explicit for clarity.
        browserName: 'chromium',
      },
    },
  ],
});
