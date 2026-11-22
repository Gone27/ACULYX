/**
 * @file sidepanel-verdict.spec.ts
 * Playwright E2E UI regression test for unregistered rule verdicts and dimension lines in Sidepanel.
 *
 * Verifies:
 * 1. An unregistered/arbitrary rule (ARBITRARY-RULE) displays "? Uncertain" badge, NOT "Likely bug".
 * 2. The dimensions line explicitly displays Assessment: unreviewed, Evidence: observed, Scope: in-scope.
 * 3. The self-check summary notes no registered passive proof.
 * 4. A registered rule with remaining preconditions (AUTH-003) displays "Likely bug" badge and Assessment: likely.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { test, expect, chromium } from '@playwright/test';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const extensionPath = path.resolve(__dirname, '../../dist');

test.describe('Sidepanel Lead Verdict UI Regression E2E', () => {
  test('unregistered rule renders "? Uncertain" badge with unreviewed assessment, not "Likely bug"', async () => {
    const testExtDir = path.resolve(__dirname, '../../dist-e2e-sidepanel-test');
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

      // Switch to Leads tab
      await sidepanelPage.click('#tab-leads');
      await expect(sidepanelPage.locator('#view-leads')).toBeVisible();

      // Broadcast lead state from background service worker to the sidepanel
      await background.evaluate(async () => {
        const arbitraryLead = {
          id: 'LD-TEST-ARBITRARY',
          ruleId: 'ARBITRARY-RULE',
          family: 'F4',
          tier: 'observed',
          potential: 'high',
          confidence: 0.95,
          title: 'Arbitrary Unregistered Rule Lead',
          needs: [],
          doesNotProve: [],
          evidence: {
            preview: 'test-preview-evidence',
            location: 'https://app.example.com/test',
          },
          tags: [],
          scopeStatus: 'in-scope',
          timestamp: Date.now(),
          origin: 'https://app.example.com',
          url: 'https://app.example.com/test',
          sourceSensor: 'S1',
          verdict: {
            status: 'uncertain',
            evidenceStatus: 'observed',
            scopeStatus: 'in-scope',
            securityAssessment: 'unreviewed',
            method: 'passive',
            summary: 'Observed: condition directly seen, but rule ARBITRARY-RULE has no registered passive vulnerability proof (unreviewed).',
            checks: [
              { id: 'scope', kind: 'passive', outcome: 'pass', detail: 'Target is in declared scope.' },
              { id: 'evidence-tier', kind: 'passive', outcome: 'pass', detail: 'Condition directly observed with no outstanding preconditions.' },
              { id: 'rule-predicate', kind: 'passive', outcome: 'inconclusive', detail: 'No automated passive vulnerability proof registered for rule ARBITRARY-RULE.' },
            ],
            missing: ['Verify whether this observation constitutes an exploitable issue in this application context.'],
            verifiedAt: Date.now(),
          },
        };

        const registeredLikelyLead = {
          id: 'LD-TEST-REGISTERED-LIKELY',
          ruleId: 'AUTH-003',
          family: 'F4',
          tier: 'observed',
          potential: 'high',
          confidence: 0.95,
          title: 'Registered Auth Lead With Precondition',
          needs: ['prove the form submission is sensitive'],
          doesNotProve: [],
          evidence: {
            preview: 'form action=http://login.example.com method=POST',
            location: 'https://app.example.com/login',
          },
          tags: [],
          scopeStatus: 'in-scope',
          timestamp: Date.now(),
          origin: 'https://app.example.com',
          url: 'https://app.example.com/login',
          sourceSensor: 'S1',
          verdict: {
            status: 'likely',
            evidenceStatus: 'observed',
            scopeStatus: 'in-scope',
            securityAssessment: 'likely',
            method: 'passive',
            summary: 'Likely a real issue; at least one impact-defining condition is still unproven.',
            checks: [
              { id: 'scope', kind: 'passive', outcome: 'pass', detail: 'Target is in declared scope.' },
              { id: 'evidence-tier', kind: 'passive', outcome: 'pass', detail: 'Condition directly observed, but 1 precondition(s) still unproven.' },
            ],
            missing: ['prove the form submission is sensitive'],
            verifiedAt: Date.now(),
          },
        };

        await chrome.runtime.sendMessage({
          type: 'LEAD_STATE_UPDATE',
          origin: 'https://app.example.com',
          leads: [arbitraryLead, registeredLikelyLead],
          activeChains: [],
          stats: { total: 2, critical: 0, high: 2, medium: 0, low: 0, info: 0 },
        }).catch(() => {});
      });

      // 1. Check card for unregistered rule ARBITRARY-RULE
      const arbitraryCard = sidepanelPage.locator('#sp-lead-card-LD-TEST-ARBITRARY');
      await expect(arbitraryCard).toBeVisible();

      const arbitraryBadge = arbitraryCard.locator('.lead-verdict-badge');
      await expect(arbitraryBadge).toBeVisible();
      await expect(arbitraryBadge).toHaveText('? Uncertain');
      await expect(arbitraryBadge).not.toHaveText('Likely bug');
      await expect(arbitraryBadge).toHaveClass(/verdict-uncertain/);

      const arbitraryDims = arbitraryCard.locator('.lead-dimensions-line');
      await expect(arbitraryDims).toBeVisible();
      await expect(arbitraryDims).toContainText('Assessment: unreviewed');
      await expect(arbitraryDims).toContainText('Evidence: observed');
      await expect(arbitraryDims).toContainText('Scope: in-scope');

      const arbitrarySummary = arbitraryCard.locator('.lead-verdict-line');
      await expect(arbitrarySummary).toContainText('no registered passive vulnerability proof');

      // 2. Check card for registered rule AUTH-003 with remaining preconditions
      const registeredCard = sidepanelPage.locator('#sp-lead-card-LD-TEST-REGISTERED-LIKELY');
      await expect(registeredCard).toBeVisible();

      const registeredBadge = registeredCard.locator('.lead-verdict-badge');
      await expect(registeredBadge).toBeVisible();
      await expect(registeredBadge).toHaveText('Likely bug');
      await expect(registeredBadge).toHaveClass(/verdict-likely/);

      const registeredDims = registeredCard.locator('.lead-dimensions-line');
      await expect(registeredDims).toBeVisible();
      await expect(registeredDims).toContainText('Assessment: likely');
      await expect(registeredDims).toContainText('Evidence: observed');
      await expect(registeredDims).toContainText('Scope: in-scope');

      // 3. Verify sidepanel nav tabs have proper roles and keyboard focus attributes
      const graphTab = sidepanelPage.locator('#tab-graph');
      const leadsTab = sidepanelPage.locator('#tab-leads');
      await expect(graphTab).toHaveAttribute('role', 'tab');
      await expect(leadsTab).toHaveAttribute('role', 'tab');
      await expect(leadsTab).toHaveAttribute('aria-selected', 'true');
      await expect(graphTab).toHaveAttribute('aria-selected', 'false');

      // Verify no horizontal overflow in sidepanel body
      const sidepanelNoHScroll = await sidepanelPage.evaluate(() => {
        return document.body.scrollWidth <= document.body.clientWidth + 1;
      });
      expect(sidepanelNoHScroll).toBe(true);

      await context.close();
    } finally {
      if (fs.existsSync(testExtDir)) {
        try {
          fs.rmSync(testExtDir, { recursive: true, force: true });
        } catch {
          // Ignore
        }
      }
    }
  });
});
