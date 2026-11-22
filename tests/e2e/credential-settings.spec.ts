import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { test, expect, chromium, type BrowserContext, type Page } from '@playwright/test';
import { startServer } from '../server/index';
import type { Lead } from '../../src/leads/types';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const extensionPath = path.resolve(__dirname, '../../dist');
const fakeGithubToken = 'ghp_0123456789abcdefghijklmnopqrstuvwxyz';

interface BackgroundWindow {
  __SettingsService?: {
    getSettings: () => Promise<Record<string, unknown>>;
    updateSettings: (settings: Record<string, unknown>) => Promise<void>;
  };
  __globalLeadStore?: { getAllLeads: () => Lead[] };
}

interface PlanResult {
  success: boolean;
  error?: string;
}

async function requestCredentialPlan(page: Page, leadId: string): Promise<PlanResult> {
  return page.evaluate(async (id) => {
    const raw: unknown = await chrome.runtime.sendMessage({ type: 'PLAN_CREDENTIAL_CHECK', leadId: id });
    const response = typeof raw === 'object' && raw !== null ? raw as Record<string, unknown> : {};
    const error = typeof response.error === 'string' ? response.error : undefined;
    return {
      success: response.success === true,
      ...(error === undefined ? {} : { error }),
    };
  }, leadId);
}

test('credential setting toggles update background state and invalidate candidates using the real options UI', async () => {
  const port = 3471;
  const { server, baseUrl } = await startServer(port, '127.0.0.1');

  const testExtDir = path.resolve(__dirname, `../../test-results/dist-e2e-credential-${Date.now()}`);
  fs.cpSync(extensionPath, testExtDir, { recursive: true });
  const manifestPath = path.join(testExtDir, 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as {
    host_permissions?: string[];
    optional_host_permissions?: string[];
  };
  manifest.host_permissions = [`http://127.0.0.1/*`];
  manifest.optional_host_permissions = (manifest.optional_host_permissions ?? []).filter((host) => host !== '<all_urls>');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

  const userDataDir = path.resolve(__dirname, `../../test-results/playwright-credential-${Date.now()}`);
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
    const extensionId = new URL(background.url()).host;
    const options = await context.newPage();
    await options.goto(`chrome-extension://${extensionId}/src/options/options.html`);
    await expect(options.locator('#credential-liveness-toggle')).toBeAttached();
    await options.waitForTimeout(500);
    await expect(options.locator('#credential-liveness-toggle')).not.toBeChecked();

    // Set only the local test scope and normal monitoring prerequisites; leave
    // liveness off, then perform the liveness toggle itself through the UI.
    const preparedSettings = await background.evaluate(async () => {
      const service = (self as unknown as BackgroundWindow).__SettingsService;
      if (service === undefined) throw new Error('settings service not exposed');
      const settings = await service.getSettings();
      settings.monitoringMode = 'per-site';
      settings.leadsEnabled = true;
      settings.credentialLivenessEnabled = false;
      settings.scopeProfiles = [{
        id: 'credential-local-test',
        name: 'Local synthetic test',
        rules: [{ pattern: '127.0.0.1', type: 'include' }],
      }];
      settings.activeScopeProfileId = 'credential-local-test';
      await service.updateSettings(settings);
      return settings;
    });
    const transitioned = await options.evaluate(async (settings) => {
      const raw: unknown = await chrome.runtime.sendMessage({ type: 'SETTINGS_CHANGED', settings });
      const response = typeof raw === 'object' && raw !== null ? raw as Record<string, unknown> : {};
      return { success: response.success === true };
    }, preparedSettings);
    expect(transitioned.success).toBe(true);
    await options.reload();
    await options.waitForTimeout(700);
    await options.locator('.nav-item[data-section="leads"]').click();
    await options.locator('#credential-liveness-toggle').check();
    await options.locator('#save-btn').click();
    await expect(options.locator('#save-status')).toContainText('Settings saved');
    await expect.poll(async () => background.evaluate(async () =>
      (await (self as unknown as BackgroundWindow).__SettingsService?.getSettings())?.credentialLivenessEnabled
    )).toBe(true);

    const providerPermissionGranted = await options.evaluate(async () =>
      await chrome.permissions.contains({ origins: ['https://api.github.com/*'] }));
    expect(providerPermissionGranted).toBe(false);

    const page = await context.newPage();
    await page.goto(`${baseUrl}/lead-lab/credential-setting`);
    await page.waitForLoadState('networkidle');
    let lead: Lead | undefined;
    await expect.poll(async () => {
      const leads = await background.evaluate(() =>
        (self as unknown as BackgroundWindow).__globalLeadStore?.getAllLeads() ?? []);
      lead = leads.find((item) => item.family === 'F1' && item.tags?.includes('github'));
      return Boolean(lead);
    }, { timeout: 10_000 }).toBe(true);
    expect(lead?.scopeStatus).toBe('in-scope');
    expect(lead?.evidence.preview).not.toContain(fakeGithubToken);

    const panel = await context.newPage();
    await panel.goto(`chrome-extension://${extensionId}/src/sidepanel/sidepanel.html`);
    if (lead === undefined) throw new Error('Synthetic GitHub lead was not captured');
    const planned = await requestCredentialPlan(panel, lead.id);
    expect(planned.success).toBe(true);

    // Disable only this toggle; do not change a tracked neighboring setting.
    await options.locator('#credential-liveness-toggle').uncheck();
    await options.locator('#save-btn').click();
    await expect(options.locator('#save-status')).toContainText('Settings saved');
    await expect.poll(async () => background.evaluate(async () =>
      (await (self as unknown as BackgroundWindow).__SettingsService?.getSettings())?.credentialLivenessEnabled
    )).toBe(false);
    const storage = await options.evaluate(async () => ({
      local: await chrome.storage.local.get(null),
      session: await chrome.storage.session.get(null),
    }));
    expect(JSON.stringify(storage)).not.toContain(fakeGithubToken);

    const planAfterDisable = await requestCredentialPlan(panel, lead.id);
    expect(planAfterDisable.success).toBe(false);
    expect(planAfterDisable.error).toMatch(/disabled/i);

    // Re-enable without rescanning: raw candidate must have been discarded.
    await options.locator('#credential-liveness-toggle').check();
    await options.locator('#save-btn').click();
    await expect(options.locator('#save-status')).toContainText('Settings saved');
    await expect.poll(async () => background.evaluate(async () =>
      (await (self as unknown as BackgroundWindow).__SettingsService?.getSettings())?.credentialLivenessEnabled
    )).toBe(true);
    const planWithoutCandidate = await requestCredentialPlan(panel, lead.id);
    expect(planWithoutCandidate.success).toBe(false);
    expect(planWithoutCandidate.error).toMatch(/candidate|available/i);

    await panel.close();
    await page.close();
    await options.close();
  } finally {
    if (context !== undefined) await context.close();
    server.close();
    fs.rmSync(testExtDir, { recursive: true, force: true });
    fs.rmSync(userDataDir, { recursive: true, force: true });
  }
});

test('credential-liveness toggle alone marks settings dirty, exposes Discard, triggers unsaved navigation guard, and cleanly discards', async () => {
  const userDataDir = path.resolve(__dirname, `../../test-results/playwright-cred-dirty-${Date.now()}`);
  const testExtDir = path.resolve(__dirname, `../../test-results/dist-e2e-cred-dirty-${Date.now()}`);
  fs.cpSync(extensionPath, testExtDir, { recursive: true });

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
    const extensionId = new URL(background.url()).host;
    const options = await context.newPage();
    await options.goto(`chrome-extension://${extensionId}/src/options/options.html`);

    // Wait for options page to fully initialize
    await options.waitForFunction(() => {
      const badge = document.getElementById('nav-dirty-badge');
      return badge !== null;
    }, undefined, { timeout: 10_000 });
    await options.waitForTimeout(600);

    // Navigate to leads section to expose the credential liveness toggle
    await options.locator('.nav-item[data-section="leads"]').click();
    await options.waitForTimeout(300);

    // Precondition: toggle unchecked, dirty indicators hidden
    await expect(options.locator('#credential-liveness-toggle')).not.toBeChecked();
    await expect(options.locator('#nav-dirty-badge')).toBeHidden();
    await expect(options.locator('#btn-discard')).toBeHidden();

    // ACT: check the credential liveness toggle
    await options.locator('#credential-liveness-toggle').check();

    // ASSERT: dirty indicators now visible, save-status says unsaved
    await expect(options.locator('#nav-dirty-badge')).toBeVisible();
    await expect(options.locator('#btn-discard')).toBeVisible();
    await expect(options.locator('#save-status')).toContainText('Unsaved changes');

    // ASSERT: unsaved navigation guard fires when switching sections
    await options.locator('.nav-item[data-section="monitoring"]').click();
    await expect(options.locator('#unsaved-dialog')).toHaveAttribute('open');

    // Cancel the dialog — dirty state must remain
    await options.locator('#dialog-cancel').click();
    await expect(options.locator('#nav-dirty-badge')).toBeVisible();
    await expect(options.locator('#btn-discard')).toBeVisible();

    // ACT: discard via the top-bar button
    await options.locator('#btn-discard').click();
    await options.waitForTimeout(400);

    // ASSERT: toggle reverted, dirty indicators gone
    await expect(options.locator('#credential-liveness-toggle')).not.toBeChecked();
    await expect(options.locator('#nav-dirty-badge')).toBeHidden();
    await expect(options.locator('#btn-discard')).toBeHidden();

    // ASSERT: background storage still has credentialLivenessEnabled = false
    const storedValue = await background.evaluate(async () => {
      const service = (self as unknown as BackgroundWindow).__SettingsService;
      if (service === undefined) throw new Error('settings service not exposed');
      const settings = await service.getSettings();
      return settings['credentialLivenessEnabled'];
    });
    expect(storedValue).toBe(false);

    await options.close();
  } finally {
    if (context !== undefined) await context.close();
    fs.rmSync(testExtDir, { recursive: true, force: true });
    fs.rmSync(userDataDir, { recursive: true, force: true });
  }
});
