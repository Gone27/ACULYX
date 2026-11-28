/**
 * @file sidepanel-capture-motion.spec.ts
 * Real Chromium E2E tests for Appendix E deliverables:
 *  - Visible ACULYX wordmark branding across popup and sidepanel (including 320px compact)
 *  - Sidepanel state-aware Capture CTA flow (`restricted`, `monitoring-off`,
 *    `permission-needed`, `access-granted-reload`, `capturing`)
 *  - Ninja motion guardrails:
 *    - Katana slash grade reveal triggers only on grade change (no replay on identical update)
 *    - Smoke-soft stagger capped at <= 8 items even with 100+ leads/findings
 *    - Shuriken loader active only while scanning and disabled in reduced motion
 *    - One-shot radar blip ping for newly discovered leads only
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, expect, chromium, type BrowserContext, type Worker, type Page } from '@playwright/test';
import { startServer, type TestServerHandle } from '../server';
import type { SettingsService } from '../../src/shared/settings';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const extensionPath = path.resolve(__dirname, '../../dist');

interface BackgroundGlobals {
  __SettingsService?: typeof SettingsService;
}

async function getTabIdForUrl(helperPage: Page, urlPrefix: string): Promise<number> {
  const id = await helperPage.evaluate(async (prefix) => {
    const tabs = await chrome.tabs.query({});
    const match = tabs.find((t) => typeof t.url === 'string' && t.url.startsWith(prefix));
    return match?.id ?? null;
  }, urlPrefix);
  if (typeof id !== 'number') {
    throw new Error(`Could not resolve Chrome tabId for ${urlPrefix}`);
  }
  return id;
}

async function setExtensionSettings(
  background: Worker,
  mode: 'off' | 'per-site' | 'all-sites',
): Promise<void> {
  const updated = await background.evaluate(async (monitoringMode) => {
    const svc = (self as unknown as BackgroundGlobals).__SettingsService;
    if (!svc) throw new Error('SettingsService not exposed on background');
    const settings = await svc.getSettings();
    settings.monitoringMode = monitoringMode;
    settings.leadsEnabled = true;
    await svc.updateSettings(settings);
    return settings;
  }, mode);
  await background.evaluate((settings) => {
    chrome.runtime.sendMessage({ type: 'SETTINGS_CHANGED', settings }).catch(() => undefined);
  }, updated);
}

test.describe('Appendix E: Branding, Sidepanel Capture CTA, and Ninja Motion', () => {
  let serverIp: TestServerHandle;
  let serverLocalhost: TestServerHandle;
  let tempExtDir: string;

  test.beforeAll(async () => {
    [serverIp, serverLocalhost] = await Promise.all([
      startServer(0, '127.0.0.1'),
      startServer(0, 'localhost'),
    ]);
  });

  test.afterAll(async () => {
    await Promise.all([
      new Promise<void>((resolve) => serverIp.server.close(() => resolve())),
      new Promise<void>((resolve) => serverLocalhost.server.close(() => resolve())),
    ]);
    if (tempExtDir && fs.existsSync(tempExtDir)) {
      fs.rmSync(tempExtDir, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
    }
  });

  test('verifies sidepanel Capture CTA state transitions and wordmark visibility', async () => {
    tempExtDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aculyx-capture-motion-e2e-'));
    fs.cpSync(extensionPath, tempExtDir, { recursive: true });

    // Pre-grant 127.0.0.1 only; leave localhost as ungranted optional host permission
    const manifestPath = path.join(tempExtDir, 'manifest.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as {
      host_permissions?: string[];
      optional_host_permissions?: string[];
    };
    manifest.host_permissions = ['http://127.0.0.1/*'];
    manifest.optional_host_permissions = ['http://*/*', 'https://*/*'];
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
      expect(extensionId).toBeTruthy();

      // Open target tabs:
      // 1) Start monitoring OFF while visiting pagePreGrantedNoScan so no scan exists yet
      await setExtensionSettings(background, 'off');
      const pagePreGrantedNoScan = await context.newPage();
      await pagePreGrantedNoScan.goto(`${serverIp.baseUrl}/good-headers`, { waitUntil: 'load' });

      // 2) Ungranted localhost tab
      const pageUngranted = await context.newPage();
      await pageUngranted.goto(`${serverLocalhost.baseUrl}/good-headers`, { waitUntil: 'load' });

      // 3) Restricted about:blank tab
      const pageBlank = await context.newPage();
      await pageBlank.goto('about:blank');

      const sidepanelPage = await context.newPage();
      await sidepanelPage.setViewportSize({ width: 380, height: 680 });
      await sidepanelPage.goto(`chrome-extension://${extensionId}/src/sidepanel/sidepanel.html`);

      // Check monitoring-off state on an HTTP tab
      const preGrantedTabId = await getTabIdForUrl(sidepanelPage, serverIp.baseUrl);
      const ungrantedTabId = await getTabIdForUrl(sidepanelPage, serverLocalhost.baseUrl);
      const blankTabId = await getTabIdForUrl(sidepanelPage, 'about:blank');

      await sidepanelPage.goto(`chrome-extension://${extensionId}/src/sidepanel/sidepanel.html?tabId=${preGrantedTabId}`);
      await expect(sidepanelPage.locator('#sp-capture-bar')).toHaveAttribute('data-capture-state', 'warning');
      await expect(sidepanelPage.locator('#sp-capture-status')).toContainText('Monitoring is Off');
      await expect(sidepanelPage.locator('#sp-capture-btn')).toBeHidden();
      await expect(sidepanelPage.locator('#sp-reload-capture-btn')).toBeHidden();
      await expect(sidepanelPage.locator('#sp-scan-shuriken')).toHaveAttribute('data-scanning', 'false');

      // Switch to per-site mode while preGrantedNoScan still has no captured scan -> access-granted-reload
      await setExtensionSettings(background, 'per-site');
      await sidepanelPage.goto(`chrome-extension://${extensionId}/src/sidepanel/sidepanel.html?tabId=${preGrantedTabId}`);
      await expect(sidepanelPage.locator('#sp-capture-bar')).toHaveAttribute('data-capture-state', 'access-granted-reload');
      await expect(sidepanelPage.locator('#sp-reload-capture-btn')).toBeVisible();
      await expect(sidepanelPage.locator('#sp-reload-capture-btn')).toHaveText('Reload page to start capture');
      await expect(sidepanelPage.locator('#sp-capture-btn')).toBeHidden();

      // Click user-initiated Reload button -> transitions into captured / capturing state with Grade A
      await sidepanelPage.locator('#sp-reload-capture-btn').click();
      await expect(sidepanelPage.locator('#sp-capture-bar')).toHaveAttribute('data-capture-state', 'capturing', { timeout: 10_000 });
      await expect(sidepanelPage.locator('#sp-capture-btn')).toBeHidden();
      await expect(sidepanelPage.locator('#sp-reload-capture-btn')).toBeHidden();
      await expect(sidepanelPage.locator('#sp-scan-shuriken')).toHaveAttribute('data-scanning', 'false', { timeout: 5_000 });

      // Check restricted (about:blank) state
      await sidepanelPage.goto(`chrome-extension://${extensionId}/src/sidepanel/sidepanel.html?tabId=${blankTabId}`);
      await expect(sidepanelPage.locator('#sp-capture-bar')).toHaveAttribute('data-capture-state', 'restricted');
      await expect(sidepanelPage.locator('#sp-capture-btn')).toBeHidden();

      // Check permission-needed (ungranted localhost) state & port-unconstrained disclosure
      await sidepanelPage.goto(`chrome-extension://${extensionId}/src/sidepanel/sidepanel.html?tabId=${ungrantedTabId}`);
      await expect(sidepanelPage.locator('#sp-capture-bar')).toHaveAttribute('data-capture-state', 'permission-needed');
      await expect(sidepanelPage.locator('#sp-capture-status')).toContainText('all ports');
      await expect(sidepanelPage.locator('#sp-capture-btn')).toBeVisible();
      await expect(sidepanelPage.locator('#sp-capture-btn')).toHaveText('Capture this site');

      // Exercise actual #sp-capture-btn click: denial -> retry grant -> stale-tab navigation race guard
      await sidepanelPage.evaluate(() => {
        const w = window as unknown as {
          __permRequests: string[][];
          __permGrantNext: boolean;
          __permGrantedSet: Set<string>;
          __permDefer?: (granted: boolean) => void;
          __permHold: boolean;
        };
        w.__permRequests = [];
        w.__permGrantNext = false;
        w.__permGrantedSet = new Set<string>();
        w.__permHold = false;

        const perms = chrome.permissions as unknown as {
          request: (perms: chrome.permissions.Permissions, cb?: (granted: boolean) => void) => void;
          contains: (perms: chrome.permissions.Permissions, cb?: (result: boolean) => void) => void;
        };
        perms.contains = (query, cb) => {
          const allHit = (query.origins ?? []).length > 0 && (query.origins ?? []).every((o) => w.__permGrantedSet.has(o));
          cb?.(allHit);
        };
        perms.request = (req, cb) => {
          const origins = req.origins ?? [];
          w.__permRequests.push([...origins]);
          const finish = (granted: boolean) => {
            if (granted) {
              for (const o of origins) w.__permGrantedSet.add(o);
            }
            cb?.(granted);
          };
          if (w.__permHold) {
            w.__permDefer = finish;
            return;
          }
          finish(w.__permGrantNext);
        };
      });

      // 1) User denies -> denied state + retry prompt preserved + port dropped in match pattern
      await sidepanelPage.locator('#sp-capture-btn').click();
      await expect(sidepanelPage.locator('#sp-capture-bar')).toHaveAttribute('data-capture-state', 'denied');
      await expect(sidepanelPage.locator('#sp-capture-status')).toContainText('all ports');
      await expect(sidepanelPage.locator('#sp-capture-btn')).toBeEnabled();
      const firstRequested = await sidepanelPage.evaluate(
        () => (window as unknown as { __permRequests: string[][] }).__permRequests[0],
      );
      expect(firstRequested).toEqual(['http://localhost/*']);

      // 2) User retries and grants -> access-granted-reload with user-controlled reload button
      await sidepanelPage.evaluate(() => {
        (window as unknown as { __permGrantNext: boolean }).__permGrantNext = true;
      });
      await sidepanelPage.locator('#sp-capture-btn').click();
      await expect(sidepanelPage.locator('#sp-capture-bar')).toHaveAttribute('data-capture-state', 'access-granted-reload');
      await expect(sidepanelPage.locator('#sp-reload-capture-btn')).toBeVisible();

      // 3) Stale-tab navigation race: hold request open, switch tab to restricted, resolve late callback -> stays restricted
      await sidepanelPage.evaluate(() => {
        const w = window as unknown as { __permGrantedSet: Set<string>; __permHold: boolean };
        w.__permGrantedSet.clear();
        w.__permHold = true;
      });
      await sidepanelPage.goto(`chrome-extension://${extensionId}/src/sidepanel/sidepanel.html?tabId=${ungrantedTabId}`);
      await expect(sidepanelPage.locator('#sp-capture-bar')).toHaveAttribute('data-capture-state', 'permission-needed');
      await sidepanelPage.evaluate(() => {
        const w = window as unknown as {
          __permRequests: string[][];
          __permDefer?: (granted: boolean) => void;
          __permHold: boolean;
        };
        w.__permRequests = [];
        w.__permHold = true;
        const perms = chrome.permissions as unknown as {
          request: (perms: chrome.permissions.Permissions, cb?: (granted: boolean) => void) => void;
        };
        perms.request = (req, cb) => {
          w.__permRequests.push([...(req.origins ?? [])]);
          w.__permDefer = (granted: boolean) => cb?.(granted);
        };
      });
      await sidepanelPage.locator('#sp-capture-btn').click();
      await pageBlank.bringToFront();
      await expect(sidepanelPage.locator('#sp-capture-bar')).toHaveAttribute('data-capture-state', 'restricted');
      await sidepanelPage.evaluate(() => {
        (window as unknown as { __permDefer?: (granted: boolean) => void }).__permDefer?.(true);
      });
      await sidepanelPage.waitForTimeout(100);
      await expect(sidepanelPage.locator('#sp-capture-bar')).toHaveAttribute('data-capture-state', 'restricted');

      // Wordmark branding check across 740px, 380px, and 320px viewports (asserting original 1024x395 PNG)
      const screenshotOutDir = path.resolve(__dirname, '../../test-results/wordmark-layout');
      fs.mkdirSync(screenshotOutDir, { recursive: true });
      for (const vp of [
        { width: 740, height: 720, expectStacked: false, snap: 'sidepanel-740px.png' },
        { width: 380, height: 680, expectStacked: true, snap: 'sidepanel-380px.png' },
        { width: 320, height: 600, expectStacked: true, snap: 'sidepanel-320px.png' },
      ]) {
        await sidepanelPage.setViewportSize({ width: vp.width, height: vp.height });
        const wmStats = await sidepanelPage.evaluate(() => {
          const img = document.querySelector<HTMLImageElement>('.header-wordmark');
          const actions = document.querySelector<HTMLElement>('.header-actions');
          const imgRect = img?.getBoundingClientRect();
          const actRect = actions?.getBoundingClientRect();
          return {
            complete: img?.complete ?? false,
            currentSrc: img?.currentSrc ?? '',
            alt: img?.getAttribute('alt') ?? '',
            naturalWidth: img?.naturalWidth ?? 0,
            naturalHeight: img?.naturalHeight ?? 0,
            width: imgRect?.width ?? 0,
            height: imgRect?.height ?? 0,
            imgRight: imgRect?.right ?? 0,
            imgBottom: imgRect?.bottom ?? 0,
            actLeft: actRect?.left ?? 0,
            actTop: actRect?.top ?? 0,
            noHScroll: document.documentElement.scrollWidth <= window.innerWidth + 1,
          };
        });
        expect(wmStats.complete).toBe(true);
        expect(wmStats.alt).toBe('ACULYX — Header & Cookie Security Checker');
        expect(wmStats.currentSrc).toContain('aculyx-wordmark');
        expect(wmStats.currentSrc).toMatch(/\.png($|\?)/);
        expect(wmStats.naturalWidth).toBe(1024);
        expect(wmStats.naturalHeight).toBe(395);
        expect(wmStats.width).toBeGreaterThanOrEqual(160);
        expect(Math.abs(wmStats.width / wmStats.height - 1024 / 395)).toBeLessThan(0.15);
        expect(wmStats.noHScroll).toBe(true);
        if (vp.expectStacked) {
          expect(wmStats.imgBottom).toBeLessThanOrEqual(wmStats.actTop + 2);
        } else {
          expect(wmStats.imgRight).toBeLessThanOrEqual(wmStats.actLeft + 2);
        }
        await expect(sidepanelPage.locator('#sp-capture-bar')).toBeVisible();
        await sidepanelPage.evaluate(() => {
          const ov = document.getElementById('view-overview');
          if (ov) ov.scrollTop = 0;
        });
        await sidepanelPage.screenshot({ path: path.join(screenshotOutDir, vp.snap) });
      }

      await sidepanelPage.close();
      await pageBlank.close();
      await pageUngranted.close();
      await pagePreGrantedNoScan.close();
    } finally {
      if (context) await context.close().catch(() => {});
    }
  });

  test('verifies Ninja motion guardrails (Katana grade-only, Smoke <= 8 cap, Shuriken, Radar ping, reduced motion)', async () => {
    const extDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aculyx-motion-e2e-'));
    fs.cpSync(extensionPath, extDir, { recursive: true });

    const manifestPath = path.join(extDir, 'manifest.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as {
      host_permissions?: string[];
    };
    manifest.host_permissions = ['http://127.0.0.1/*'];
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

    let context: BrowserContext | undefined;
    try {
      context = await chromium.launchPersistentContext('', {
        headless: false,
        args: [
          '--headless=new',
          `--disable-extensions-except=${extDir}`,
          `--load-extension=${extDir}`,
          '--no-sandbox',
        ],
      });

      let [background] = context.serviceWorkers();
      if (!background) {
        background = await context.waitForEvent('serviceworker', { timeout: 10_000 });
      }
      const extensionId = background.url().split('/')[2];
      await setExtensionSettings(background, 'per-site');

      const targetPage = await context.newPage();
      await targetPage.goto(`${serverIp.baseUrl}/no-headers`, { waitUntil: 'load' });
      // Wait briefly for webRequest / background state to finalize
      await targetPage.waitForTimeout(300);

      // ── Popup Katana grade reveal & Smoke-soft cap ────────────
      const popupPage = await context.newPage();
      await popupPage.addInitScript(() => {
        (window as unknown as { __gradeRevealAdds: number; __smokeAdds: number }).__gradeRevealAdds = 0;
        (window as unknown as { __gradeRevealAdds: number; __smokeAdds: number }).__smokeAdds = 0;
        document.addEventListener('DOMContentLoaded', () => {
          const badge = document.getElementById('grade-badge');
          if (badge) {
            const obs = new MutationObserver((muts) => {
              const last = muts[muts.length - 1];
              const prevTokens = (last?.oldValue ?? '').split(/\s+/);
              if (!prevTokens.includes('motion-grade-reveal') && badge.classList.contains('motion-grade-reveal')) {
                (window as unknown as { __gradeRevealAdds: number }).__gradeRevealAdds += 1;
              }
            });
            obs.observe(badge, { attributes: true, attributeFilter: ['class'], attributeOldValue: true });
          }
          const list = document.getElementById('findings-list');
          if (list) {
            const obsList = new MutationObserver((muts) => {
              for (const m of muts) {
                for (const n of m.addedNodes) {
                  if (n instanceof HTMLElement && n.classList.contains('motion-smoke-enter')) {
                    (window as unknown as { __smokeAdds: number }).__smokeAdds += 1;
                  }
                }
              }
            });
            obsList.observe(list, { childList: true });
          }
        });
      });

      const tabId = await background.evaluate(async (prefix) => {
        const tabs = await chrome.tabs.query({});
        const match = tabs.find((t) => typeof t.url === 'string' && t.url.startsWith(prefix));
        return match?.id ?? null;
      }, serverIp.baseUrl);
      if (typeof tabId !== 'number') {
        throw new Error(`Could not resolve Chrome tabId for ${serverIp.baseUrl}`);
      }

      await popupPage.goto(`chrome-extension://${extensionId}/src/popup/popup.html?tabId=${tabId}`);
      await expect(popupPage.locator('#grade-badge')).toBeVisible();
      await expect(popupPage.locator('#findings-list li').first()).toBeVisible();

      // Initial grade render triggered Katana reveal once, and Smoke-soft items capped <= 8
      const initialMetrics = await popupPage.evaluate(() => {
        const w = window as unknown as { __gradeRevealAdds: number; __smokeAdds: number };
        const img = document.querySelector<HTMLImageElement>('.header-wordmark');
        const rect = img?.getBoundingClientRect();
        return {
          gradeReveals: w.__gradeRevealAdds,
          smokeAdds: w.__smokeAdds,
          wordmarkLoaded: img ? img.complete && img.naturalWidth === 1024 && img.naturalHeight === 395 : false,
          currentSrc: img?.currentSrc ?? '',
          ratio: rect && rect.height > 0 ? rect.width / rect.height : 0,
        };
      });
      expect(initialMetrics.wordmarkLoaded).toBe(true);
      expect(initialMetrics.currentSrc).toContain('aculyx-wordmark');
      expect(initialMetrics.currentSrc).toMatch(/\.png($|\?)/);
      expect(Math.abs(initialMetrics.ratio - 1024 / 395)).toBeLessThan(0.15);
      await popupPage.screenshot({ path: path.resolve(__dirname, '../../test-results/wordmark-layout/popup-380px.png') });
      expect(initialMetrics.gradeReveals).toBe(1);
      expect(initialMetrics.smokeAdds).toBeGreaterThan(0);
      expect(initialMetrics.smokeAdds).toBeLessThanOrEqual(8);

      // Re-load identical /no-headers page (same origin & same grade) -> Katana reveal MUST NOT replay
      await targetPage.goto(`${serverIp.baseUrl}/no-headers`, { waitUntil: 'load' });
      await popupPage.waitForTimeout(420);
      const revealsAfterIdenticalGrade = await popupPage.evaluate(
        () => (window as unknown as { __gradeRevealAdds: number }).__gradeRevealAdds,
      );
      expect(revealsAfterIdenticalGrade).toBe(1);
      // After animation timeout cleanup, lingering motion-grade-reveal must be removed
      await expect(popupPage.locator('#grade-badge')).not.toHaveClass(/motion-grade-reveal/);
      await expect(popupPage.locator('#popup-scan-shuriken')).toHaveAttribute('data-scanning', 'false');

      // Navigate targetPage from /no-headers -> /good-headers -> grade changes -> Katana reveal increments
      await targetPage.goto(`${serverIp.baseUrl}/good-headers`, { waitUntil: 'load' });
      await expect(async () => {
        const reveals = await popupPage.evaluate(
          () => (window as unknown as { __gradeRevealAdds: number }).__gradeRevealAdds,
        );
        expect(reveals).toBeGreaterThanOrEqual(2);
      }).toPass({ timeout: 5_000 });

      // ── Sidepanel 100+ Leads Smoke-Soft Cap & Radar Ping ─────
      const sidepanelPage = await context.newPage();
      await sidepanelPage.setViewportSize({ width: 380, height: 680 });
      await sidepanelPage.goto(`chrome-extension://${extensionId}/src/sidepanel/sidepanel.html?tabId=${tabId}`);
      await expect(sidepanelPage.locator('.header-wordmark')).toBeVisible();

      const origin = serverIp.baseUrl;
      const manyLeads = Array.from({ length: 120 }, (_, i) => ({
        id: `LD-BULK-${i + 1}`,
        ruleId: 'SEC-001',
        family: 'F1',
        tier: 'observed',
        potential: i < 5 ? 'critical' : i < 15 ? 'high' : 'medium',
        confidence: 0.9,
        title: `Synthetic lead #${i + 1}`,
        needs: ['Inspect'],
        doesNotProve: ['Exploit'],
        evidence: { preview: `tok_${i}`, location: `${origin}/app.js:${i + 1}` },
        tags: ['secret'],
        scopeStatus: 'in-scope',
        timestamp: 1_700_000_000_000 + i,
        origin,
        url: `${origin}/app.js`,
        sourceSensor: 'S1',
      }));

      // Switch to Findings view first so Smoke-soft class insertion is observable immediately
      await sidepanelPage.locator('#tab-findings').click();
      await popupPage.evaluate(
        ({ o, tid, leads }) => {
          void chrome.runtime.sendMessage({
            type: 'LEAD_STATE_UPDATE',
            origin: o,
            tabId: tid,
            leads,
          }).catch(() => undefined);
        },
        { o: origin, tid: tabId, leads: manyLeads },
      );

      await expect(sidepanelPage.locator('#sp-leads-list .lead-card').first()).toBeVisible({ timeout: 5_000 });
      const animatedCardCount = await sidepanelPage.locator('#sp-leads-list .lead-card.motion-smoke-enter').count();
      expect(animatedCardCount).toBeGreaterThan(0);
      expect(animatedCardCount).toBeLessThanOrEqual(8);

      // Radar pings for 120 new leads must be capped (<= 6), not 120 simultaneous pings
      const pingCount = await sidepanelPage.locator('#sp-radar-blips .radar-blip-ping').count();
      expect(pingCount).toBeGreaterThan(0);
      expect(pingCount).toBeLessThanOrEqual(6);

      // Clean up after ~850ms (smoke <= 520ms + radar ping 700ms)
      await sidepanelPage.waitForTimeout(850);
      expect(await sidepanelPage.locator('#sp-leads-list .lead-card.motion-smoke-enter').count()).toBe(0);
      expect(await sidepanelPage.locator('#sp-radar-blips .radar-blip-ping').count()).toBe(0);
      await expect(popupPage.locator('#grade-badge .badge-scan.shuriken-loader')).toBeHidden();

      // Overview radar pings & reduced motion disable ALL effects across popup & sidepanel
      await sidepanelPage.locator('#tab-overview').click();
      await sidepanelPage.evaluate(() => {
        document.documentElement.setAttribute('data-motion', 'reduce');
        const shuriken = document.getElementById('sp-scan-shuriken');
        if (shuriken) shuriken.setAttribute('data-scanning', 'true');
        const firstCard = document.querySelector('#sp-leads-list .lead-card');
        if (firstCard) firstCard.classList.add('motion-smoke-enter');
      });
      const reducedSidepanel = await sidepanelPage.evaluate(() => {
        const shuriken = document.getElementById('sp-scan-shuriken');
        const card = document.querySelector('#sp-leads-list .lead-card.motion-smoke-enter');
        const cardAfter = card ? window.getComputedStyle(card, '::after').animationName : 'none';
        return {
          shuriken: shuriken ? window.getComputedStyle(shuriken).animationName : 'missing',
          card: card ? window.getComputedStyle(card).animationName : 'missing',
          cardAfter,
        };
      });
      expect(reducedSidepanel.shuriken).toBe('none');
      expect(reducedSidepanel.card).toBe('none');
      expect(reducedSidepanel.cardAfter).toBe('none');

      await popupPage.evaluate(() => {
        document.documentElement.setAttribute('data-motion', 'reduce');
        const badge = document.getElementById('grade-badge');
        if (badge) badge.classList.add('motion-grade-reveal');
        const badgeShuriken = document.getElementById('badge-scan-shuriken');
        if (badgeShuriken) badgeShuriken.setAttribute('data-scanning', 'true');
      });
      const reducedPopup = await popupPage.evaluate(() => {
        const shield = document.querySelector('#grade-badge .badge-shield');
        const letter = document.querySelector('#grade-badge .badge-grade');
        const badge = document.getElementById('grade-badge');
        const badgeShuriken = document.getElementById('badge-scan-shuriken');
        return {
          shield: shield ? window.getComputedStyle(shield).animationName : 'missing',
          letter: letter ? window.getComputedStyle(letter).animationName : 'missing',
          glint: badge ? window.getComputedStyle(badge, '::after').animationName : 'missing',
          shuriken: badgeShuriken ? window.getComputedStyle(badgeShuriken).animationName : 'missing',
        };
      });
      expect(reducedPopup.shield).toBe('none');
      expect(reducedPopup.letter).toBe('none');
      expect(reducedPopup.glint).toBe('none');
      expect(reducedPopup.shuriken).toBe('none');

      // OS prefers-reduced-motion: reduce + data-motion="no-reduce" ("Never reduce") keeps animations enabled
      await popupPage.emulateMedia({ reducedMotion: 'reduce' });
      await popupPage.evaluate(() => {
        document.documentElement.setAttribute('data-motion', 'no-reduce');
      });
      const overriddenAnim = await popupPage.evaluate(() => {
        const shield = document.querySelector('#grade-badge .badge-shield');
        return shield ? window.getComputedStyle(shield).animationName : 'missing';
      });
      expect(overriddenAnim).toBe('shieldGradeSnap');
      await popupPage.emulateMedia({ reducedMotion: null });

      // Verify corrected sidepanel motion labels in Settings
      await sidepanelPage.locator('#options-link').click();
      await expect(sidepanelPage.locator('#sp-setting-motion option[value="always"]')).toHaveText('Always reduce (animations off)');
      await expect(sidepanelPage.locator('#sp-setting-motion option[value="never"]')).toHaveText('Never reduce (animations on)');

      await sidepanelPage.close();
      await popupPage.close();
      await targetPage.close();
    } finally {
      if (context) await context.close().catch(() => {});
      if (fs.existsSync(extDir)) {
        fs.rmSync(extDir, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
      }
    }
  });
});
