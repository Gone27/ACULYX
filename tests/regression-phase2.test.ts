import { describe, it, expect, beforeEach, vi } from 'vitest';

const { webRequestListeners } = vi.hoisted(() => {
  const dummyEvent = () => ({
    addListener: vi.fn(),
    removeListener: vi.fn(),
    hasListener: vi.fn(),
  });

  const webRequestListeners: Record<string, Array<(...args: unknown[]) => unknown>> = {
    onBeforeSendHeaders: [],
    onHeadersReceived: [],
    onResponseStarted: [],
    onBeforeRedirect: [],
    onErrorOccurred: [],
    onCompleted: [],
  };

  const createWebRequestListener = (eventName: string) => ({
    addListener: vi.fn((listener: (...args: unknown[]) => unknown) => {
      webRequestListeners[eventName]?.push(listener);
    }),
    removeListener: vi.fn(),
    hasListener: vi.fn(),
  });

  (globalThis as unknown as { chrome: unknown }).chrome = {
    webNavigation: {
      onBeforeNavigate: dummyEvent(),
      onCommitted: dummyEvent(),
      onHistoryStateUpdated: dummyEvent(),
    },
    webRequest: {
      onBeforeSendHeaders: createWebRequestListener('onBeforeSendHeaders'),
      onHeadersReceived: createWebRequestListener('onHeadersReceived'),
      onResponseStarted: createWebRequestListener('onResponseStarted'),
      onBeforeRedirect: createWebRequestListener('onBeforeRedirect'),
      onErrorOccurred: createWebRequestListener('onErrorOccurred'),
      onCompleted: createWebRequestListener('onCompleted'),
    },
    cookies: {
      onChanged: dummyEvent(),
      getAll: vi.fn().mockResolvedValue([]),
    },
    tabs: {
      onRemoved: dummyEvent(),
      query: vi.fn((_q: unknown, cb?: (tabs: unknown[]) => void) => {
        if (typeof cb === 'function') cb([]);
        return Promise.resolve([]);
      }),
      get: vi.fn(),
      create: vi.fn().mockResolvedValue({}),
      reload: vi.fn().mockResolvedValue(undefined),
    },
    runtime: {
      id: 'mock-extension-id',
      onConnect: dummyEvent(),
      onMessage: dummyEvent(),
      getURL: vi.fn((path: string) => `chrome-extension://mock/${path}`),
    },
    action: {
      setBadgeText: vi.fn().mockResolvedValue(undefined),
      setBadgeBackgroundColor: vi.fn().mockResolvedValue(undefined),
    },
    alarms: {
      get: vi.fn((_name: string, cb?: (a: unknown) => void) => { if (cb) cb(null); }),
      create: vi.fn(),
      onAlarm: dummyEvent(),
    },
    sidePanel: {
      setPanelBehavior: vi.fn().mockResolvedValue(undefined),
    },
    permissions: {
      onRemoved: dummyEvent(),
      onAdded: dummyEvent(),
      getAll: vi.fn().mockResolvedValue({ origins: [] }),
    },
    storage: {
      local: {
        get: vi.fn().mockResolvedValue({}),
        set: vi.fn().mockResolvedValue(undefined),
        remove: vi.fn().mockResolvedValue(undefined),
      },
      session: {
        get: vi.fn().mockResolvedValue({}),
        set: vi.fn().mockResolvedValue(undefined),
        remove: vi.fn().mockResolvedValue(undefined),
      },
    },
  };

  return { webRequestListeners };
});

import fs from 'fs';
import path from 'path';
import { computeScore } from '../src/rules/scoring';
import { CapturePolicy } from '../src/background/capture-policy';
import { registerCaptureListeners, inFlightRequests } from '../src/background/capture';
import { recordThirdPartyBlocked } from '../src/background/index';
import { tabStates } from '../src/background/lifecycle';
import type { Finding, TabState } from '../src/shared/types';

describe('Phase 2 Defect Remediation Regression Suite', () => {
  describe('Defect 1: Commercial Branding Cleanup', () => {
    it('verifies eval-banner and tier-badge classes in sidepanel templates and styles', () => {
      const htmlPath = path.resolve(__dirname, '../src/sidepanel/sidepanel.html');
      const cssPath = path.resolve(__dirname, '../src/sidepanel/sidepanel.css');
      const tsPath = path.resolve(__dirname, '../src/sidepanel/sidepanel.ts');

      const html = fs.readFileSync(htmlPath, 'utf-8');
      expect(html).toContain('id="eval-banner"');
      expect(html).toContain('class="eval-banner"');
      expect(html).not.toContain('id="pro-banner"');
      expect(html).not.toContain('class="pro-banner"');

      const css = fs.readFileSync(cssPath, 'utf-8');
      expect(css).toContain('.tier-badge.evaluation');
      expect(css).toContain('.tier-badge.standard');
      expect(css).toContain('.eval-banner');
      expect(css).not.toContain('.pro-banner');

      const ts = fs.readFileSync(tsPath, 'utf-8');
      expect(ts).toContain("getEl<HTMLDivElement>('eval-banner')");
      expect(ts).toContain("'tier-badge evaluation'");
      expect(ts).toContain("'tier-badge standard'");
      expect(ts).not.toContain("getEl<HTMLDivElement>('pro-banner')");
    });

    it('verifies eval-mode-toggle in options template and script', () => {
      const htmlPath = path.resolve(__dirname, '../src/options/options.html');
      const tsPath = path.resolve(__dirname, '../src/options/options.ts');

      const html = fs.readFileSync(htmlPath, 'utf-8');
      expect(html).toContain('id="eval-mode-toggle"');
      expect(html).toContain('for="eval-mode-toggle"');
      expect(html).not.toContain('id="pro-mode-toggle"');

      const ts = fs.readFileSync(tsPath, 'utf-8');
      expect(ts).toContain("getEl<HTMLInputElement>('eval-mode-toggle')");
      expect(ts).toContain('evalModeToggle');
      expect(ts).not.toContain('proModeToggle');
    });

    it('verifies isEvaluation property support in shared types and background', () => {
      const typesPath = path.resolve(__dirname, '../src/shared/types.ts');
      const indexPath = path.resolve(__dirname, '../src/background/index.ts');

      const types = fs.readFileSync(typesPath, 'utf-8');
      expect(types).toContain('isEvaluation?: boolean;');

      const index = fs.readFileSync(indexPath, 'utf-8');
      expect(index).toContain('const isEvaluation = Boolean(currentSettings.evaluationMode);');
    });
  });

  describe('Defect 2: Third-Party Subresource Blind Spot in CoverageLedger', () => {
    beforeEach(() => {
      tabStates.clear();
      CapturePolicy.setSnapshotForTesting({
        ready: true,
        revision: 20,
        mode: 'per-site',
        broadGrantActive: false,
        grantedOrigins: new Set(['https://monitored.example.com']),
      });
    });

    it('appends third-party-blocked record to state.coverage.ledger when dropped at boundary on monitored tab', () => {
      const tabId = 101;
      const mockState: TabState = {
        tabId,
        origin: 'https://monitored.example.com',
        url: 'https://monitored.example.com/index.html',
        hops: [],
        cookies: [],
        findings: [],
        grade: 'B',
        score: 85,
        scoreVersion: '2.0.0',
        scoreBreakdown: [],
        coverage: {
          hopsExpected: 1,
          hopsCaptured: 1,
          hasCache: false,
          hasServiceWorker: false,
          serviceWorkerStatus: 'unknown',
          serviceWorkerUrl: null,
          isRestricted: false,
          metaCspFound: false,
          ledger: [],
          blindSpots: [],
        },
        subdomainTrust: { hasEscalationPath: false, vectors: [] },
        monitoredByUser: true,
        updatedAt: Date.now(),
      };
      tabStates.set(tabId, mockState);

      // Dropped cross-origin subresource URL with query parameter
      const blockedUrl = 'https://tracker.thirdparty.com/collect?token=secret123&uid=456';
      recordThirdPartyBlocked(tabId, blockedUrl);

      expect(mockState.coverage.ledger).toBeDefined();
      expect(mockState.coverage.ledger?.length).toBe(1);

      const entry = mockState.coverage.ledger?.[0];
      if (entry === undefined) {
        throw new Error('Expected entry in ledger');
      }
      expect(entry.type).toBe('third-party-blocked');
      // Verify URL was sanitized for storage (query params stripped)
      expect(entry.url).not.toContain('secret123');
      expect(entry.url).toBe('https://tracker.thirdparty.com/collect');
      expect(entry.notes).toBe('third-party-blocked');

      // Verify blind spots updated
      expect(mockState.coverage.blindSpots).toEqual(
        expect.arrayContaining([expect.stringContaining('third-party-blocked')]),
      );
    });

    it('ignores same-origin subresources and unmonitored tabs', () => {
      const tabId = 102;
      const mockState: TabState = {
        tabId,
        origin: 'https://monitored.example.com',
        url: 'https://monitored.example.com/index.html',
        hops: [],
        cookies: [],
        findings: [],
        grade: 'A',
        score: 95,
        scoreVersion: '2.0.0',
        scoreBreakdown: [],
        coverage: {
          hopsExpected: 1,
          hopsCaptured: 1,
          hasCache: false,
          hasServiceWorker: false,
          serviceWorkerStatus: 'unknown',
          serviceWorkerUrl: null,
          isRestricted: false,
          metaCspFound: false,
          ledger: [],
          blindSpots: [],
        },
        subdomainTrust: { hasEscalationPath: false, vectors: [] },
        monitoredByUser: false, // Unmonitored!
        updatedAt: Date.now(),
      };
      tabStates.set(tabId, mockState);

      // Should not record for unmonitored tab
      recordThirdPartyBlocked(tabId, 'https://thirdparty.com/api');
      expect(mockState.coverage.ledger?.length).toBe(0);

      // Enable monitoring
      mockState.monitoredByUser = true;

      // Same-origin subresource should not be recorded as third-party-blocked
      recordThirdPartyBlocked(tabId, 'https://monitored.example.com/api/data');
      expect(mockState.coverage.ledger?.length).toBe(0);
    });

    it('enforces 50-entry cap on coverage.ledger', () => {
      const tabId = 103;
      const mockState: TabState = {
        tabId,
        origin: 'https://monitored.example.com',
        url: 'https://monitored.example.com/index.html',
        hops: [],
        cookies: [],
        findings: [],
        grade: 'C',
        score: 75,
        scoreVersion: '2.0.0',
        scoreBreakdown: [],
        coverage: {
          hopsExpected: 1,
          hopsCaptured: 1,
          hasCache: false,
          hasServiceWorker: false,
          serviceWorkerStatus: 'unknown',
          serviceWorkerUrl: null,
          isRestricted: false,
          metaCspFound: false,
          ledger: [],
          blindSpots: [],
        },
        subdomainTrust: { hasEscalationPath: false, vectors: [] },
        monitoredByUser: true,
        updatedAt: Date.now(),
      };
      tabStates.set(tabId, mockState);

      for (let i = 1; i <= 65; i++) {
        recordThirdPartyBlocked(tabId, `https://cdn${i}.thirdparty.com/asset-${i}.js`);
      }

      expect(mockState.coverage.ledger?.length).toBe(50);
      // Newest entries should be preserved
      expect(mockState.coverage.ledger?.[49]?.url).toBe('https://cdn65.thirdparty.com/asset-65.js');
    });

    it('triggers third-party-blocked callback via WebRequest onBeforeSendHeaders boundary filter', () => {
      const blockedReports: Array<{ tabId: number; url: string }> = [];
      registerCaptureListeners(
        () => {},
        () => {},
        (tabId, url) => blockedReports.push({ tabId, url }),
      );

      // Get the last registered onBeforeSendHeaders listener
      const sendHeadersListeners = webRequestListeners.onBeforeSendHeaders ?? [];
      const onBeforeSendHeaders = sendHeadersListeners[sendHeadersListeners.length - 1];
      expect(onBeforeSendHeaders).toBeDefined();

      // Fire an unpermitted cross-origin XHR subresource
      onBeforeSendHeaders?.({
        type: 'xmlhttprequest',
        tabId: 105,
        requestId: 'subresource-req-1',
        url: 'https://external-api.evil.com/telemetry',
        timeStamp: Date.now(),
      });

      // Must be dropped before inFlightRequests
      expect(inFlightRequests.has('subresource-req-1')).toBe(false);
      // Must trigger blocked callback
      expect(blockedReports).toHaveLength(1);
      expect(blockedReports[0]?.tabId).toBe(105);
      expect(blockedReports[0]?.url).toBe('https://external-api.evil.com/telemetry');
    });
  });

  describe('Defect 3: Finding Model Nomenclature Aliases', () => {
    it('supports redirect-hop and redirect provenance aliases', () => {
      const findingHop: Finding = {
        ruleId: 'REDIR-001',
        category: 'header',
        severity: 'medium',
        title: 'Redirect dropped security header',
        evidence: 'CSP missing on hop 2',
        recommendation: 'Ensure CSP persists across redirects',
        reference: 'https://example.com/redir',
        provenance: 'redirect-hop',
        outcome: 'violation',
      };

      const findingLegacy: Finding = {
        ...findingHop,
        provenance: 'redirect',
      };

      expect(findingHop.provenance).toBe('redirect-hop');
      expect(findingLegacy.provenance).toBe('redirect');
    });

    it('supports har-import and har-json provenance aliases', () => {
      const findingImport: Finding = {
        ruleId: 'HSTS-001',
        category: 'transport',
        severity: 'high',
        title: 'Missing HSTS header',
        evidence: 'Header absent',
        recommendation: 'Add HSTS',
        reference: 'https://example.com/hsts',
        provenance: 'har-import',
        outcome: 'violation',
      };

      const findingJson: Finding = {
        ...findingImport,
        provenance: 'har-json',
      };

      expect(findingImport.provenance).toBe('har-import');
      expect(findingJson.provenance).toBe('har-json');
    });

    it('scores violation and fail outcomes identically as active deductions', () => {
      const findingViolation: Finding = {
        ruleId: 'CSP-001',
        category: 'header',
        severity: 'critical',
        title: 'Missing Content-Security-Policy',
        evidence: 'No CSP header present',
        recommendation: 'Configure CSP',
        reference: 'https://example.com/csp',
        outcome: 'violation',
      };

      const findingFail: Finding = {
        ...findingViolation,
        outcome: 'fail',
      };

      const scoreViolation = computeScore([findingViolation]);
      const scoreFail = computeScore([findingFail]);

      expect(scoreViolation.score).toBe(scoreFail.score);
      expect(scoreViolation.score).toBeLessThan(100);
      expect(scoreViolation.breakdown).toHaveLength(1);
      expect(scoreViolation.breakdown[0]?.penalty).toBeGreaterThan(0);
    });

    it('exempts pass, not-observed, and not-applicable outcomes from penalties', () => {
      const findingPass: Finding = {
        ruleId: 'CSP-001',
        category: 'header',
        severity: 'critical',
        title: 'CSP present',
        evidence: 'default-src self',
        recommendation: 'None',
        reference: 'https://example.com',
        outcome: 'pass',
      };

      const findingNotObserved: Finding = {
        ruleId: 'CORS-001',
        category: 'cors',
        severity: 'high',
        title: 'CORS check omitted',
        evidence: 'Headers omitted by browser',
        recommendation: 'None',
        reference: 'https://example.com',
        outcome: 'not-observed',
      };

      const findingNotApplicable: Finding = {
        ruleId: 'HSTS-001',
        category: 'transport',
        severity: 'high',
        title: 'HSTS not applicable on HTTP',
        evidence: 'Scheme is http',
        recommendation: 'None',
        reference: 'https://example.com',
        outcome: 'not-applicable',
      };

      const result = computeScore([findingPass, findingNotObserved, findingNotApplicable]);
      expect(result.score).toBe(100);
      expect(result.breakdown).toHaveLength(0);
    });
  });
});
