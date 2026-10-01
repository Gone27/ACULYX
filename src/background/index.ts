/**
 * index.ts
 *
 * Main service-worker entry point for the Header & Cookie Security Checker
 * extension.  Wires together:
 *
 *   • lifecycle    — keepalive alarms + session-storage hydration
 *   • capture      — WebRequest listeners (two-stage header snapshotting)
 *   • correlate    — Set-Cookie ↔ chrome.cookies reconciliation
 *   • rules engine — scoring, findings, grade computation
 *   • port registry— live push to popup / sidepanel
 *   • badge        — per-tab grade display
 *
 * All side-effects are confined to listener callbacks; no top-level async
 * work is performed so the module is safe to import during SW startup.
 */

import { tabStates, initLifecycle, hydrateFromSession, originAuthBaselines } from './lifecycle';
import { registerCaptureListeners, captureMap } from './capture';
import { correlateCookies } from './correlate';
import { registerPageSignalInjection } from './page-signals';
import { runRules, runApiRules } from '../rules/engine';
import { extractSetCookieHeaders, originFromUrl } from '../rules/utils';
import { checkAuthTransition } from '../rules/auth-diff';
import { discoverNodes, mergeIntoGraph } from '../rules/graph-discovery';
import { registrableDomain } from '../rules/headers/subdomain-trust';
import { SessionStorage, LocalStorage } from '../shared/storage';
import { PortRegistry, portSend } from '../shared/messaging';
import {
  PermissionsService,
  reconcilePermissionsOnRemoved,
  reconcilePermissionsOnStartup,
} from './permissions';
import {
  BADGE_COLORS,
  RESTRICTED_SCHEMES,
  POPUP_PORT_NAME,
  SIDEPANEL_PORT_NAME,
  DEFAULT_SETTINGS,
} from '../shared/constants';
import { SettingsService } from '../shared/settings';
import type {
  TabState,
  Grade,
  CoverageInfo,
  CoverageLedgerEntry,
  Settings,
  SettingsV2,
  ApiHop,
  ApiEndpointState,
} from '../shared/types';
import type {
  ExtensionMessage,
  StateResponseMessage,
  SettingsChangedMessage,
} from '../shared/messaging';

// ---------------------------------------------------------------------------
// Port registry — live connections from popup / sidepanel
// ---------------------------------------------------------------------------

const portRegistry = new PortRegistry();
const pendingServiceWorkerReports = new Map<number, {
  status: 'controlled' | 'not-controlled';
  serviceWorkerUrl: string | null;
}>();
const pendingMetaCspReports = new Set<number>();

let currentSettings: SettingsV2 = DEFAULT_SETTINGS;
void SettingsService.getSettings().then((s) => { currentSettings = s; }).catch(() => {});
SettingsService.onSettingsChanged((s) => { currentSettings = s; });

function recomputeTabState(tabId: number, state: TabState): void {
  const result = runRules({
    hops: state.hops,
    cookies: state.cookies,
    origin: state.origin,
    metaCspFound: state.coverage.metaCspFound,
    captureFindings: state.captureFindings ?? [],
    cookieSettings: {
      alwaysSensitive: currentSettings.sensitiveCookieNames ?? currentSettings.alwaysSensitiveCookies ?? [],
      alwaysIgnore: currentSettings.ignoredCookieNames ?? currentSettings.alwaysIgnoreCookies ?? [],
    },
  });

  state.findings = result.findings;
  state.score = result.score;
  state.grade = result.grade;
  state.qualityScore = result.qualityScore;
  state.qualityGrade = result.qualityGrade;
  state.scoreBreakdown = result.breakdown;
  state.scoreVersion = result.scoreVersion;
  state.subdomainTrust = result.subdomainTrust;
  state.coverage.blindSpots = computeBlindSpots(state.coverage);
  state.updatedAt = Date.now();

  tabStates.set(tabId, state);
  void SessionStorage.setTabState(state);

  // Record historical score trend for this domain
  if (state.monitoredByUser && state.origin) {
    void LocalStorage.recordOriginHistory(state.origin, {
      timestamp: state.updatedAt,
      score: state.score,
      grade: state.grade,
    });

    // Pre-login vs. post-login posture diff
    const baseline = originAuthBaselines.get(state.origin);
    const { isAuthEvent, record, newBaseline } = checkAuthTransition(
      state.origin,
      baseline,
      state.cookies,
      state.findings,
      state.score,
      state.grade,
      currentSettings.alwaysSensitiveCookies,
      currentSettings.alwaysIgnoreCookies,
    );
    originAuthBaselines.set(state.origin, newBaseline);
    void SessionStorage.setAuthBaseline(state.origin, newBaseline);

    if (isAuthEvent && record !== null) {
      void LocalStorage.recordAuthDiff(state.origin, record);
    }

    // Accumulate attack surface graph
    void (async () => {
      try {
        const u = new URL(state.origin);
        const hostname = u.hostname;
        const apex = registrableDomain(hostname) ?? hostname;
        const discovered = discoverNodes(hostname, state.hops, state.cookies, state.apiEndpoints);
        const existingGraph = await LocalStorage.getGraph(apex);
        const updatedGraph = mergeIntoGraph(
          existingGraph,
          hostname,
          state.score,
          state.grade,
          discovered,
          Boolean(currentSettings.isPro),
        );
        await LocalStorage.saveGraph(updatedGraph);
      } catch {
        // Silently ignore graph merge errors
      }
    })();
  }

  setBadgeForTab(tabId, state.grade);
  portRegistry.broadcast(tabId, { type: 'TAB_STATE_UPDATE', state });
}

// ---------------------------------------------------------------------------
// Badge helpers
// ---------------------------------------------------------------------------

/**
 * Returns true when the URL belongs to a restricted scheme (chrome://, etc.)
 * that the extension cannot inspect.
 */
function isRestrictedUrl(url: string): boolean {
  return RESTRICTED_SCHEMES.some((scheme) => url.startsWith(scheme));
}

/**
 * Updates the action badge text and background colour for the given tab.
 * Silently swallows errors (e.g. tab already closed).
 */
function setBadgeForTab(tabId: number, grade: Grade | '?'): void {
  if (!Number.isInteger(tabId) || tabId < 0) return;

  const color = BADGE_COLORS[grade];
  const text = grade === '?' ? '?' : grade;
  chrome.action.setBadgeText({ text, tabId }).catch(() => undefined);
  chrome.action.setBadgeBackgroundColor({ color, tabId }).catch(() => undefined);
}

function computeBlindSpots(coverage: CoverageInfo): string[] {
  const spots: string[] = [];
  if (coverage.isRestricted) {
    spots.push('Restricted URL: browser security policy blocks inspection of internal browser pages.');
  }
  if (coverage.hasCache) {
    spots.push('Cached response: headers reflect browser cache; live server headers may have evolved.');
  }
  if (coverage.hasServiceWorker) {
    spots.push('Active Service Worker: responses may be generated or modified client-side without reaching origin server.');
  }
  if (coverage.hopsExpected > coverage.hopsCaptured) {
    spots.push(`${coverage.hopsExpected - coverage.hopsCaptured} intermediate redirect hop(s) were missed during capture.`);
  }
  return spots;
}

function pushLedgerEntry(state: TabState, entry: CoverageLedgerEntry): void {
  const ledger = state.coverage.ledger ?? (state.coverage.ledger = []);
  ledger.push(entry);
  if (ledger.length > 50) {
    state.coverage.ledger = ledger.slice(-50);
  }
}

// ---------------------------------------------------------------------------
// Default TabState factory
// ---------------------------------------------------------------------------

function createDefaultTabState(tabId: number, url: string): TabState {
  const origin = originFromUrl(url) ?? url;
  const serviceWorkerReport = pendingServiceWorkerReports.get(tabId);

  const coverage: CoverageInfo = {
    hopsExpected: 1,
    hopsCaptured: 0,
    hasCache: false,
    hasServiceWorker: serviceWorkerReport?.status === 'controlled',
    serviceWorkerStatus: serviceWorkerReport?.status ?? 'unknown',
    serviceWorkerUrl: serviceWorkerReport?.serviceWorkerUrl ?? null,
    isRestricted: isRestrictedUrl(url),
    metaCspFound: pendingMetaCspReports.has(tabId),
    ledger: [],
    blindSpots: [],
  };

  return {
    tabId,
    origin,
    url,
    hops: [],
    cookies: [],
    findings: [],
    captureFindings: [],
    grade: 'F',
    score: 0,
    qualityScore: 100,
    qualityGrade: 'A',
    scoreVersion: '',
    scoreBreakdown: [],
    coverage,
    subdomainTrust: { hasEscalationPath: false, vectors: [] },
    monitoredByUser: false,
    updatedAt: Date.now(),
  };
}

// ---------------------------------------------------------------------------
// onHopComplete — core analysis pipeline
// ---------------------------------------------------------------------------

/**
 * Invoked by capture.ts after both WebRequest stages have completed for a
 * given request.  Runs the full analysis pipeline and pushes updates to all
 * connected ports.
 */
async function onHopComplete(
  tabId: number,
  hop: import('../shared/types').Hop,
): Promise<void> {
  if (!Number.isInteger(tabId) || tabId < 0) return;

  // ------------------------------------------------------------------
  // 1. Retrieve or initialise tab state.
  // ------------------------------------------------------------------
  const state = tabStates.get(tabId) ?? createDefaultTabState(tabId, hop.url);

  // Update URL to the final navigated URL.
  state.url = hop.url;
  state.origin = originFromUrl(hop.url) ?? hop.url;

  // ------------------------------------------------------------------
  // 2. Guard: restricted URLs cannot be inspected.
  // ------------------------------------------------------------------
  if (isRestrictedUrl(hop.url)) {
    state.coverage.isRestricted = true;
    tabStates.set(tabId, state);
    setBadgeForTab(tabId, '?');
    return;
  }

  // ------------------------------------------------------------------
  // 3. Guard: check the user has granted permission for this origin.
  //    chrome.permissions.contains requires origin/* pattern format.
  // ------------------------------------------------------------------
  const origin = state.origin;
  if (!origin || origin === hop.url) return; // originFromUrl returned null (non-http URL)

  const permitted = await PermissionsService.hasPermissionForOrigin(origin);
  if (!permitted) {
    // Not monitored — reset badge to '?' and do nothing further.
    state.coverage.isRestricted = false;
    setBadgeForTab(tabId, '?');
    return;
  }
  state.coverage.metaCspFound ||= pendingMetaCspReports.has(tabId);
  state.monitoredByUser = true;

  // ------------------------------------------------------------------
  // 4. Append the new hop.
  // ------------------------------------------------------------------
  state.hops = [...state.hops, hop].sort((left, right) => left.timestamp - right.timestamp);
  const isRedirect = hop.status >= 300 && hop.status < 400;
  const minExpectedHops = isRedirect ? state.hops.length + 1 : state.hops.length;
  state.coverage.hopsExpected = Math.max(
    state.coverage.hopsExpected,
    minExpectedHops,
  );
  state.coverage.hopsCaptured = state.hops.length;
  state.coverage.hasCache = state.coverage.hasCache || hop.fromCache;

  const ledgerSource: 'network' | 'cache' | 'hsts-upgrade' = hop.fromCache
    ? 'cache'
    : (hop.isHstsUpgrade ? 'hsts-upgrade' : 'network');
  pushLedgerEntry(state, {
    type: hop.isHstsUpgrade ? 'redirect' : 'navigation',
    url: hop.url,
    source: ledgerSource,
    status: hop.status,
    timestamp: hop.timestamp,
    notes: hop.headersDiffer ? 'Headers modified by extension' : undefined,
  });

  // ------------------------------------------------------------------
  // 5. Correlate cookies.
  // ------------------------------------------------------------------
  const setCookieValues = extractSetCookieHeaders(hop.rawHeaders);
  const correlation = await correlateCookies(tabId, hop.url, setCookieValues);
  state.cookies = correlation.records;
  const captureFindingMap = new Map(
    [...(state.captureFindings ?? []), ...correlation.findings].map((finding) => [
      `${finding.ruleId}:${finding.sourceUrl ?? ''}:${finding.evidence}`,
      finding,
    ]),
  );
  state.captureFindings = [...captureFindingMap.values()];

  // ------------------------------------------------------------------
  // 6. Recompute evaluation from the canonical tab state.
  // ------------------------------------------------------------------
  // ------------------------------------------------------------------
  // 7. Finalise state.
  // ------------------------------------------------------------------
  recomputeTabState(tabId, state);
}

// ---------------------------------------------------------------------------
// Navigation reset
// ---------------------------------------------------------------------------

/**
 * Clears stale analysis state when the user navigates away from a page.
 * Runs before the network request for the new page fires so there is no
 * flash of old data.
 */
chrome.webNavigation.onBeforeNavigate.addListener(
  (details: chrome.webNavigation.WebNavigationParentedCallbackDetails): void => {
    // Only reset on top-level frame navigations.
    if (details.frameId !== 0) return;

    const { tabId } = details;

    pendingServiceWorkerReports.delete(tabId);
    pendingMetaCspReports.delete(tabId);

    // Remove in-memory state.
    tabStates.delete(tabId);

    // Remove persisted state (fire-and-forget).
    SessionStorage.removeTabState(tabId).catch(() => undefined);

    // Clear in-flight capture entries that belong to this tab.
    for (const [requestId, partial] of captureMap.entries()) {
      if (partial.tabId === tabId) {
        captureMap.delete(requestId);
      }
    }

    // Reset the badge to the unknown state.
    setBadgeForTab(tabId, '?');
  },
);

registerPageSignalInjection();

chrome.sidePanel?.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => undefined);

// ---------------------------------------------------------------------------
// Cookie change listener
// ---------------------------------------------------------------------------

/**
 * Handles live cookie mutations (including JS-set cookies).
 * Re-correlates and re-scores every tab whose origin matches the affected
 * cookie domain.
 */
chrome.cookies.onChanged.addListener(
  (changeInfo: chrome.cookies.CookieChangeInfo): void => {
    if (changeInfo.removed) return; // Removals don't affect security posture.

    const affectedDomain = changeInfo.cookie.domain.replace(/^\./, '');

    for (const [tabId, state] of tabStates.entries()) {
      // Match tabs whose origin contains the affected cookie domain.
      const tabHostname = (() => {
        try {
          return new URL(state.url).hostname;
        } catch {
          return '';
        }
      })();

      if (!tabHostname.endsWith(affectedDomain)) continue;

      // Re-correlate and re-score asynchronously (fire-and-forget with error guard).
      void (async () => {
        try {
          const correlation = await correlateCookies(tabId, state.url, []);
          state.cookies = correlation.records;

          recomputeTabState(tabId, state);
        } catch {
          // Silently ignore errors from background re-scoring.
        }
      })();
    }
  },
);

// ---------------------------------------------------------------------------
// Tab cleanup
// ---------------------------------------------------------------------------

chrome.tabs.onRemoved.addListener((tabId: number): void => {
  tabStates.delete(tabId);
  pendingMetaCspReports.delete(tabId);
  SessionStorage.removeTabState(tabId).catch(() => undefined);
});

// ---------------------------------------------------------------------------
// Port connections (popup / sidepanel)
// ---------------------------------------------------------------------------

chrome.runtime.onConnect.addListener((port: chrome.runtime.Port): void => {
  const isPopup = port.name === POPUP_PORT_NAME;
  const isSidePanel = port.name === SIDEPANEL_PORT_NAME;

  if (!isPopup && !isSidePanel) return;

  // Attempt to derive the tabId from the connecting port's sender tab.
  const senderTabId: number | undefined = port.sender?.tab?.id;

  // Register immediately if we already know the tabId; otherwise we wait for
  // a RequestStateMessage which will include the tabId.
  if (senderTabId !== undefined) {
    portRegistry.register(port, senderTabId);

    // Push current state immediately so the UI doesn't wait for the next hop.
    const current = tabStates.get(senderTabId);
    if (current) {
      const response: StateResponseMessage = {
        type: 'STATE_RESPONSE',
        state: current,
      };
      portSend(port, response);
    }
  }

  port.onMessage.addListener((msg: ExtensionMessage): void => {
    if (msg.type === 'REQUEST_STATE') {
      const resolvedTabId = msg.tabId ?? senderTabId;

      if (resolvedTabId === undefined) return;

      // Register with the resolved tabId in case we didn't have it at connect.
      portRegistry.register(port, resolvedTabId);

      const stateForTab = tabStates.get(resolvedTabId);
      const response: StateResponseMessage = {
        type: 'STATE_RESPONSE',
        state: stateForTab ?? null,
      };
      portSend(port, response);
    }
  });
});

// ---------------------------------------------------------------------------
// Runtime message handler (one-shot messages, not port-based)
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener(
  (
    message: ExtensionMessage,
    _sender: chrome.runtime.MessageSender,
    sendResponse: (response: ExtensionMessage) => void,
  ): boolean => {
    if (message.type === 'REQUEST_STATE') {
      const stateForTab = message.tabId !== undefined
        ? tabStates.get(message.tabId) ?? null
        : null;

      const response: StateResponseMessage = {
        type: 'STATE_RESPONSE',
        state: stateForTab,
      };
      sendResponse(response);
      return false; // Response sent synchronously.
    }

    if (message.type === 'PERMISSIONS_CHANGED') {
      void (async () => {
        try {
          if (!message.granted && message.origins.length > 0) {
            await reconcilePermissionsOnRemoved(message.origins, {
              tabStates,
              pendingServiceWorkerReports,
              pendingMetaCspReports,
              setBadge: (t, text) => {
                if (text === '') {
                  void chrome.action?.setBadgeText({ tabId: t, text: '' })?.catch?.(() => undefined);
                } else {
                  setBadgeForTab(t, text as Grade | '?');
                }
              },
              broadcast: (t, msg) => portRegistry.broadcast(t, msg),
            });
          }
          const settings = await LocalStorage.getSettings();

          // Notify all connected ports about the settings change.
          const settingsMsg: SettingsChangedMessage = {
            type: 'SETTINGS_CHANGED',
            settings,
          };
          portRegistry.broadcastAll(settingsMsg);
        } catch {
          // Ignore storage errors during permission change handling.
        }
      })();

      return false;
    }

    if (message.type === 'SETTINGS_CHANGED') {
      currentSettings = message.settings;
      portRegistry.broadcastAll(message);
      sendResponse(message);
      return false;
    }

    if (message.type === 'SERVICE_WORKER_STATUS') {
      const senderTabId = _sender.tab?.id;
      if (senderTabId !== undefined) {
        const report = {
          status: message.status,
          serviceWorkerUrl: message.serviceWorkerUrl,
        };
        pendingServiceWorkerReports.set(senderTabId, report);
        const state = tabStates.get(senderTabId);
        if (state) {
          state.coverage.serviceWorkerStatus = report.status;
          state.coverage.serviceWorkerUrl = report.serviceWorkerUrl;
          state.coverage.hasServiceWorker = report.status === 'controlled';
          if (report.status === 'controlled') {
            pushLedgerEntry(state, {
              type: 'service-worker',
              url: report.serviceWorkerUrl ?? state.url,
              source: 'service-worker',
              timestamp: Date.now(),
              notes: 'Page is controlled by active service worker',
            });
          }
          recomputeTabState(senderTabId, state);
        }
      }
      return false;
    }

    if (message.type === 'META_CSP_FOUND') {
      const senderTabId = _sender.tab?.id;
      if (senderTabId !== undefined) {
        pendingMetaCspReports.add(senderTabId);
        const state = tabStates.get(senderTabId);
        if (state) {
          state.coverage.metaCspFound = true;
          // Store the policy strings so the popup can display them and
          // so we can run csp_evaluator on them separately from the header CSP.
          if (message.policies !== undefined && message.policies.length > 0) {
            state.coverage.metaCspPolicies = message.policies.slice(0, 5).map((p) => p.slice(0, 2048));
            pushLedgerEntry(state, {
              type: 'subresource',
              url: state.url,
              source: 'dom',
              timestamp: Date.now(),
              notes: `${message.policies.length} <meta> CSP tag(s) detected in DOM`,
            });
            // Generate meta-CSP findings if the page has no header CSP
            // (meta-CSP cannot restrict navigation or workers, unlike header CSP).
            const hasHeaderCsp = state.hops.at(-1)?.headers['content-security-policy'] !== undefined;
            if (!hasHeaderCsp) {
              // Record an informational finding that the policy is via meta tag only
              const existing = state.captureFindings ?? [];
              if (!existing.some((f) => f.ruleId === 'CSP-META-001')) {
                (state.captureFindings ?? (state.captureFindings = [])).push({
                  ruleId: 'CSP-META-001',
                  category: 'header',
                  severity: 'info',
                  title: 'CSP delivered via <meta> tag, not HTTP header',
                  impact: 'Meta-tag CSP cannot restrict navigation, workers, or plugin content. HTTP header CSP provides broader enforcement.',
                  evidence: `${message.policies.length} meta-CSP policy/policies found`,
                  recommendation: 'Prefer Content-Security-Policy HTTP response header; keep the meta tag as a fallback only.',
                  reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy#meta',
                });
              }
            }
          }
          recomputeTabState(senderTabId, state);
        }
      }
      return false;
    }

    if (message.type === 'SRI_SCAN') {
      const senderTabId = _sender.tab?.id;
      const state = senderTabId === undefined ? undefined : tabStates.get(senderTabId);
      if (senderTabId !== undefined && state) {
        state.captureFindings = (state.captureFindings ?? []).filter((finding) => finding.ruleId !== 'SRI-001');

        const missingScripts = message.missingIntegrity ?? 0;
        const missingStyles = message.missingStyleIntegrity ?? 0;
        const totalMissing = missingScripts + missingStyles;

        if (totalMissing > 0) {
          const parts: string[] = [];
          if (missingScripts > 0) parts.push(`${missingScripts}/${message.externalScripts ?? 0} script(s)`);
          if (missingStyles > 0) parts.push(`${missingStyles}/${message.externalStylesheets ?? 0} stylesheet(s)`);

          state.captureFindings.push({
            ruleId: 'SRI-001', category: 'header', severity: 'medium',
            title: `${totalMissing} external resource(s) lack Subresource Integrity`,
            impact: 'A compromised or modified third-party script or stylesheet may run with the privileges of this page.',
            evidence: `Missing integrity attribute on: ${parts.join(', ')}`,
            recommendation: 'Add integrity hashes and crossorigin="anonymous" to external scripts and stylesheets, or self-host resources whose content you control.',
            reference: 'https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity',
          });
        }
        recomputeTabState(senderTabId, state);
      }
      return false;
    }

    if (message.type === 'REQUEST_GRAPH') {
      void (async () => {
        try {
          const apex = message.apexDomain;
          const graph = await LocalStorage.getGraph(apex);
          const isPro = Boolean(currentSettings.isPro);

          if (!graph) {
            sendResponse({
              type: 'GRAPH_RESPONSE',
              graph: {
                apexDomain: apex,
                nodes: [{ hostname: apex, isApex: true, lastSeen: Date.now(), discoveredVia: ['navigation'] }],
                edges: [],
                isPro,
                lastUpdated: Date.now(),
              },
            });
            return;
          }

          if (!isPro) {
            let tabHost = '';
            if (message.tabId !== undefined) {
              const tabState = tabStates.get(message.tabId);
              tabHost = tabState ? (originFromUrl(tabState.url) !== null ? new URL(tabState.origin).hostname : '') : '';
            }
            const filteredNodes = graph.nodes.filter((n) => n.isApex || (tabHost.length > 0 && n.hostname === tabHost));
            const nodeHosts = new Set(filteredNodes.map((n) => n.hostname));
            const filteredEdges = graph.edges.filter((e) => nodeHosts.has(e.source) && nodeHosts.has(e.target));
            sendResponse({
              type: 'GRAPH_RESPONSE',
              graph: {
                ...graph,
                nodes: filteredNodes,
                edges: filteredEdges,
                isPro: false,
              },
            });
            return;
          }

          sendResponse({
            type: 'GRAPH_RESPONSE',
            graph: { ...graph, isPro },
          });
        } catch {
          // Send fallback on error
        }
      })();
      return true;
    }

    if (message.type === 'GENERATE_POC') {
      const state = tabStates.get(message.tabId);
      if (!state || !state.monitoredByUser) {
        sendResponse({
          type: 'GENERATE_POC_RESPONSE',
          success: false,
          error: 'Site must be monitored before generating verification sandbox.',
        });
        return false;
      }

      const pocUrl = chrome.runtime.getURL('src/sandbox/poc.html') +
        `?target=${encodeURIComponent(state.url)}&type=${encodeURIComponent(message.pocType)}`;

      chrome.tabs.create({ url: pocUrl }).then(() => {
        sendResponse({
          type: 'GENERATE_POC_RESPONSE',
          success: true,
          url: pocUrl,
        });
      }).catch((err: Error) => {
        sendResponse({
          type: 'GENERATE_POC_RESPONSE',
          success: false,
          error: err.message,
        });
      });
      return true;
    }

    return false;
  },
);

// ---------------------------------------------------------------------------
// Startup sequence
// ---------------------------------------------------------------------------

chrome.storage.local.onChanged.addListener((changes: { [key: string]: chrome.storage.StorageChange }) => {
  if (changes.settings?.newValue !== undefined) {
    currentSettings = { ...DEFAULT_SETTINGS, ...(changes.settings.newValue as Partial<Settings>) };
  }
});

// 1. Arm the keepalive alarm immediately on SW startup.
initLifecycle();

// 2. Begin capturing WebRequest events synchronously to avoid missing early navigations.
registerCaptureListeners(
  (tabId: number, hop: import('../shared/types').Hop): void => {
    void onHopComplete(tabId, hop);
  },
  (apiHop: ApiHop): void => {
    const state = tabStates.get(apiHop.tabId);
    if (!state) return;

    const targetOrigin = originFromUrl(apiHop.url);
    const isFirstParty = state.origin === targetOrigin;
    apiHop.isThirdParty = !isFirstParty;

    const findings = runApiRules(apiHop, {
      alwaysSensitive: currentSettings.sensitiveCookieNames ?? currentSettings.alwaysSensitiveCookies ?? [],
      alwaysIgnore: currentSettings.ignoredCookieNames ?? currentSettings.alwaysIgnoreCookies ?? [],
    });

    if (!state.apiEndpoints) {
      state.apiEndpoints = new Map();
    }

    const endpointState: ApiEndpointState = {
      normalizedPath: apiHop.normalizedPath,
      lastHop: apiHop,
      findings,
      isFirstParty,
    };

    state.apiEndpoints.set(apiHop.normalizedPath, endpointState);

    if (state.apiEndpoints.size > 50) {
      const firstKey = state.apiEndpoints.keys().next().value;
      if (firstKey !== undefined) {
        state.apiEndpoints.delete(firstKey);
      }
    }

    pushLedgerEntry(state, {
      type: 'api',
      url: apiHop.url,
      source: apiHop.fromCache === true ? 'cache' : 'network',
      status: apiHop.status,
      timestamp: apiHop.timestamp ?? Date.now(),
      notes: `${apiHop.method} ${apiHop.isThirdParty === true ? '(third-party)' : '(first-party)'}`,
    });

    state.updatedAt = Date.now();
    void SessionStorage.setTabState(state);

    // Accumulate attack surface graph for API host and CORS endpoints
    void (async () => {
      try {
        const u = new URL(state.origin);
        const hostname = u.hostname;
        const apex = registrableDomain(hostname) ?? hostname;
        const discovered = discoverNodes(hostname, state.hops, state.cookies, state.apiEndpoints);
        const existingGraph = await LocalStorage.getGraph(apex);
        const updatedGraph = mergeIntoGraph(
          existingGraph,
          hostname,
          state.score,
          state.grade,
          discovered,
          Boolean(currentSettings.isPro),
        );
        await LocalStorage.saveGraph(updatedGraph);
      } catch {
        // Silently ignore graph merge errors
      }
    })();

    portRegistry.broadcast(apiHop.tabId, {
      type: 'TAB_STATE_UPDATE',
      state,
    });
  }
);

// 3. Restore in-memory state from session storage in parallel (survives SW restart).
void hydrateFromSession().then(async () => {
  await reconcilePermissionsOnStartup({
    tabStates,
    pendingServiceWorkerReports,
    pendingMetaCspReports,
    setBadge: (t, text) => {
      if (text === '') {
        void chrome.action?.setBadgeText({ tabId: t, text: '' })?.catch?.(() => undefined);
      } else {
        setBadgeForTab(t, text as Grade | '?');
      }
    },
    broadcast: (t, msg) => portRegistry.broadcast(t, msg),
  });
});

if (
  typeof chrome !== 'undefined' &&
  typeof chrome.permissions !== 'undefined' &&
  typeof chrome.permissions.onRemoved !== 'undefined'
) {
  chrome.permissions.onRemoved.addListener((removed) => {
    const origins = removed.origins ?? [];
    void reconcilePermissionsOnRemoved(origins, {
      tabStates,
      pendingServiceWorkerReports,
      pendingMetaCspReports,
      setBadge: (t, text) => {
        if (text === '') {
          void chrome.action?.setBadgeText({ tabId: t, text: '' })?.catch?.(() => undefined);
        } else {
          setBadgeForTab(t, text as Grade | '?');
        }
      },
      broadcast: (t, msg) => portRegistry.broadcast(t, msg),
    });
  });
}




