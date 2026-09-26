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

import { tabStates, initLifecycle, hydrateFromSession } from './lifecycle';
import { registerCaptureListeners, captureMap } from './capture';
import { correlateCookies } from './correlate';
import { runRules } from '../rules/engine';
import { extractSetCookieHeaders, originFromUrl } from '../rules/utils';
import { SessionStorage, LocalStorage } from '../shared/storage';
import { PortRegistry, portSend } from '../shared/messaging';
import {
  BADGE_COLORS,
  RESTRICTED_SCHEMES,
  POPUP_PORT_NAME,
  SIDEPANEL_PORT_NAME,
} from '../shared/constants';
import type {
  TabState,
  Grade,
  CoverageInfo,
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

function recomputeTabState(tabId: number, state: TabState): void {
  const result = runRules({
    hops: state.hops,
    cookies: state.cookies,
    origin: state.origin,
  });

  state.findings = result.findings;
  state.score = result.score;
  state.grade = result.grade;
  state.scoreBreakdown = result.breakdown;
  state.scoreVersion = result.scoreVersion;
  state.subdomainTrust = result.subdomainTrust;
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
    metaCspFound: false,
  };

  return {
    tabId,
    origin,
    url,
    hops: [],
    cookies: [],
    findings: [],
    grade: 'F',
    score: 0,
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

  const permitted = await new Promise<boolean>((resolve) =>
    chrome.permissions.contains({ origins: [`${origin}/*`] }, resolve),
  );
  if (!permitted) {
    // Not monitored — reset badge to '?' and do nothing further.
    state.coverage.isRestricted = false;
    setBadgeForTab(tabId, '?');
    return;
  }
  state.monitoredByUser = true;

  // ------------------------------------------------------------------
  // 4. Append the new hop.
  // ------------------------------------------------------------------
  state.hops = [...state.hops, hop];
  state.coverage.hopsExpected = Math.max(
    state.coverage.hopsExpected,
    state.hops.reduce((count, item) => count + 1 + (item.redirectCount ?? 0), 0),
  );
  state.coverage.hopsCaptured = state.hops.length;
  state.coverage.hasCache = state.coverage.hasCache || hop.fromCache;

  // ------------------------------------------------------------------
  // 5. Correlate cookies.
  // ------------------------------------------------------------------
  const setCookieValues = extractSetCookieHeaders(hop.rawHeaders);
  const correlatedCookies = await correlateCookies(tabId, hop.url, setCookieValues);
  state.cookies = correlatedCookies;

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
          const correlatedCookies = await correlateCookies(tabId, state.url, []);
          state.cookies = correlatedCookies;

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
          recomputeTabState(senderTabId, state);
        }
      }
      return false;
    }

    return false;
  },
);

// ---------------------------------------------------------------------------
// Startup sequence
// ---------------------------------------------------------------------------

void (async (): Promise<void> => {
  // 1. Restore in-memory state from session storage (survives SW restart).
  await hydrateFromSession();

  // 2. Arm the keepalive alarm.
  initLifecycle();

  // 3. Begin capturing WebRequest events.
  registerCaptureListeners((tabId: number, hop: import('../shared/types').Hop): void => {
    void onHopComplete(tabId, hop);
  });
})();
