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
import { registerCaptureListeners, captureMap, clearInFlightCaptures, inFlightRequests } from './capture';
import { CapturePolicy } from './capture-policy';
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
import { SettingsService, settingsTransitionPipeline } from '../shared/settings';
import type {
  TabState,
  Grade,
  CoverageInfo,
  CoverageLedgerEntry,
  SettingsV2,
  ApiHop,
  ApiEndpointState,
  Hop,
} from '../shared/types';
import type {
  ExtensionMessage,
  StateResponseMessage,
  SettingsChangedMessage,
} from '../shared/messaging';

// ---------------------------------------------------------------------------
// Per-tab navigation generation counter
// Incremented on onBeforeNavigate (top-level frameId === 0).
// Tags hops, API hops, cookie changes, and page signals.
// Late arrivals for older generations are discarded immediately.
// ---------------------------------------------------------------------------

export const tabGenerations = new Map<number, number>();

export function getTabGeneration(tabId: number): number {
  return tabGenerations.get(tabId) ?? 0;
}

export function incrementTabGeneration(tabId: number): number {
  const next = (tabGenerations.get(tabId) ?? 0) + 1;
  tabGenerations.set(tabId, next);
  return next;
}

// ---------------------------------------------------------------------------
// Per-tab ordered reducer action queue
// Serializes state-changing work per tab to eliminate race conditions
// and preserve strict causal ordering.
// ---------------------------------------------------------------------------

export class TabActionQueue {
  private queues = new Map<number, Promise<void>>();

  enqueue<T>(tabId: number, generation: number, action: () => Promise<T>): Promise<T | undefined> {
    const current = this.queues.get(tabId) ?? Promise.resolve();
    let release!: () => void;
    const next = new Promise<void>((resolve) => {
      release = resolve;
    });
    const tail = current.then(() => next, () => next);
    this.queues.set(tabId, tail);

    return current.then(async () => {
      try {
        if (getTabGeneration(tabId) !== generation) {
          return undefined; // Discard late arrival
        }
        return await action();
      } finally {
        release();
        if (this.queues.get(tabId) === tail) {
          this.queues.delete(tabId);
        }
      }
    });
  }

  clearTab(tabId: number): void {
    this.queues.delete(tabId);
  }

  clearAll(): void {
    this.queues.clear();
  }
}

export const tabActionQueue = new TabActionQueue();

// ---------------------------------------------------------------------------
// Message and event deduplication
// Bounded map of recent event/message IDs with TTL to prevent duplicate rule runs,
// duplicate storage writes, or duplicate port broadcasts.
// ---------------------------------------------------------------------------

const processedEvents = new Map<string, number>();
const MAX_DEDUP_EVENTS = 150;
const DEDUP_EVENT_TTL_MS = 60_000;

export function isDuplicateEvent(eventId: string, now: number = Date.now()): boolean {
  const prev = processedEvents.get(eventId);
  if (prev !== undefined && (now - prev) < DEDUP_EVENT_TTL_MS) {
    return true;
  }

  if (processedEvents.size >= MAX_DEDUP_EVENTS) {
    for (const [id, ts] of processedEvents.entries()) {
      if ((now - ts) >= DEDUP_EVENT_TTL_MS) {
        processedEvents.delete(id);
      }
    }
    if (processedEvents.size >= MAX_DEDUP_EVENTS) {
      const oldestKey = processedEvents.keys().next().value;
      if (oldestKey !== undefined) processedEvents.delete(oldestKey);
    }
  }

  processedEvents.set(eventId, now);
  return false;
}

// ---------------------------------------------------------------------------
// Transient structures maintenance
// Bounds every transient structure: cap 100, TTL 60s, deterministic eviction.
// ---------------------------------------------------------------------------

export function pruneTransientStructures(now: number = Date.now()): void {
  // 1. captureMap (Cap 100, TTL 60s)
  for (const [requestId, partial] of captureMap.entries()) {
    if ((now - partial.timestamp) > 60_000) {
      captureMap.delete(requestId);
    }
  }
  if (captureMap.size > 100) {
    const excess = captureMap.size - 100;
    let count = 0;
    for (const requestId of captureMap.keys()) {
      captureMap.delete(requestId);
      count++;
      if (count >= excess) break;
    }
  }

  // 2. inFlightRequests (Cap 100, TTL 60s)
  for (const [requestId, req] of inFlightRequests.entries()) {
    if ((now - req.timestamp) > 60_000) {
      inFlightRequests.delete(requestId);
    }
  }
  if (inFlightRequests.size > 100) {
    const excess = inFlightRequests.size - 100;
    let count = 0;
    for (const requestId of inFlightRequests.keys()) {
      inFlightRequests.delete(requestId);
      count++;
      if (count >= excess) break;
    }
  }
}

// ---------------------------------------------------------------------------
// Port registry — live connections from popup / sidepanel
// ---------------------------------------------------------------------------

const portRegistry = new PortRegistry();
export const badgeTrackedTabs = new Set<number>();

const pendingServiceWorkerReports = new Map<number, {
  status: 'controlled' | 'not-controlled';
  serviceWorkerUrl: string | null;
  generation: number;
}>();
const pendingMetaCspReports = new Set<number>();

// Fail-closed default settings (mode: 'off') until storage hydration resolves
let currentSettings: SettingsV2 = { ...DEFAULT_SETTINGS, monitoringMode: 'off' };
export const settingsReady = SettingsService.whenReady().then(async (s) => {
  currentSettings = s;
  settingsTransitionPipeline.setLastAppliedSettings(s);
  await CapturePolicy.refreshSnapshot();
  return s;
});
SettingsService.onSettingsChanged((s) => {
  currentSettings = s;
});

// Session hydration barrier (MV3 recovery)
let resolveSessionHydration!: () => void;
export const sessionHydrationReady = new Promise<void>((resolve) => {
  resolveSessionHydration = resolve;
});

// Shared startup barrier: both settings and session hydration must resolve.
// Fail-closed while pending. Never uses keepalive alarms.
export const startupReady = Promise.all([settingsReady, sessionHydrationReady]).then(() => undefined);

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
  state.navigationGeneration = getTabGeneration(tabId);
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
      currentSettings.sensitiveCookieNames ?? currentSettings.alwaysSensitiveCookies ?? [],
      currentSettings.ignoredCookieNames ?? currentSettings.alwaysIgnoreCookies ?? [],
    );
    originAuthBaselines.set(state.origin, newBaseline);
    void SessionStorage.setAuthBaseline(state.origin, newBaseline);

    if (isAuthEvent && record !== null) {
      void LocalStorage.recordAuthDiff(state.origin, record);
    }

    // Accumulate attack surface graph atomically (serialized per apex domain)
    void (async () => {
      try {
        const u = new URL(state.origin);
        const hostname = u.hostname;
        const apex = registrableDomain(hostname) ?? hostname;
        const discovered = discoverNodes(hostname, state.hops, state.cookies, state.apiEndpoints);
        await LocalStorage.mutateGraph(apex, (existingGraph) =>
          mergeIntoGraph(
            existingGraph,
            hostname,
            state.score,
            state.grade,
            discovered,
            Boolean(currentSettings.isPro),
          ),
        );
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

  badgeTrackedTabs.add(tabId);
  const color = BADGE_COLORS[grade];
  const text = grade === '?' ? '?' : grade;
  chrome.action.setBadgeText({ text, tabId }).catch(() => undefined);
  chrome.action.setBadgeBackgroundColor({ color, tabId }).catch(() => undefined);
}

/**
 * Universal action badge clearing: clears badges across ALL open tabs
 * (including tabs that do not have TabState records, restricted tabs, etc.).
 */
export async function clearBadgesOnAllTabs(): Promise<void> {
  if (typeof chrome !== 'undefined' && typeof chrome.action !== 'undefined') {
    try {
      await chrome.action.setBadgeText({ text: '' });
    } catch {
      // Ignore
    }
  }

  if (
    typeof chrome !== 'undefined' &&
    typeof chrome.tabs !== 'undefined' &&
    typeof chrome.tabs.query === 'function'
  ) {
    try {
      const allTabs = await new Promise<chrome.tabs.Tab[]>((resolve) => {
        chrome.tabs.query({}, (tabs) => resolve(tabs ?? []));
      });
      for (const tab of allTabs) {
        if (tab.id !== undefined && tab.id >= 0) {
          void chrome.action?.setBadgeText?.({ tabId: tab.id, text: '' })?.catch?.(() => undefined);
        }
      }
    } catch {
      for (const tabId of Array.from(tabStates.keys())) {
        void chrome.action?.setBadgeText?.({ tabId, text: '' })?.catch?.(() => undefined);
      }
    }
  } else {
    for (const tabId of Array.from(tabStates.keys())) {
      void chrome.action?.setBadgeText?.({ tabId, text: '' })?.catch?.(() => undefined);
    }
  }
}

// WS1 1C & 1D: Wire atomic settings transition side effects
settingsTransitionPipeline.registerHooks({
  onRescoreTabs: (_prev, _next) => {
    for (const [tabId, state] of Array.from(tabStates.entries())) {
      recomputeTabState(tabId, state);
      void SessionStorage.setTabState(state).catch(() => undefined);
      portRegistry.broadcast(tabId, { type: 'TAB_STATE_UPDATE', state });
    }
  },
  onModeChange: async (_prevMode, newMode) => {
    if (newMode === 'off') {
      // 1. Immediately clear in-flight WebRequest captures (synchronous gate flip)
      clearInFlightCaptures();

      // 2. Clear in-memory tab state and pending reports
      const activeTabIds = Array.from(tabStates.keys());
      tabStates.clear();
      pendingServiceWorkerReports.clear();
      pendingMetaCspReports.clear();

      // 3. Clear session storage entries
      await SessionStorage.clearAllTabStates();

      // 4. Clear badges for ALL open tabs
      await clearBadgesOnAllTabs();

      // 5. Notify open ports for each cleared tab
      for (const tabId of activeTabIds) {
        portRegistry.broadcast(tabId, { type: 'STATE_RESPONSE', state: null });
      }
    }
  },
});

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
  const currentGen = getTabGeneration(tabId);
  const serviceWorkerReport = pendingServiceWorkerReports.get(tabId);
  const isSwCurrent = serviceWorkerReport !== undefined && serviceWorkerReport.generation === currentGen;
  const isMetaCurrent = pendingMetaCspReports.has(tabId);

  const coverage: CoverageInfo = {
    hopsExpected: 1,
    hopsCaptured: 0,
    hasCache: false,
    hasServiceWorker: isSwCurrent && serviceWorkerReport?.status === 'controlled',
    serviceWorkerStatus: isSwCurrent ? (serviceWorkerReport?.status ?? 'unknown') : 'unknown',
    serviceWorkerUrl: isSwCurrent ? (serviceWorkerReport?.serviceWorkerUrl ?? null) : null,
    isRestricted: isRestrictedUrl(url),
    metaCspFound: isMetaCurrent,
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
    navigationGeneration: currentGen,
  };
}

// ---------------------------------------------------------------------------
// onHopComplete — core analysis pipeline
// ---------------------------------------------------------------------------

/**
 * Invoked by capture.ts after both WebRequest stages have completed for a
 * given request.  Runs the full analysis pipeline through the per-tab ordered
 * reducer queue and pushes updates to all connected ports.
 */
async function onHopComplete(
  tabId: number,
  hop: Hop,
): Promise<void> {
  if (!Number.isInteger(tabId) || tabId < 0) return;

  const currentGen = getTabGeneration(tabId);
  if (hop.generation !== undefined && hop.generation !== currentGen) {
    return; // Discard late arrival for older navigation
  }
  const gen = hop.generation ?? currentGen;
  hop.generation = gen;

  pruneTransientStructures();

  await tabActionQueue.enqueue(tabId, gen, async () => {
    // 0. Await settings hydration and session hydration barrier (fail-closed if pending)
    await startupReady;

    if (getTabGeneration(tabId) !== gen) return;

    // 1. Retrieve or initialise tab state.
    const state = tabStates.get(tabId) ?? createDefaultTabState(tabId, hop.url);
    state.navigationGeneration = gen;
    state.url = hop.url;
    state.origin = originFromUrl(hop.url) ?? hop.url;

    // 2. Guard: authoritative fail-closed capture policy.
    const captureCheck = await CapturePolicy.evaluate(hop.url);
    if (!captureCheck.allowed) {
      if (captureCheck.reason === 'off') {
        void chrome.action?.setBadgeText({ tabId, text: '' })?.catch?.(() => undefined);
        return;
      }
      if (captureCheck.reason === 'broad-access-conflict') {
        setBadgeForTab(tabId, '?');
        return;
      }
      if (captureCheck.reason === 'restricted-url') {
        state.coverage.isRestricted = true;
        tabStates.set(tabId, state);
        setBadgeForTab(tabId, '?');
        return;
      }
      // not-permitted or other unprivileged reason
      state.coverage.isRestricted = false;
      setBadgeForTab(tabId, '?');
      return;
    }

    if (pendingMetaCspReports.has(tabId)) {
      state.coverage.metaCspFound = true;
    }
    state.monitoredByUser = true;

    // 4. Append the new hop.
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

    // 5. Correlate cookies (generation-aware).
    const setCookieValues = extractSetCookieHeaders(hop.rawHeaders);
    const correlation = await correlateCookies(
      tabId,
      hop.url,
      setCookieValues,
      gen,
      (t, g) => getTabGeneration(t) === g,
    );
    if (correlation.discarded === true) return;
    state.cookies = correlation.records;
    const captureFindingMap = new Map(
      [...(state.captureFindings ?? []), ...correlation.findings].map((finding) => [
        `${finding.ruleId}:${finding.sourceUrl ?? ''}:${finding.evidence}`,
        finding,
      ]),
    );
    state.captureFindings = [...captureFindingMap.values()];

    // 6. Recompute evaluation from the canonical tab state.
    recomputeTabState(tabId, state);
  });
}

// ---------------------------------------------------------------------------
// Navigation reset
// ---------------------------------------------------------------------------

/**
 * Clears stale analysis state when the user navigates away from a page.
 * Increments per-tab navigation generation counter and invalidates pending tasks.
 */
chrome.webNavigation.onBeforeNavigate.addListener(
  (details: chrome.webNavigation.WebNavigationParentedCallbackDetails): void => {
    // Only reset on top-level frame navigations.
    if (details.frameId !== 0) return;

    const { tabId } = details;
    incrementTabGeneration(tabId);
    tabActionQueue.clearTab(tabId);

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
 * cookie domain using the per-tab ordered action queue.
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

      const gen = getTabGeneration(tabId);
      void tabActionQueue.enqueue(tabId, gen, async () => {
        try {
          const correlation = await correlateCookies(
            tabId,
            state.url,
            [],
            gen,
            (t, g) => getTabGeneration(t) === g,
          );
          if (correlation.discarded === true) return;
          state.cookies = correlation.records;

          recomputeTabState(tabId, state);
        } catch {
          // Silently ignore errors from background re-scoring.
        }
      });
    }
  },
);

// ---------------------------------------------------------------------------
// Tab cleanup
// ---------------------------------------------------------------------------

chrome.tabs.onRemoved.addListener((tabId: number): void => {
  tabGenerations.delete(tabId);
  tabActionQueue.clearTab(tabId);
  tabStates.delete(tabId);
  pendingServiceWorkerReports.delete(tabId);
  pendingMetaCspReports.delete(tabId);
  portRegistry.unregisterTab(tabId);
  badgeTrackedTabs.delete(tabId);

  for (const [requestId, partial] of captureMap.entries()) {
    if (partial.tabId === tabId) {
      captureMap.delete(requestId);
    }
  }

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

    // Push current state immediately once startupReady resolves so the UI doesn't wait for the next hop.
    void startupReady.then(() => {
      const current = currentSettings.monitoringMode !== 'off'
        ? tabStates.get(senderTabId)
        : undefined;
      if (current) {
        const response: StateResponseMessage = {
          type: 'STATE_RESPONSE',
          state: current,
        };
        portSend(port, response);
      }
    });
  }

  port.onMessage.addListener((msg: ExtensionMessage): void => {
    if (msg.type === 'REQUEST_STATE') {
      const resolvedTabId = msg.tabId ?? senderTabId;

      if (resolvedTabId === undefined) return;

      // Register with the resolved tabId in case we didn't have it at connect.
      portRegistry.register(port, resolvedTabId);

      void startupReady.then(() => {
        const stateForTab = currentSettings.monitoringMode !== 'off'
          ? (tabStates.get(resolvedTabId) ?? null)
          : null;
        const response: StateResponseMessage = {
          type: 'STATE_RESPONSE',
          state: stateForTab,
        };
        portSend(port, response);
      });
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
      void startupReady.then(() => {
        const stateForTab = message.tabId !== undefined && currentSettings.monitoringMode !== 'off'
          ? tabStates.get(message.tabId) ?? null
          : null;

        const response: StateResponseMessage = {
          type: 'STATE_RESPONSE',
          state: stateForTab,
        };
        sendResponse(response);
      });
      return true; // Response sent asynchronously after startupReady.
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
          await CapturePolicy.refreshSnapshot();
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
      void (async () => {
        try {
          await settingsTransitionPipeline.transition(message.settings, 'message');
        } catch {
          // Fail closed on unsupported schema or invalid data
        }
        portRegistry.broadcastAll(message);
      })();

      sendResponse(message);
      return false;
    }

    if (message.type === 'SERVICE_WORKER_STATUS') {
      const senderTabId = _sender.tab?.id;
      if (senderTabId !== undefined) {
        const currentGen = getTabGeneration(senderTabId);
        if (message.generation !== undefined && message.generation !== currentGen) {
          return false;
        }
        const gen = message.generation ?? currentGen;
        const eventId = message.eventId ?? `sw:${senderTabId}:${gen}:${message.status}:${message.serviceWorkerUrl ?? ''}`;
        if (isDuplicateEvent(eventId)) {
          return false;
        }

        const report = {
          status: message.status,
          serviceWorkerUrl: message.serviceWorkerUrl,
          generation: gen,
        };
        pendingServiceWorkerReports.set(senderTabId, report);

        void tabActionQueue.enqueue(senderTabId, gen, async () => {
          await startupReady;
          if (getTabGeneration(senderTabId) !== gen) return;

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
        });
      }
      return false;
    }

    if (message.type === 'META_CSP_FOUND') {
      const senderTabId = _sender.tab?.id;
      if (senderTabId !== undefined) {
        const currentGen = getTabGeneration(senderTabId);
        if (message.generation !== undefined && message.generation !== currentGen) {
          return false;
        }
        const gen = message.generation ?? currentGen;
        const policiesStr = (message.policies ?? []).join(';');
        const eventId = message.eventId ?? `meta-csp:${senderTabId}:${gen}:${policiesStr}`;
        if (isDuplicateEvent(eventId)) {
          return false;
        }

        pendingMetaCspReports.add(senderTabId);

        void tabActionQueue.enqueue(senderTabId, gen, async () => {
          await startupReady;
          if (getTabGeneration(senderTabId) !== gen) return;

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
        });
      }
      return false;
    }

    if (message.type === 'SRI_SCAN') {
      const senderTabId = _sender.tab?.id;
      if (senderTabId !== undefined) {
        const currentGen = getTabGeneration(senderTabId);
        if (message.generation !== undefined && message.generation !== currentGen) {
          return false;
        }
        const gen = message.generation ?? currentGen;
        const missingScripts = message.missingIntegrity ?? 0;
        const missingStyles = message.missingStyleIntegrity ?? 0;
        const totalMissing = missingScripts + missingStyles;
        const eventId = message.eventId ?? `sri:${senderTabId}:${gen}:${missingScripts}:${missingStyles}:${message.externalScripts ?? 0}:${message.externalStylesheets ?? 0}`;
        if (isDuplicateEvent(eventId)) {
          return false;
        }

        void tabActionQueue.enqueue(senderTabId, gen, async () => {
          await startupReady;
          if (getTabGeneration(senderTabId) !== gen) return;

          const state = tabStates.get(senderTabId);
          if (state) {
            state.captureFindings = (state.captureFindings ?? []).filter((finding) => finding.ruleId !== 'SRI-001');

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
        });
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

// 1. Arm the periodic maintenance alarm immediately on SW startup.
initLifecycle();

// 2. Begin capturing WebRequest events synchronously to avoid missing early navigations.
registerCaptureListeners(
  (tabId: number, hop: Hop): void => {
    void onHopComplete(tabId, hop);
  },
  (apiHop: ApiHop): void => {
    const tabId = apiHop.tabId;
    if (!Number.isInteger(tabId) || tabId < 0) return;

    const currentGen = getTabGeneration(tabId);
    if (apiHop.generation !== undefined && apiHop.generation !== currentGen) {
      return; // Discard late arrival for older navigation
    }
    const gen = apiHop.generation ?? currentGen;
    apiHop.generation = gen;

    pruneTransientStructures();

    void tabActionQueue.enqueue(tabId, gen, async () => {
      // 0. Await settings hydration and session hydration barrier (fail-closed if pending)
      await startupReady;

      if (getTabGeneration(tabId) !== gen) return;

      const state = tabStates.get(tabId);
      if (!state) return;

      const allowed = await CapturePolicy.isAllowed(apiHop.url);
      if (!allowed) return;
      if (getTabGeneration(tabId) !== gen) return;

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
      state.navigationGeneration = gen;
      void SessionStorage.setTabState(state);

      // Accumulate attack surface graph for API host and CORS endpoints atomically
      void (async () => {
        try {
          const u = new URL(state.origin);
          const hostname = u.hostname;
          const apex = registrableDomain(hostname) ?? hostname;
          const discovered = discoverNodes(hostname, state.hops, state.cookies, state.apiEndpoints);
          await LocalStorage.mutateGraph(apex, (existingGraph) =>
            mergeIntoGraph(
              existingGraph,
              hostname,
              state.score,
              state.grade,
              discovered,
              Boolean(currentSettings.isPro),
            ),
          );
        } catch {
          // Silently ignore graph merge errors
        }
      })();

      portRegistry.broadcast(apiHop.tabId, {
        type: 'TAB_STATE_UPDATE',
        state,
      });
    });
  },
);

// 3. Restore in-memory state from session storage in parallel (survives SW restart).
void hydrateFromSession()
  .then(async () => {
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
  })
  .finally(() => {
    resolveSessionHydration();
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




