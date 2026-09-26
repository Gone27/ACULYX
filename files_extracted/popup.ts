/**
 * popup.ts — SecCheck popup logic
 *
 * Rules enforced here:
 *  - ZERO innerHTML / outerHTML / insertAdjacentHTML
 *  - All user-visible strings set via textContent or createElement+appendChild
 *  - Only chrome.* APIs (no fetch / XHR — connect-src is 'none')
 *
 * New in this version:
 *  - B: Score breakdown <details> panel
 *  - C: "Stop monitoring" button (revokes permission for this origin)
 *  - D: "Export JSON" button (local blob download, no network)
 */

import type { TabState, Finding, CoverageInfo, ScoreBreakdown } from '../shared/types';
import { sendToBackground } from '../shared/messaging';
import { POPUP_PORT_NAME, BADGE_COLORS, SEVERITY_ORDER } from '../shared/constants';

/* ── DOM element references (asserted non-null at init time) ── */
let gradeBadge:        HTMLDivElement;
let scoreText:         HTMLDivElement;
let originText:        HTMLDivElement;
let coverageBar:       HTMLDivElement;
let stateMessage:      HTMLDivElement;
let monitorSection:    HTMLDivElement;
let monitorBtn:        HTMLButtonElement;
let stopMonitoringBtn: HTMLButtonElement;   // C
let findingsSection:   HTMLDivElement;
let findingsList:      HTMLUListElement;
let breakdownSection:  HTMLDetailsElement; // B
let breakdownBody:     HTMLTableSectionElement; // B
let exportBtn:         HTMLButtonElement;   // D
let settingsLink:      HTMLAnchorElement;

/** The tab ID currently being inspected by the popup. */
let currentTabId: number | null = null;
/** The normalised origin (scheme + host + port) of the active tab. */
let currentOrigin: string = '';
/** Last full TabState received — used by the export function. */
let currentState: TabState | null = null;

/* ================================================================
   Boot
   ================================================================ */

document.addEventListener('DOMContentLoaded', () => {
  gradeBadge        = getEl<HTMLDivElement>('grade-badge');
  scoreText         = getEl<HTMLDivElement>('score-text');
  originText        = getEl<HTMLDivElement>('origin-text');
  coverageBar       = getEl<HTMLDivElement>('coverage-bar');
  stateMessage      = getEl<HTMLDivElement>('state-message');
  monitorSection    = getEl<HTMLDivElement>('monitor-section');
  monitorBtn        = getEl<HTMLButtonElement>('monitor-btn');
  stopMonitoringBtn = getEl<HTMLButtonElement>('stop-monitoring-btn');
  findingsSection   = getEl<HTMLDivElement>('findings-section');
  findingsList      = getEl<HTMLUListElement>('findings-list');
  breakdownSection  = getEl<HTMLDetailsElement>('breakdown-section');
  breakdownBody     = getEl<HTMLTableSectionElement>('breakdown-body');
  exportBtn         = getEl<HTMLButtonElement>('export-btn');
  settingsLink      = getEl<HTMLAnchorElement>('settings-link');

  wireSettingsLink();
  wireMonitorButton();
  wireStopMonitoringButton(); // C
  wireExportButton();         // D
  initPopup();
});

/* ================================================================
   Initialisation — query current tab, check permissions, fetch state
   ================================================================ */

async function initPopup(): Promise<void> {
  showStateMessage('Loading…');

  let tabs: chrome.tabs.Tab[];
  try {
    tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  } catch {
    showStateMessage('Unable to determine the active tab.');
    return;
  }

  const tab = tabs[0];
  if (!tab || typeof tab.id !== 'number' || !tab.url) {
    showStateMessage('No active tab found.');
    return;
  }

  currentTabId = tab.id;

  if (isRestrictedUrl(tab.url)) {
    showStateMessage('Restricted page — not inspectable.');
    return;
  }

  let origin: string;
  try {
    origin = new URL(tab.url).origin;
  } catch {
    showStateMessage('Unsupported URL scheme.');
    return;
  }

  currentOrigin = origin;
  originText.textContent = origin;

  const hasPermission = await checkPermission(origin);

  if (!hasPermission) {
    showMonitorSection();
    clearStateMessage();
    return;
  }

  showStateMessage('Analysing…');
  try {
    const response = await sendToBackground({ type: 'REQUEST_STATE', tabId: currentTabId });
    if (response.type === 'STATE_RESPONSE') {
      if (response.state) {
        renderState(response.state);
      } else {
        showStateMessage('Waiting for the first request on this page…');
      }
    }
  } catch {
    showStateMessage('Could not reach the service worker. Try reloading.');
  }

  openLivePort();
}

/* ================================================================
   Live port — receive pushed TAB_STATE_UPDATE messages
   ================================================================ */

function openLivePort(): void {
  if (currentTabId === null) return;

  const port = chrome.runtime.connect({ name: POPUP_PORT_NAME });

  port.onMessage.addListener((msg: unknown) => {
    if (!isTabStateUpdate(msg)) return;
    if (msg.state.tabId === currentTabId) {
      renderState(msg.state);
    }
  });

  port.onDisconnect.addListener(() => {
    // SW restarted — next interaction reconnects.
  });
}

/* ================================================================
   State rendering
   ================================================================ */

function renderState(state: TabState): void {
  currentState = state; // store for export
  clearStateMessage();

  // Grade badge
  gradeBadge.textContent = state.grade;
  gradeBadge.style.background = BADGE_COLORS[state.grade] ?? BADGE_COLORS['?'];

  // Score + origin
  scoreText.textContent = `Score: ${state.score}/100`;
  originText.textContent = state.origin;

  // C: show stop-monitoring button
  stopMonitoringBtn.hidden = false;

  // Coverage warnings
  renderCoverage(state.coverage, state.hops);

  // Findings list (top 5)
  if (state.findings.length > 0) {
    renderFindings(state.findings);
    findingsSection.hidden = false;
  } else {
    findingsSection.hidden = true;
  }

  // B: Score breakdown
  renderBreakdown(state.scoreBreakdown);

  // D: Export button
  exportBtn.hidden = false;

  monitorSection.hidden = true;
}

/* ── Coverage bar ─────────────────────────────────────────────── */

function renderCoverage(
  coverage: CoverageInfo,
  hops: TabState['hops'],
): void {
  const warnings: string[] = [];

  if (coverage.isRestricted) warnings.push('Restricted page');
  if (coverage.hasCache)      warnings.push('⚠ Response from cache — headers may be stale');

  const headersDiffer = hops.some((h) => h.headersDiffer);
  if (headersDiffer) warnings.push('⚠ Headers modified by another extension');

  if (warnings.length === 0) {
    coverageBar.hidden = true;
    coverageBar.textContent = '';
    return;
  }

  coverageBar.textContent = warnings.join(' | ');
  coverageBar.hidden = false;
}

/* ── Findings list ────────────────────────────────────────────── */

function renderFindings(findings: Finding[]): void {
  while (findingsList.firstChild) {
    findingsList.removeChild(findingsList.firstChild);
  }

  const sorted = [...findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );
  const top5 = sorted.slice(0, 5);

  for (const finding of top5) {
    findingsList.appendChild(buildFindingItem(finding));
  }
}

function buildFindingItem(finding: Finding): HTMLLIElement {
  const li = document.createElement('li');
  li.className = `finding-item severity-${finding.severity}`;

  const severitySpan = document.createElement('span');
  severitySpan.className = 'finding-severity';
  severitySpan.textContent = finding.severity;

  const body = document.createElement('div');
  body.className = 'finding-body';

  const titleSpan = document.createElement('span');
  titleSpan.className = 'finding-title';
  titleSpan.textContent = finding.title;
  titleSpan.title = finding.title;

  const evidenceSpan = document.createElement('span');
  evidenceSpan.className = 'finding-evidence';
  evidenceSpan.textContent = finding.evidence;
  evidenceSpan.title = finding.evidence;

  const referenceLink = document.createElement('a');
  referenceLink.className = 'finding-reference';
  referenceLink.href = finding.reference;
  referenceLink.target = '_blank';
  referenceLink.rel = 'noopener noreferrer';
  referenceLink.textContent = 'Learn more →';

  body.appendChild(titleSpan);
  body.appendChild(evidenceSpan);
  body.appendChild(referenceLink);
  li.appendChild(severitySpan);
  li.appendChild(body);

  return li;
}

/* ── B: Score breakdown ───────────────────────────────────────── */

function renderBreakdown(breakdown: ScoreBreakdown[]): void {
  // Clear existing rows
  while (breakdownBody.firstChild) {
    breakdownBody.removeChild(breakdownBody.firstChild);
  }

  // Only show rules that cost points
  const scoring = breakdown.filter((b) => b.penalty > 0);

  if (scoring.length === 0) {
    breakdownSection.hidden = true;
    return;
  }

  for (const item of scoring) {
    const tr = document.createElement('tr');

    const tdRule = document.createElement('td');
    tdRule.className = 'col-rule';
    tdRule.textContent = item.ruleId;

    const tdTitle = document.createElement('td');
    tdTitle.className = 'col-title';
    tdTitle.textContent = item.title;

    const tdPts = document.createElement('td');
    tdPts.className = 'col-pts';
    tdPts.textContent = `−${item.penalty}`;

    tr.appendChild(tdRule);
    tr.appendChild(tdTitle);
    tr.appendChild(tdPts);
    breakdownBody.appendChild(tr);
  }

  breakdownSection.hidden = false;
}

/* ================================================================
   C: Stop monitoring
   ================================================================ */

function wireStopMonitoringButton(): void {
  stopMonitoringBtn.addEventListener('click', () => {
    if (!currentOrigin) return;

    chrome.permissions.remove(
      { origins: [`${currentOrigin}/*`] },
      (removed) => {
        if (removed) {
          // Notify SW so it can flush state and reset badge
          void sendToBackground({
            type: 'PERMISSIONS_CHANGED',
            granted: false,
            origins: [`${currentOrigin}/*`],
          }).catch(() => undefined);

          // Return to un-monitored UI
          stopMonitoringBtn.hidden = true;
          exportBtn.hidden = true;
          breakdownSection.hidden = true;
          findingsSection.hidden = true;
          gradeBadge.textContent = '?';
          gradeBadge.style.background = BADGE_COLORS['?'];
          scoreText.textContent = '';
          currentState = null;
          showMonitorSection();
          clearStateMessage();
        }
      },
    );
  });
}

/* ================================================================
   D: Export JSON
   ================================================================ */

function wireExportButton(): void {
  exportBtn.addEventListener('click', () => {
    if (currentState === null) return;

    // Build a clean export object — no cookie values (CookieRecord has none),
    // no internal IDs, just what's useful to the user.
    const exportData = {
      exportedAt: new Date().toISOString(),
      origin: currentState.origin,
      url: currentState.url,
      grade: currentState.grade,
      score: currentState.score,
      scoreVersion: currentState.scoreVersion,
      findings: currentState.findings,
      scoreBreakdown: currentState.scoreBreakdown,
      cookies: currentState.cookies, // metadata only — no values
      coverage: currentState.coverage,
    };

    const json = JSON.stringify(exportData, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);

    // Derive a safe filename from the origin hostname
    let hostname = 'unknown';
    try {
      hostname = new URL(currentState.origin).hostname;
    } catch { /* leave as 'unknown' */ }

    const date = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
    const filename = `seccheck-${hostname}-${date}.json`;

    // Trigger download via a synthetic anchor click
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });
}

/* ================================================================
   UI helpers
   ================================================================ */

function showStateMessage(msg: string): void {
  stateMessage.textContent = msg;
}

function clearStateMessage(): void {
  stateMessage.textContent = '';
}

function showMonitorSection(): void {
  monitorSection.hidden = false;
  findingsSection.hidden = true;
}

/* ================================================================
   Event wiring
   ================================================================ */

function wireSettingsLink(): void {
  settingsLink.addEventListener('click', (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });
}

function wireMonitorButton(): void {
  monitorBtn.addEventListener('click', () => {
    if (!currentOrigin) return;

    chrome.permissions.request(
      { origins: [`${currentOrigin}/*`] },
      (granted) => {
        if (granted) {
          monitorSection.hidden = true;
          showStateMessage('Waiting for the first request on this page…');

          if (currentTabId !== null) {
            void sendToBackground({
              type: 'PERMISSIONS_CHANGED',
              granted: true,
              origins: [`${currentOrigin}/*`],
            }).catch(() => undefined);
          }

          openLivePort();
        }
      },
    );
  });
}

/* ================================================================
   Utilities
   ================================================================ */

function getEl<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing required element #${id}`);
  return el as T;
}

function isRestrictedUrl(url: string): boolean {
  const RESTRICTED_PREFIXES = [
    'chrome://', 'chrome-extension://', 'about:',
    'edge://', 'brave://', 'data:', 'javascript:', 'view-source:',
  ];
  return RESTRICTED_PREFIXES.some((prefix) => url.startsWith(prefix));
}

function checkPermission(origin: string): Promise<boolean> {
  return new Promise((resolve) => {
    chrome.permissions.contains({ origins: [`${origin}/*`] }, resolve);
  });
}

/* ── Message type-guard ───────────────────────────────────────── */

interface TabStateUpdateMsg {
  type: 'TAB_STATE_UPDATE';
  state: TabState;
}

function isTabStateUpdate(msg: unknown): msg is TabStateUpdateMsg {
  return (
    typeof msg === 'object' &&
    msg !== null &&
    (msg as Record<string, unknown>)['type'] === 'TAB_STATE_UPDATE' &&
    typeof (msg as Record<string, unknown>)['state'] === 'object'
  );
}
