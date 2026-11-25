/**
 * popup.ts — ACULYX Compact Status Launcher
 *
 * Rules enforced here:
 *  - ZERO innerHTML / outerHTML / insertAdjacentHTML
 *  - All user-visible strings set via textContent or createElement+appendChild
 *  - Only chrome.* APIs (no fetch / XHR — connect-src is 'none')
 *  - Fast, responsive launcher for origin status, gating, top 3 teasers, and workspace launch
 */

import type {
  TabState,
  Finding,
  CoverageInfo,
  SettingsV2,
} from '../shared/types';
import { sendToBackground } from '../shared/messaging';
import type { LeadStateUpdateMessage } from '../shared/messaging';
import type { Lead } from '../leads/types';
import { POPUP_PORT_NAME, SEVERITY_ORDER } from '../shared/constants';
import { SettingsService } from '../shared/settings';
import { PermissionsService, patternFromOrigin } from '../background/permissions';
import { isModeCaptureAllowed } from '../shared/gating';
import { selectVisibleFindings } from '../shared/filters';
import { applyAppearance } from '../shared/appearance';

/* ── DOM element references (asserted non-null at init time) ── */
let tabBtnHygiene:       HTMLButtonElement;
let tabBtnLeads:         HTMLButtonElement;
let hygieneView:         HTMLDivElement;
let leadsView:           HTMLDivElement;
let leadsCountBadge:     HTMLSpanElement;
let leadsEmptyState:     HTMLDivElement;
let leadsCardList:       HTMLDivElement;

let gradeBadge:          HTMLDivElement;
let badgeGrade:          SVGTextElement;
let scoreText:           HTMLDivElement;
let qualityScoreText:    HTMLDivElement;
let originText:          HTMLDivElement;
let coverageBar:         HTMLDivElement;
let stateMessage:        HTMLDivElement;
let specialNotice:       HTMLDivElement;
let monitorSection:      HTMLDivElement;
let monitorBtn:          HTMLButtonElement;
let stopMonitoringBtn:   HTMLButtonElement;
let findingsSection:     HTMLDivElement;
let findingsCountBadge:  HTMLSpanElement;
let findingsList:        HTMLUListElement;
let openGraphBtn:        HTMLButtonElement;
let settingsLink:        HTMLAnchorElement;

/** The tab ID currently being inspected by the popup. */
let currentTabId: number | null = null;
/** The active tab full URL. */
let currentTabUrl: string = '';
/** The normalised origin (scheme + host + port) of the active tab. */
let currentOrigin: string = '';
/** Cached settings used for presentation filtering. */
let currentSettings: SettingsV2 | null = null;
/** Current leads list. */
let currentLeads: Lead[] = [];

type PopupDisplayState =
  | 'not-monitored'
  | 'permission-needed'
  | 'permission-denied'
  | 'access-granted-reload'
  | 'capturing'
  | 'results'
  | 'paused-conflict'
  | 'all-sites-missing'
  | 'restricted';

function setPopupState(s: PopupDisplayState): void {
  document.body.dataset['state'] = s;
}

/* ================================================================
   Boot
   ================================================================ */

document.addEventListener('DOMContentLoaded', () => {
  tabBtnHygiene       = getEl<HTMLButtonElement>('tab-btn-hygiene');
  tabBtnLeads         = getEl<HTMLButtonElement>('tab-btn-leads');
  hygieneView         = getEl<HTMLDivElement>('hygiene-view');
  leadsView           = getEl<HTMLDivElement>('leads-view');
  leadsCountBadge     = getEl<HTMLSpanElement>('leads-count-badge');
  leadsEmptyState     = getEl<HTMLDivElement>('leads-empty-state');
  leadsCardList       = getEl<HTMLDivElement>('leads-card-list');

  gradeBadge          = getEl<HTMLDivElement>('grade-badge');
  badgeGrade          = getEl<SVGTextElement>('badge-grade');
  scoreText           = getEl<HTMLDivElement>('score-text');
  qualityScoreText    = getEl<HTMLDivElement>('quality-score-text');
  originText          = getEl<HTMLDivElement>('origin-text');
  coverageBar         = getEl<HTMLDivElement>('coverage-bar');
  stateMessage        = getEl<HTMLDivElement>('state-message');
  specialNotice       = getEl<HTMLDivElement>('special-notice');
  monitorSection      = getEl<HTMLDivElement>('monitor-section');
  monitorBtn          = getEl<HTMLButtonElement>('monitor-btn');
  stopMonitoringBtn   = getEl<HTMLButtonElement>('stop-monitoring-btn');
  findingsSection     = getEl<HTMLDivElement>('findings-section');
  findingsCountBadge  = getEl<HTMLSpanElement>('findings-count-badge');
  findingsList        = getEl<HTMLUListElement>('findings-list');
  openGraphBtn        = getEl<HTMLButtonElement>('open-graph-btn');
  settingsLink        = getEl<HTMLAnchorElement>('settings-link');

  wireSegmentedControl();
  wireSettingsLink();
  wireMonitorButton();
  wireStopMonitoringButton();
  wireOpenWorkspaceButton();

  SettingsService.onSettingsChanged((newSettings) => {
    currentSettings = newSettings;
    applyAppearance(newSettings.theme, newSettings.density, newSettings.reducedMotion);
  });

  void initPopup();
});

/* ================================================================
   Initialisation — query current tab, check permissions, fetch state
   ================================================================ */

async function initPopup(): Promise<void> {
  showStateMessage('Loading…', 'loading');

  const urlParams = new URLSearchParams(window.location.search);
  const paramTabId = urlParams.get('tabId');
  let tab: chrome.tabs.Tab | undefined;

  if (paramTabId !== null && paramTabId.length > 0) {
    const id = parseInt(paramTabId, 10);
    if (!Number.isNaN(id)) {
      try {
        tab = await chrome.tabs.get(id);
      } catch {
        // Fall back to querying active tab
      }
    }
  }

  if (tab === undefined) {
    let tabs: chrome.tabs.Tab[];
    try {
      tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    } catch {
      showStateMessage('Unable to determine the active tab.', 'error');
      return;
    }
    tab = tabs[0];
  }

  if (!tab || typeof tab.id !== 'number' || tab.url == null || tab.url.length === 0) {
    showStateMessage('No active tab found.', 'error');
    return;
  }

  currentTabId = tab.id;
  currentTabUrl = tab.url;

  const settings = await SettingsService.getSettings();
  currentSettings = settings;
  applyAppearance(settings.theme, settings.density, settings.reducedMotion);
  const broadActive = await PermissionsService.isBroadGrantPresent();
  const completeBroad = await PermissionsService.hasCompleteBroadGrant();
  const gate = isModeCaptureAllowed(tab.url, settings, broadActive, undefined, completeBroad);
  if (!gate.allowed) {
    if (gate.reason === 'off') {
      originText.textContent = tab.url;
      showStateMessage('Monitoring is turned off in Settings.');
      setPopupState('not-monitored');
      return;
    }
    if (gate.reason === 'broad-access-conflict') {
      originText.textContent = tab.url;
      showBroadAccessConflictNotice();
      setPopupState('paused-conflict');
      return;
    }
    if (gate.reason === 'all-sites-missing-grant') {
      originText.textContent = tab.url;
      showAllSitesMissingNotice();
      setPopupState('all-sites-missing');
      return;
    }
    if (gate.reason === 'restricted-url') {
      originText.textContent = tab.url;
      showStateMessage('Restricted page — browser pages cannot be inspected.', 'restricted');
      setPopupState('restricted');
      return;
    }
  }

  if (tab.url.toLowerCase().endsWith('.pdf') || tab.url.toLowerCase().includes('.pdf?')) {
    specialNotice.textContent = '📄 Static Document: This tab displays a PDF/document file where web application security headers and cookies do not apply.';
    specialNotice.className = 'special-notice';
    specialNotice.hidden = false;
  }

  let origin: string;
  try {
    origin = new URL(tab.url).origin;
  } catch {
    showStateMessage('Unsupported URL scheme.', 'restricted');
    setPopupState('restricted');
    return;
  }

  currentOrigin = origin;
  originText.textContent = origin;

  const hasPermission = broadActive || (await checkPermission(origin));

  if (!hasPermission) {
    showMonitorSection();
    showStateMessage('Permission required before this site can be analysed.', 'permission');
    setPopupState('permission-needed');
    return;
  }

  showStateMessage('Analysing…', 'loading');
  try {
    const response = await sendToBackground({ type: 'REQUEST_STATE', tabId: currentTabId });
    if (response.type === 'STATE_RESPONSE') {
      if (response.state) {
        renderState(response.state);
      } else {
        showStateMessage('Waiting for the first response on this page…', 'waiting');
        setPopupState('capturing');
      }
    }
  } catch {
    showStateMessage('Could not reach the service worker. Try reloading.', 'error');
  }

  openLivePort();
  if (currentSettings?.leadsEnabled === true) {
    void sendToBackground({ type: 'TRIGGER_LEADS_SCAN', tabId: currentTabId, url: currentTabUrl }).catch(() => undefined);
  }
  void refreshLeads();
}

/* ================================================================
   Live port — receive pushed TAB_STATE_UPDATE messages
   ================================================================ */

function openLivePort(): void {
  if (currentTabId === null) return;

  const port = chrome.runtime.connect({ name: POPUP_PORT_NAME });

  port.onMessage.addListener((msg: unknown) => {
    if (typeof msg === 'object' && msg !== null && (msg as { type?: string }).type === 'SETTINGS_CHANGED') {
      const newSettings = (msg as { settings?: SettingsV2 }).settings;
      if (newSettings !== undefined) {
        currentSettings = newSettings;
        applyAppearance(newSettings.theme, newSettings.density, newSettings.reducedMotion);
      }
      return;
    }
    if (typeof msg === 'object' && msg !== null && (msg as { type?: string }).type === 'LEAD_STATE_UPDATE') {
      const leadMsg = msg as LeadStateUpdateMessage;
      if (!currentOrigin || leadMsg.origin === currentOrigin || (leadMsg.tabId !== undefined && leadMsg.tabId === currentTabId)) {
        currentLeads = leadMsg.leads ?? [];
        renderLeadsTeaser(currentLeads);
      }
      return;
    }
    if (isStateResponse(msg) && msg.state?.tabId === currentTabId) {
      renderState(msg.state);
      return;
    }
    if (!isTabStateUpdate(msg)) return;
    if (msg.state.tabId === currentTabId) {
      renderState(msg.state);
    }
  });

  port.postMessage({ type: 'REQUEST_STATE', tabId: currentTabId });

  port.onDisconnect.addListener(() => {
    // SW restarted — next interaction reconnects.
  });
}

/* ================================================================
   State rendering
   ================================================================ */

function renderState(state: TabState): void {
  const savedScrollTop = document.documentElement.scrollTop || document.body.scrollTop;

  clearStateMessage();

  if (state.hops.length === 0 || state.grade === '?') {
    setPopupState('capturing');
    setBadgeState('scanning', '?', 'No security data captured yet');
    gradeBadge.className = 'grade-badge grade-unknown';
    scoreText.textContent = 'Score: No data';
    qualityScoreText.textContent = '';
  } else {
    setPopupState('results');
    setBadgeState('graded', state.grade, `Security grade ${state.grade}, score ${state.score} of 100`);
    gradeBadge.className = 'grade-badge grade-' + (state.grade?.toLowerCase() ?? 'unknown');

    scoreText.textContent = `Score: ${state.score}/100`;
    qualityScoreText.textContent = `Quality: ${state.qualityScore ?? 100}/100 (${state.qualityGrade ?? 'A'})`;
  }
  originText.textContent = state.origin;

  renderSpecialNotices(state);

  stopMonitoringBtn.hidden = false;
  monitorSection.hidden = true;

  renderCoverage(state.coverage, state.hops);
  renderFindingsTeaser(state.findings);

  if (savedScrollTop > 0) {
    document.documentElement.scrollTop = savedScrollTop;
    document.body.scrollTop = savedScrollTop;
  }
}

/* ── Coverage bar ─────────────────────────────────────────────── */

function renderCoverage(
  coverage: CoverageInfo,
  hops: TabState['hops'],
): void {
  const warnings: string[] = [
    `Coverage: ${coverage.hopsCaptured}/${coverage.hopsExpected} response${coverage.hopsExpected === 1 ? '' : 's'}`,
  ];

  if (coverage.serviceWorkerStatus === 'controlled') {
    warnings.push('SW: controlled');
  } else if (coverage.serviceWorkerStatus === 'not-controlled') {
    warnings.push('SW: not detected');
  }

  if (coverage.isRestricted) warnings.push('Restricted page');
  if (coverage.hasCache) warnings.push('⚠ Cached response');
  if (coverage.metaCspFound) warnings.push('Meta CSP present');

  const headersDiffer = hops.some((h) => h.headersDiffer);
  if (headersDiffer) warnings.push('⚠ Headers differ between points');

  if (Array.isArray(coverage.blindSpots)) {
    for (const spot of coverage.blindSpots) {
      if (!warnings.some((w) => w.toLowerCase().includes(spot.slice(0, 15).toLowerCase()))) {
        warnings.push(`⚠ ${spot}`);
      }
    }
  }

  coverageBar.textContent = warnings.join(' | ');
  coverageBar.hidden = false;
}

/* ── Top 3 Findings Teaser (Safe text DOM APIs, zero innerHTML) ─── */

function renderFindingsTeaser(findings: Finding[]): void {
  while (findingsList.firstChild) {
    findingsList.removeChild(findingsList.firstChild);
  }

  const severityFilter = currentSettings?.severityFilter ?? SEVERITY_ORDER;
  const { visibleFindings } = selectVisibleFindings(
    findings,
    severityFilter,
    false,
  );

  const sorted = [...visibleFindings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );
  const top3 = sorted.slice(0, 3);

  const actionableCount = findings.filter(
    (f) => f.severity !== 'info' && f.severity !== 'pass' && f.outcome !== 'pass',
  ).length;
  const infoHardeningCount = findings.length - actionableCount;
  findingsCountBadge.textContent = infoHardeningCount > 0
    ? `${actionableCount} issues · ${infoHardeningCount} hardening`
    : `${actionableCount} issues`;

  if (top3.length === 0) {
    findingsSection.hidden = true;
    return;
  }

  findingsSection.hidden = false;

  for (const finding of top3) {
    const li = document.createElement('li');
    li.className = `finding-item severity-${finding.severity}`;
    li.dataset['severity'] = finding.severity;

    const headerRow = document.createElement('div');
    headerRow.className = 'finding-header-row';

    const pill = document.createElement('span');
    pill.className = `finding-severity-pill severity-${finding.severity}`;
    pill.textContent = finding.severity.toUpperCase();

    const titleSpan = document.createElement('span');
    titleSpan.className = 'finding-title';
    titleSpan.textContent = finding.title;

    headerRow.appendChild(pill);
    headerRow.appendChild(titleSpan);

    li.appendChild(headerRow);

    if (finding.impact !== undefined && finding.impact.length > 0) {
      const impactEl = document.createElement('p');
      impactEl.className = 'finding-impact-text';
      impactEl.textContent = finding.impact;
      li.appendChild(impactEl);
    } else if (finding.evidence.length > 0) {
      const evEl = document.createElement('p');
      evEl.className = 'finding-evidence-text';
      evEl.textContent = finding.evidence;
      li.appendChild(evEl);
    }

    findingsList.appendChild(li);
  }
}

/* ── Top 3 Leads Teaser (Safe text DOM APIs, zero innerHTML) ────── */

function renderLeadsTeaser(leads: Lead[]): void {
  while (leadsCardList.firstChild) {
    leadsCardList.removeChild(leadsCardList.firstChild);
  }

  leadsCountBadge.textContent = `${leads.length} lead${leads.length === 1 ? '' : 's'}`;

  if (leads.length === 0) {
    leadsEmptyState.hidden = false;
    return;
  }

  leadsEmptyState.hidden = true;

  const top3 = leads.slice(0, 3);
  for (const lead of top3) {
    const card = document.createElement('div');
    card.className = `lead-teaser-card potential-${lead.potential ?? 'info'}`;

    const topRow = document.createElement('div');
    topRow.className = 'lead-card-top';

    const potentialBadge = document.createElement('span');
    potentialBadge.className = `lead-tier-badge tier-${lead.potential ?? 'info'}`;
    potentialBadge.textContent = (lead.potential ?? lead.tier ?? 'INFO').toUpperCase();

    const familyBadge = document.createElement('span');
    familyBadge.className = 'lead-family-badge';
    familyBadge.textContent = lead.family ?? 'LEAD';

    topRow.appendChild(potentialBadge);
    topRow.appendChild(familyBadge);

    const titleEl = document.createElement('p');
    titleEl.className = 'lead-title';
    titleEl.textContent = lead.title;

    card.appendChild(topRow);
    card.appendChild(titleEl);

    const detail = lead.verdict?.summary ?? lead.remediation ?? (lead.evidence.location.length > 0 ? String(lead.evidence.location) : '');
    if (detail.length > 0) {
      const descEl = document.createElement('p');
      descEl.className = 'lead-desc';
      descEl.textContent = detail;
      card.appendChild(descEl);
    }

    leadsCardList.appendChild(card);
  }
}

async function refreshLeads(): Promise<void> {
  if (currentTabId === null && (currentOrigin === null || currentOrigin.length === 0)) return;
  try {
    const res = await sendToBackground({
      type: 'GET_LEADS_STATE',
      tabId: currentTabId ?? undefined,
      origin: currentOrigin !== null && currentOrigin.length > 0 ? currentOrigin : undefined,
    });
    if (res.type === 'LEAD_STATE_UPDATE') {
      currentLeads = res.leads ?? [];
      renderLeadsTeaser(currentLeads);
    }
  } catch {
    // Background service worker might be waking up
  }
}

/* ================================================================
   Special Notices
   ================================================================ */

function renderSpecialNotices(state: TabState): void {
  let isLocalhost = false;
  try {
    const hostname = new URL(state.origin).hostname;
    isLocalhost = hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
  } catch {
    // Ignore URL parse error
  }

  if (isLocalhost) {
    specialNotice.textContent = '🔧 Localhost Development: Public domain cookie rules and strict HSTS requirements are relaxed for local development servers.';
    specialNotice.className = 'special-notice notice-warning';
    specialNotice.hidden = false;
    return;
  }

  if (state.url.startsWith('http://')) {
    specialNotice.textContent = '⚠️ Plain HTTP: Connection is unencrypted — network traffic and cookies can be intercepted.';
    specialNotice.className = 'special-notice notice-warning';
    specialNotice.hidden = false;
    return;
  }

  if (state.cookies.length === 0) {
    specialNotice.textContent = '🌱 Clean Cookie Footprint: Zero cookies set on this page.';
    specialNotice.className = 'special-notice notice-success';
    specialNotice.hidden = false;
    return;
  }

  specialNotice.hidden = true;
}

/* ================================================================
   UI helpers
   ================================================================ */

function showStateMessage(
  msg: string,
  mode: 'loading' | 'waiting' | 'permission' | 'restricted' | 'error' = 'waiting',
): void {
  if (mode === 'loading' || mode === 'waiting') {
    setBadgeState('scanning', undefined, 'Checking this page');
  } else if (mode === 'permission' || mode === 'restricted' || mode === 'error') {
    setBadgeState('locked', undefined, mode === 'permission' ? 'Site access locked' : 'Page not available for analysis');
  }
  stateMessage.textContent = msg;
  stateMessage.className = `state-message state-${mode}`;
}

function setBadgeState(
  state: 'locked' | 'scanning' | 'graded',
  grade: TabState['grade'] | undefined,
  label: string,
): void {
  gradeBadge.dataset['state'] = state;
  if (grade === undefined) {
    gradeBadge.removeAttribute('data-grade');
    badgeGrade.textContent = '?';
  } else {
    gradeBadge.dataset['grade'] = grade;
    badgeGrade.textContent = grade;
  }
  gradeBadge.setAttribute('aria-label', label);
}

function clearStateMessage(): void {
  stateMessage.textContent = '';
  stateMessage.className = 'state-message';
}

function showMonitorSection(): void {
  monitorSection.hidden = false;
  findingsSection.hidden = true;
}

/* ================================================================
   Event wiring
   ================================================================ */

function wireSegmentedControl(): void {
  tabBtnHygiene.addEventListener('click', () => {
    tabBtnHygiene.classList.add('active');
    tabBtnHygiene.setAttribute('aria-selected', 'true');
    tabBtnLeads.classList.remove('active');
    tabBtnLeads.setAttribute('aria-selected', 'false');
    hygieneView.hidden = false;
    hygieneView.classList.add('active');
    leadsView.hidden = true;
    leadsView.classList.remove('active');
  });

  tabBtnLeads.addEventListener('click', () => {
    tabBtnLeads.classList.add('active');
    tabBtnLeads.setAttribute('aria-selected', 'true');
    tabBtnHygiene.classList.remove('active');
    tabBtnHygiene.setAttribute('aria-selected', 'false');
    leadsView.hidden = false;
    leadsView.classList.add('active');
    hygieneView.hidden = true;
    hygieneView.classList.remove('active');
    if (currentSettings?.leadsEnabled === true && currentTabId !== null && currentTabUrl.length > 0) {
      void sendToBackground({ type: 'TRIGGER_LEADS_SCAN', tabId: currentTabId, url: currentTabUrl }).catch(() => undefined);
    }
    void refreshLeads();
  });
}

function wireSettingsLink(): void {
  settingsLink.addEventListener('click', (e) => {
    e.preventDefault();
    void chrome.runtime.openOptionsPage();
  });
}

function wireMonitorButton(): void {
  monitorBtn.addEventListener('click', () => {
    if (!currentOrigin) return;

    const pattern = patternFromOrigin(currentOrigin);
    chrome.permissions.request(
      { origins: [pattern] },
      (granted) => {
        if (granted) {
          monitorSection.hidden = true;
          showStateMessage('Permission granted. Refreshing this page to begin monitoring…', 'waiting');
          setPopupState('access-granted-reload');

          if (currentTabId !== null) {
            void sendToBackground({
              type: 'PERMISSIONS_CHANGED',
              granted: true,
              origins: [pattern],
            }).catch(() => undefined);

            openLivePort();
            chrome.tabs.reload(currentTabId, {}, () => {
              if (chrome.runtime.lastError != null) {
                showStateMessage('Permission was granted, but this page could not be refreshed. Reload it to begin monitoring.', 'error');
              }
            });
          }
        } else {
          setPopupState('permission-denied');
        }
      },
    );
  });
}

function wireStopMonitoringButton(): void {
  stopMonitoringBtn.addEventListener('click', () => {
    if (!currentOrigin) return;

    const pattern = patternFromOrigin(currentOrigin);
    chrome.permissions.remove(
      { origins: [pattern] },
      (removed) => {
        if (removed) {
          void sendToBackground({
            type: 'PERMISSIONS_CHANGED',
            granted: false,
            origins: [pattern],
          }).catch(() => undefined);

          stopMonitoringBtn.hidden = true;
          specialNotice.hidden = true;
          findingsSection.hidden = true;
          setBadgeState('locked', undefined, 'Site access locked');
          scoreText.textContent = '';
          qualityScoreText.textContent = '';
          showMonitorSection();
          clearStateMessage();
          setPopupState('not-monitored');
        }
      },
    );
  });
}

interface SidePanelApi {
  open: (options: { tabId?: number; windowId?: number }) => Promise<void>;
}

function openWorkspaceInTab(): void {
  let apex = '';
  if (currentOrigin) {
    try {
      apex = new URL(currentOrigin).hostname;
    } catch {
      // ignore
    }
  }
  const tabParam = currentTabId !== null ? `&tabId=${currentTabId}` : '';
  const apexParam = apex ? `?apex=${encodeURIComponent(apex)}` : '';
  const url = chrome.runtime.getURL(`src/sidepanel/sidepanel.html${apexParam}${tabParam}`);
  void chrome.tabs.create({ url });
}

function wireOpenWorkspaceButton(): void {
  openGraphBtn.addEventListener('click', () => {
    try {
      const sp = (chrome as unknown as { sidePanel?: SidePanelApi }).sidePanel;
      if (sp !== undefined && typeof sp.open === 'function') {
        if (currentTabId !== null) {
          sp.open({ tabId: currentTabId }).catch(() => {
            chrome.windows.getCurrent((win) => {
              if (win.id !== undefined && sp !== undefined) {
                sp.open({ windowId: win.id }).catch(() => {
                  openWorkspaceInTab();
                });
              } else {
                openWorkspaceInTab();
              }
            });
          });
        } else {
          chrome.windows.getCurrent((win) => {
            if (win.id !== undefined && sp !== undefined) {
              sp.open({ windowId: win.id }).catch(() => {
                openWorkspaceInTab();
              });
            } else {
              openWorkspaceInTab();
            }
          });
        }
        return;
      }
    } catch {
      // Firefox fallback
    }
    openWorkspaceInTab();
  });
}

/* ================================================================
   Utilities
   ================================================================ */

function getEl<T extends Element>(id: string): T {
  const el = document.querySelector<T>(`#${CSS.escape(id)}`);
  if (!el) throw new Error(`Missing required element #${id}`);
  return el;
}

function showBroadAccessConflictNotice(): void {
  specialNotice.textContent = '';
  const p = document.createElement('p');
  p.textContent = 'Broad access is active while monitoring mode is set to Per-site opt-in. Capture is paused until resolved:';

  const actions = document.createElement('div');
  actions.style.display = 'flex';
  actions.style.gap = '8px';
  actions.style.marginTop = '8px';

  const removeBtn = document.createElement('button');
  removeBtn.className = 'btn-secondary';
  removeBtn.textContent = 'Remove broad access';
  removeBtn.addEventListener('click', () => {
    removeBtn.disabled = true;
    void PermissionsService.removeAllBroadGrants().then((success) => {
      removeBtn.disabled = false;
      if (success) {
        void initPopup();
      } else {
        showStateMessage('Failed to remove broad access or broad grants still remain.', 'error');
      }
    });
  });

  const switchBtn = document.createElement('button');
  switchBtn.className = 'btn-primary';
  switchBtn.textContent = 'Switch to All sites';
  switchBtn.addEventListener('click', () => {
    void SettingsService.updateSettings({ monitoringMode: 'all-sites' }).then(() => {
      void initPopup();
    });
  });

  actions.appendChild(removeBtn);
  actions.appendChild(switchBtn);
  specialNotice.appendChild(p);
  specialNotice.appendChild(actions);
  specialNotice.className = 'special-notice conflict-notice';
  specialNotice.hidden = false;
  showStateMessage('Capture paused due to broad access conflict.', 'waiting');
}

function showAllSitesMissingNotice(): void {
  specialNotice.textContent = '';
  const p = document.createElement('p');
  p.textContent = 'All-sites monitoring is enabled, but the required broad permissions are missing. Capture is paused until resolved:';

  const actions = document.createElement('div');
  actions.style.display = 'flex';
  actions.style.gap = '8px';
  actions.style.marginTop = '8px';

  const restoreBtn = document.createElement('button');
  restoreBtn.className = 'btn-primary';
  restoreBtn.textContent = 'Restore All-sites access';
  restoreBtn.addEventListener('click', () => {
    chrome.permissions.request({ origins: ['<all_urls>'] }, (granted) => {
      if (granted) {
        void initPopup();
      }
    });
  });

  const switchBtn = document.createElement('button');
  switchBtn.className = 'btn-secondary';
  switchBtn.textContent = 'Switch to per-site';
  switchBtn.addEventListener('click', () => {
    void SettingsService.updateSettings({ monitoringMode: 'per-site' }).then(() => {
      void initPopup();
    });
  });

  actions.appendChild(restoreBtn);
  actions.appendChild(switchBtn);
  specialNotice.appendChild(p);
  specialNotice.appendChild(actions);
  specialNotice.className = 'special-notice conflict-notice';
  specialNotice.hidden = false;
  showStateMessage('Capture paused due to missing broad permissions.', 'waiting');
}

function checkPermission(origin: string): Promise<boolean> {
  const pattern = patternFromOrigin(origin);
  return new Promise((resolve) => {
    chrome.permissions.contains({ origins: [pattern] }, (result) => {
      if (result) {
        resolve(true);
        return;
      }
      const direct = `${origin}/*`;
      if (direct !== pattern) {
        chrome.permissions.contains({ origins: [direct] }, resolve);
      } else {
        resolve(false);
      }
    });
  });
}

interface StateResponseMsg {
  type: 'STATE_RESPONSE';
  state: TabState | null;
}

function isStateResponse(msg: unknown): msg is StateResponseMsg {
  return typeof msg === 'object'
    && msg !== null
    && (msg as Record<string, unknown>)['type'] === 'STATE_RESPONSE'
    && 'state' in msg;
}

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
