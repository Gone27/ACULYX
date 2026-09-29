/**
 * popup.ts — SecCheck popup logic
 *
 * Rules enforced here:
 *  - ZERO innerHTML / outerHTML / insertAdjacentHTML
 *  - All user-visible strings set via textContent or createElement+appendChild
 *  - Only chrome.* APIs (no fetch / XHR — connect-src is 'none')
 *
 * Sections:
 *  - B: Score breakdown <details> panel
 *  - C: "Stop monitoring" button (revokes permission for this origin)
 *  - D: "Export JSON" button (local blob download, no network)
 *  - E: Subdomain trust analysis panel (new — SUB-001 to SUB-006)
 */

import type {
  TabState,
  Finding,
  CoverageInfo,
  ScoreBreakdown,
  SubdomainTrustAnalysis,
  SubdomainTrustVector,
} from '../shared/types';
import { sendToBackground } from '../shared/messaging';
import { POPUP_PORT_NAME, SEVERITY_ORDER } from '../shared/constants';
import { LocalStorage } from '../shared/storage';

/* ── DOM element references (asserted non-null at init time) ── */
let gradeBadge:          HTMLDivElement;
let badgeGrade:          SVGTextElement;
let scoreText:           HTMLDivElement;
let qualityScoreText:    HTMLDivElement;
let originText:          HTMLDivElement;
let coverageBar:         HTMLDivElement;
let stateMessage:        HTMLDivElement;
let monitorSection:      HTMLDivElement;
let monitorBtn:          HTMLButtonElement;
let stopMonitoringBtn:   HTMLButtonElement;   // C
let findingsSection:     HTMLDivElement;
let findingsList:        HTMLUListElement;
let breakdownSection:    HTMLDetailsElement; // B
let breakdownBody:       HTMLTableSectionElement; // B
let exportBtn:           HTMLButtonElement;   // D
let copyReportBtn:       HTMLButtonElement;   // Markdown audit export
let settingsLink:        HTMLAnchorElement;
let subdomainSection:    HTMLDetailsElement; // E
let subdomainBadge:      HTMLSpanElement;    // E
let vectorList:          HTMLUListElement;   // E
let trustGraph:          SVGSVGElement;
let onboardingCard:      HTMLDivElement;     // 5. Onboarding
let onboardingCloseBtn:  HTMLButtonElement;
let onboardingActionBtn: HTMLButtonElement;
let trendIndicator:      HTMLDivElement;     // 3. Trend over time
let trendChart:          SVGSVGElement;
let trendText:           HTMLSpanElement;
let specialNotice:       HTMLDivElement;     // 8. Graceful edge cases

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
  gradeBadge          = getEl<HTMLDivElement>('grade-badge');
  badgeGrade          = getEl<SVGTextElement>('badge-grade');
  scoreText           = getEl<HTMLDivElement>('score-text');
  qualityScoreText    = getEl<HTMLDivElement>('quality-score-text');
  originText          = getEl<HTMLDivElement>('origin-text');
  coverageBar         = getEl<HTMLDivElement>('coverage-bar');
  stateMessage        = getEl<HTMLDivElement>('state-message');
  monitorSection      = getEl<HTMLDivElement>('monitor-section');
  monitorBtn          = getEl<HTMLButtonElement>('monitor-btn');
  stopMonitoringBtn   = getEl<HTMLButtonElement>('stop-monitoring-btn');
  findingsSection     = getEl<HTMLDivElement>('findings-section');
  findingsList        = getEl<HTMLUListElement>('findings-list');
  breakdownSection    = getEl<HTMLDetailsElement>('breakdown-section');
  breakdownBody       = getEl<HTMLTableSectionElement>('breakdown-body');
  exportBtn           = getEl<HTMLButtonElement>('export-btn');
  copyReportBtn       = getEl<HTMLButtonElement>('copy-report-btn');
  settingsLink        = getEl<HTMLAnchorElement>('settings-link');
  subdomainSection    = getEl<HTMLDetailsElement>('subdomain-section');   // E
  subdomainBadge      = getEl<HTMLSpanElement>('subdomain-badge');         // E
  vectorList          = getEl<HTMLUListElement>('vector-list');            // E
  trustGraph          = getEl<SVGSVGElement>('trust-graph');
  onboardingCard      = getEl<HTMLDivElement>('onboarding-card');
  onboardingCloseBtn  = getEl<HTMLButtonElement>('onboarding-close-btn');
  onboardingActionBtn = getEl<HTMLButtonElement>('onboarding-action-btn');
  trendIndicator      = getEl<HTMLDivElement>('trend-indicator');
  trendChart          = getEl<SVGSVGElement>('trend-chart');
  trendText           = getEl<HTMLSpanElement>('trend-text');
  specialNotice       = getEl<HTMLDivElement>('special-notice');

  wireSettingsLink();
  wireMonitorButton();
  wireStopMonitoringButton(); // C
  wireExportButton();         // D
  wireCopyReportButton();     // Markdown export
  void initOnboarding();
  void initPopup();
});

/* ================================================================
   Initialisation — query current tab, check permissions, fetch state
   ================================================================ */

async function initPopup(): Promise<void> {
  showStateMessage('Loading…', 'loading');

  let tabs: chrome.tabs.Tab[];
  try {
    tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  } catch {
    showStateMessage('Unable to determine the active tab.', 'error');
    return;
  }

  const tab = tabs[0];
  if (!tab || typeof tab.id !== 'number' || tab.url == null || tab.url.length === 0) {
    showStateMessage('No active tab found.', 'error');
    return;
  }

  currentTabId = tab.id;

  if (isRestrictedUrl(tab.url)) {
    originText.textContent = tab.url;
    showStateMessage('Restricted page — browser pages cannot be inspected.', 'restricted');
    return;
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
    return;
  }

  currentOrigin = origin;
  originText.textContent = origin;

  const hasPermission = await checkPermission(origin);

  if (!hasPermission) {
    showMonitorSection();
    showStateMessage('Permission required before this site can be analysed.', 'permission');
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
      }
    }
  } catch {
    showStateMessage('Could not reach the service worker. Try reloading.', 'error');
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
  currentState = state; // store for export
  clearStateMessage();

  // Grade badge & accessibility
  setBadgeState('graded', state.grade, `Security grade ${state.grade}, score ${state.score} of 100`);

  // Score + origin
  scoreText.textContent = `Score: ${state.score}/100`;
  qualityScoreText.textContent = `Configuration quality: ${state.qualityScore ?? 100}/100 (${state.qualityGrade ?? 'A'})`;
  originText.textContent = state.origin;

  // 3. Historical trend over time
  void renderTrend(state.origin, state.score, state.grade);

  // 8. Graceful edge cases (localhost, clean cookie footprint, etc.)
  renderSpecialNotices(state);

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

  // E: Subdomain trust analysis
  renderSubdomainTrust(state.subdomainTrust);

  // 4. Export & Copy buttons
  exportBtn.hidden = false;
  copyReportBtn.hidden = false;

  monitorSection.hidden = true;
}

/* ── Coverage bar ─────────────────────────────────────────────── */

function renderCoverage(
  coverage: CoverageInfo,
  hops: TabState['hops'],
): void {
  const warnings: string[] = [
    `Coverage: ${coverage.hopsCaptured}/${coverage.hopsExpected} response${coverage.hopsExpected === 1 ? '' : 's'}`,
    `Service worker: ${formatServiceWorkerStatus(coverage)}`,
  ];

  if (coverage.isRestricted) warnings.push('Restricted page');
  if (coverage.hasCache) warnings.push('⚠ Response from cache — headers may be stale');
  if (coverage.metaCspFound) warnings.push('Meta CSP detected — policy contents not evaluated');

  const headersDiffer = hops.some((h) => h.headersDiffer);
  if (headersDiffer) warnings.push('⚠ Headers differ between capture points; source cannot be attributed');

  coverageBar.textContent = warnings.join(' | ');
  coverageBar.hidden = false;
}

function formatServiceWorkerStatus(coverage: CoverageInfo): string {
  if (coverage.serviceWorkerStatus === 'controlled') return 'controlled';
  if (coverage.serviceWorkerStatus === 'not-controlled') return 'not detected';
  return 'not verified';
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

  // 2. Explain why, not just what — real-world impact sentence
  if (finding.impact != null && finding.impact.length > 0) {
    const impactSpan = document.createElement('span');
    impactSpan.className = 'finding-impact';
    impactSpan.textContent = `⚡ Impact: ${finding.impact}`;
    body.appendChild(impactSpan);
  }

  if (finding.sourceUrl != null) {
    const sourceLink = document.createElement('a');
    sourceLink.className = 'finding-source';
    sourceLink.href = finding.sourceUrl;
    sourceLink.target = '_blank';
    sourceLink.rel = 'noopener noreferrer';
    sourceLink.textContent = `Found on ${formatSourceHost(finding.sourceUrl)}`;
    sourceLink.title = finding.sourceUrl;
    body.appendChild(sourceLink);
  }

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

/* ── E: Subdomain trust analysis ──────────────────────────────── */

function renderSubdomainTrust(trust: SubdomainTrustAnalysis | undefined): void {
  // Guard: old states (before upgrade) may lack this field
  if (!trust || trust.vectors.length === 0) {
    subdomainSection.hidden = true;
    return;
  }

  // Clear existing vector rows
  while (vectorList.firstChild) {
    vectorList.removeChild(vectorList.firstChild);
  }

  // Escalation badge
  subdomainBadge.textContent = trust.hasEscalationPath
    ? '⚠ Escalation path found'
    : '✔ No escalation path';
  subdomainBadge.className = `subdomain-badge ${trust.hasEscalationPath ? 'has-path' : 'no-path'}`;

  renderTrustGraph(trust.vectors);

  // Render each vector as a list item
  for (const vector of trust.vectors) {
    vectorList.appendChild(buildVectorItem(vector));
  }

  subdomainSection.hidden = false;
}

function renderTrustGraph(vectors: SubdomainTrustVector[]): void {
  const svgNamespace = 'http://www.w3.org/2000/svg';
  const centerX = 160;
  const centerY = 90;
  const positions = [
    { x: 44, y: 28 },
    { x: 116, y: 18 },
    { x: 204, y: 18 },
    { x: 276, y: 28 },
    { x: 276, y: 150 },
    { x: 204, y: 162 },
    { x: 116, y: 162 },
    { x: 44, y: 150 },
  ];
  const graphLabel = vectors.map((vector) => {
    const status = vector.present === true ? 'risk detected' : vector.present === false ? 'protected' : 'not applicable';
    return `${vector.id}: ${status}`;
  }).join('. ');

  const graphTitle = document.createElementNS(svgNamespace, 'title');
  graphTitle.id = 'trust-graph-title';
  graphTitle.textContent = 'Subdomain trust graph';
  const graphDescription = document.createElementNS(svgNamespace, 'desc');
  graphDescription.id = 'trust-graph-description';
  graphDescription.textContent = `Spokes connect the analyzed page to each subdomain trust vector. ${graphLabel}`;
  trustGraph.replaceChildren(graphTitle, graphDescription);
  trustGraph.setAttribute('aria-labelledby', 'trust-graph-title trust-graph-description');

  vectors.forEach((vector, index) => {
    const position = positions[index % positions.length];
    if (!position) return;
    const state = String(vector.present);

    const edgeGroup = document.createElementNS(svgNamespace, 'g');
    const edgeTitle = document.createElementNS(svgNamespace, 'title');
    edgeTitle.id = `trust-edge-title-${vector.id}`;
    edgeTitle.textContent = `${vector.id} link to analyzed page`;
    const edgeDescription = document.createElementNS(svgNamespace, 'desc');
    edgeDescription.id = `trust-edge-description-${vector.id}`;
    edgeDescription.textContent = `Trust bridge status: ${graphLabelForVector(vector)}. Risk level: ${vector.risk}.`;
    edgeGroup.setAttribute('role', 'img');
    edgeGroup.setAttribute('aria-labelledby', `${edgeTitle.id} ${edgeDescription.id}`);
    edgeGroup.append(edgeTitle, edgeDescription);

    const edge = document.createElementNS(svgNamespace, 'line');
    edge.setAttribute('x1', String(centerX));
    edge.setAttribute('y1', String(centerY));
    edge.setAttribute('x2', String(position.x));
    edge.setAttribute('y2', String(position.y));
    edge.setAttribute('class', `trust-edge present-${state}`);
    edge.setAttribute('aria-hidden', 'true');
    edgeGroup.appendChild(edge);
    trustGraph.appendChild(edgeGroup);

    const node = document.createElementNS(svgNamespace, 'g');
    node.setAttribute('class', `trust-node present-${state} risk-${vector.risk}`);
    node.setAttribute('role', 'img');
    const nodeTitle = document.createElementNS(svgNamespace, 'title');
    nodeTitle.id = `trust-node-title-${vector.id}`;
    nodeTitle.textContent = `${vector.id}: ${vector.label}`;
    const nodeDescription = document.createElementNS(svgNamespace, 'desc');
    nodeDescription.id = `trust-node-description-${vector.id}`;
    nodeDescription.textContent = `${graphLabelForVector(vector)}. ${vector.detail}`;
    node.setAttribute('aria-labelledby', `${nodeTitle.id} ${nodeDescription.id}`);
    node.append(nodeTitle, nodeDescription);

    const circle = document.createElementNS(svgNamespace, 'circle');
    circle.setAttribute('cx', String(position.x));
    circle.setAttribute('cy', String(position.y));
    circle.setAttribute('r', '15');
    circle.setAttribute('class', 'trust-node-circle');
    circle.setAttribute('aria-hidden', 'true');
    node.appendChild(circle);

    const label = document.createElementNS(svgNamespace, 'text');
    label.setAttribute('x', String(position.x));
    label.setAttribute('y', String(position.y + 3));
    label.textContent = vector.id.slice(-3);
    label.setAttribute('aria-hidden', 'true');
    node.appendChild(label);
    trustGraph.appendChild(node);
  });

  const center = document.createElementNS(svgNamespace, 'g');
  center.setAttribute('class', 'trust-center');
  center.setAttribute('role', 'img');
  center.setAttribute('aria-labelledby', 'trust-center-title trust-center-description');
  const centerTitle = document.createElementNS(svgNamespace, 'title');
  centerTitle.id = 'trust-center-title';
  centerTitle.textContent = 'Analyzed page';
  const centerDescription = document.createElementNS(svgNamespace, 'desc');
  centerDescription.id = 'trust-center-description';
  centerDescription.textContent = 'Central page node for the subdomain trust bridge graph.';
  center.append(centerTitle, centerDescription);
  const centerCircle = document.createElementNS(svgNamespace, 'circle');
  centerCircle.setAttribute('cx', String(centerX));
  centerCircle.setAttribute('cy', String(centerY));
  centerCircle.setAttribute('r', '28');
  centerCircle.setAttribute('aria-hidden', 'true');
  center.appendChild(centerCircle);

  const centerLabel = document.createElementNS(svgNamespace, 'text');
  centerLabel.setAttribute('x', String(centerX));
  centerLabel.setAttribute('y', String(centerY + 4));
  centerLabel.textContent = 'PAGE';
  centerLabel.setAttribute('aria-hidden', 'true');
  center.appendChild(centerLabel);
  trustGraph.appendChild(center);
}

function graphLabelForVector(vector: SubdomainTrustVector): string {
  if (vector.present === true) return 'risk detected';
  if (vector.present === false) return 'protected';
  return 'not applicable';
}

function buildVectorItem(vector: SubdomainTrustVector): HTMLLIElement {
  const li = document.createElement('li');
  li.className = `vector-item risk-${vector.risk}`;

  // Status dot
  const dot = document.createElement('span');
  dot.className = `vector-dot present-${String(vector.present)}`;

  // Body
  const body = document.createElement('div');
  body.className = 'vector-body';

  const label = document.createElement('span');
  label.className = 'vector-label';
  label.textContent = vector.label;

  const detail = document.createElement('span');
  detail.className = 'vector-detail';
  detail.textContent = vector.detail;
  detail.title = vector.detail;

  body.appendChild(label);
  body.appendChild(detail);

  // Rule ID badge
  const idSpan = document.createElement('span');
  idSpan.className = 'vector-id';
  idSpan.textContent = vector.id;

  li.appendChild(dot);
  li.appendChild(body);
  li.appendChild(idSpan);

  return li;
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
          copyReportBtn.hidden = true;
          trendIndicator.hidden = true;
          specialNotice.hidden = true;
          breakdownSection.hidden = true;
          findingsSection.hidden = true;
          subdomainSection.hidden = true;
          setBadgeState('locked', undefined, 'Site access locked');
          scoreText.textContent = '';
          qualityScoreText.textContent = '';
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
      qualityScore: currentState.qualityScore ?? 100,
      qualityGrade: currentState.qualityGrade ?? 'A',
      scoreVersion: currentState.scoreVersion,
      findings: currentState.findings,
      scoreBreakdown: currentState.scoreBreakdown,
      cookies: currentState.cookies, // metadata only — no values
      coverage: currentState.coverage,
      subdomainTrust: currentState.subdomainTrust, // E: include escalation analysis
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
   4. Markdown Audit Report Export & Copy
   ================================================================ */

function generateMarkdownReport(state: TabState): string {
  const date = new Date().toLocaleString();
  let md = `# Security Audit Report — ${state.origin}\n\n`;
  md += `**Date:** ${date}  \n`;
  md += `**Target URL:** ${state.url}  \n`;
  md += `**Overall Security Grade:** **${state.grade}** (${state.score} / 100)  \n\n`;
  md += `**Configuration Quality:** ${state.qualityGrade ?? 'A'} (${state.qualityScore ?? 100} / 100)  \n\n`;

  md += `## Executive Summary\n`;
  md += `SecCheck conducted an automated, passive inspection of HTTP response headers and cookies for \`${state.origin}\`.\n\n`;

  if (state.subdomainTrust.hasEscalationPath) {
    md += `> ⚠️ **Subdomain Escalation Path Detected:** Trust bridges exist between this site and its subdomains that could allow a compromised subdomain to compromise main-domain sessions or data.\n\n`;
  }

  md += `## Key Findings (${state.findings.length} total)\n\n`;
  if (state.findings.length === 0) {
    md += `No security weaknesses detected. All standard headers and cookie protections are configured properly.\n\n`;
  } else {
    for (const f of state.findings) {
      md += `### [${f.severity.toUpperCase()}] ${f.title}\n`;
      md += `- **Rule ID:** \`${f.ruleId}\`\n`;
      if (f.impact != null && f.impact.length > 0) md += `- **Real-World Impact:** ${f.impact}\n`;
      if (f.evidence.length > 0) md += `- **Evidence:** \`${f.evidence}\`\n`;
      md += `- **Recommendation:** ${f.recommendation}\n`;
      md += `- **Reference:** ${f.reference}\n\n`;
    }
  }

  if (state.subdomainTrust.vectors.length > 0) {
    md += `## Subdomain Trust Analysis\n\n`;
    md += `| Vector ID | Assessment | Detail |\n`;
    md += `|---|---|---|\n`;
    for (const v of state.subdomainTrust.vectors) {
      const status = v.present === true ? '⚠️ Risk confirmed' : v.present === false ? '✅ Protected' : 'ℹ️ N/A';
      md += `| \`${v.id}\` | ${status} | ${v.detail} |\n`;
    }
    md += `\n`;
  }

  md += `---\n*Generated locally by SecCheck Security Extension*\n`;
  return md;
}

function wireCopyReportButton(): void {
  copyReportBtn.addEventListener('click', () => {
    if (currentState === null) return;
    const report = generateMarkdownReport(currentState);
    void navigator.clipboard.writeText(report).then(() => {
      const original = copyReportBtn.textContent;
      copyReportBtn.textContent = '✔ Copied!';
      setTimeout(() => {
        copyReportBtn.textContent = original;
      }, 2000);
    }).catch(() => {
      copyReportBtn.textContent = 'Failed to copy';
    });
  });
}

/* ================================================================
   5. Onboarding Banner
   ================================================================ */

async function initOnboarding(): Promise<void> {
  try {
    const dismissed = await LocalStorage.isOnboardingDismissed();
    if (!dismissed) {
      onboardingCard.hidden = false;
    }
  } catch {
    // Storage access fallback
  }

  const dismiss = async (): Promise<void> => {
    onboardingCard.hidden = true;
    try {
      await LocalStorage.setOnboardingDismissed(true);
    } catch {
      // Storage access fallback
    }
  };

  onboardingCloseBtn.addEventListener('click', () => { void dismiss(); });
  onboardingActionBtn.addEventListener('click', () => { void dismiss(); });
}

/* ================================================================
   3. Historical Trend Over Time
   ================================================================ */

async function renderTrend(origin: string, currentScore: number, currentGrade: TabState['grade']): Promise<void> {
  try {
    const history = await LocalStorage.getOriginHistory(origin);
    if (history.length >= 2) {
      const points = history.slice(-8);
      const lastPoint = points[points.length - 1];
      if (!lastPoint || lastPoint.score !== currentScore || lastPoint.grade !== currentGrade) {
        points.push({ timestamp: Date.now(), score: currentScore, grade: currentGrade });
      }

      if (points.length >= 2) {
        const minScore = Math.min(...points.map((point) => point.score));
        const maxScore = Math.max(...points.map((point) => point.score));
        const coordinates = points.map((point, index) => {
          const x = 4 + (index / (points.length - 1)) * 88;
          const y = maxScore === minScore
            ? 14
            : 24 - ((point.score - minScore) / (maxScore - minScore)) * 20;
          return `${x},${y}`;
        });
        const line = document.createElementNS('http://www.w3.org/2000/svg', 'polyline');
        line.setAttribute('points', coordinates.join(' '));
        line.setAttribute('fill', 'none');
        line.setAttribute('stroke', 'currentColor');
        line.setAttribute('stroke-width', '2');
        trendChart.replaceChildren(line);
        trendChart.setAttribute('aria-label', `Score trend: ${points.map((point) => point.score).join(', ')}`);
        trendChart.removeAttribute('hidden');
      }

      // Compare current score to the previous recorded score
      const prev = history[history.length - 2];
      if (prev != null) {
        const diff = currentScore - prev.score;
        if (diff > 0) {
          trendText.textContent = `↗ +${diff} pts (was ${prev.grade}/${prev.score})`;
          trendIndicator.className = 'trend-indicator trend-improved';
        } else if (diff < 0) {
          trendText.textContent = `↘ ${diff} pts (was ${prev.grade}/${prev.score})`;
          trendIndicator.className = 'trend-indicator trend-regressed';
        } else {
          trendText.textContent = `• Stable ${currentGrade} (${currentScore})`;
          trendIndicator.className = 'trend-indicator trend-stable';
        }
        trendIndicator.hidden = false;
        return;
      }
    }
  } catch {
    // Ignore history error
  }
  trendChart.setAttribute('hidden', '');
  trendIndicator.hidden = true;
}

/* ================================================================
   8. Graceful Edge Case Notices
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

function wireSettingsLink(): void {
  settingsLink.addEventListener('click', (e) => {
    e.preventDefault();
    void chrome.runtime.openOptionsPage();
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
          showStateMessage('Permission granted. Refreshing this page to begin monitoring…', 'waiting');

          if (currentTabId !== null) {
            void sendToBackground({
              type: 'PERMISSIONS_CHANGED',
              granted: true,
              origins: [`${currentOrigin}/*`],
            }).catch(() => undefined);

            openLivePort();
            chrome.tabs.reload(currentTabId, {}, () => {
              if (chrome.runtime.lastError != null) {
                showStateMessage('Permission was granted, but this page could not be refreshed. Reload it to begin monitoring.', 'error');
              }
            });
          }
        }
      },
    );
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

function formatSourceHost(sourceUrl: string): string {
  try {
    return new URL(sourceUrl).hostname;
  } catch {
    return sourceUrl;
  }
}

/* ── Message type-guard ───────────────────────────────────────── */

interface TabStateUpdateMsg {
  type: 'TAB_STATE_UPDATE';
  state: TabState;
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

function isTabStateUpdate(msg: unknown): msg is TabStateUpdateMsg {
  return (
    typeof msg === 'object' &&
    msg !== null &&
    (msg as Record<string, unknown>)['type'] === 'TAB_STATE_UPDATE' &&
    typeof (msg as Record<string, unknown>)['state'] === 'object'
  );
}
