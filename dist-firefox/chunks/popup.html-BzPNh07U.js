import "./modulepreload-polyfill-DaKOjhqt.js";
import { s as sendToBackground, P as POPUP_PORT_NAME, e as SEVERITY_ORDER, L as LocalStorage } from "./messaging-BtQvrPlz.js";
import { r as reportPageSignals } from "./service-worker-detection-B9LeGWmi.js";
let gradeBadge;
let badgeGrade;
let scoreText;
let qualityScoreText;
let originText;
let coverageBar;
let stateMessage;
let monitorSection;
let monitorBtn;
let stopMonitoringBtn;
let findingsSection;
let findingsList;
let breakdownSection;
let breakdownBody;
let exportBtn;
let copyReportBtn;
let settingsLink;
let subdomainSection;
let subdomainBadge;
let vectorList;
let trustGraph;
let onboardingCard;
let onboardingCloseBtn;
let onboardingActionBtn;
let trendIndicator;
let trendChart;
let trendText;
let specialNotice;
let currentTabId = null;
let currentOrigin = "";
let currentState = null;
document.addEventListener("DOMContentLoaded", () => {
  gradeBadge = getEl("grade-badge");
  badgeGrade = getEl("badge-grade");
  scoreText = getEl("score-text");
  qualityScoreText = getEl("quality-score-text");
  originText = getEl("origin-text");
  coverageBar = getEl("coverage-bar");
  stateMessage = getEl("state-message");
  monitorSection = getEl("monitor-section");
  monitorBtn = getEl("monitor-btn");
  stopMonitoringBtn = getEl("stop-monitoring-btn");
  findingsSection = getEl("findings-section");
  findingsList = getEl("findings-list");
  breakdownSection = getEl("breakdown-section");
  breakdownBody = getEl("breakdown-body");
  exportBtn = getEl("export-btn");
  copyReportBtn = getEl("copy-report-btn");
  settingsLink = getEl("settings-link");
  subdomainSection = getEl("subdomain-section");
  subdomainBadge = getEl("subdomain-badge");
  vectorList = getEl("vector-list");
  trustGraph = getEl("trust-graph");
  onboardingCard = getEl("onboarding-card");
  onboardingCloseBtn = getEl("onboarding-close-btn");
  onboardingActionBtn = getEl("onboarding-action-btn");
  trendIndicator = getEl("trend-indicator");
  trendChart = getEl("trend-chart");
  trendText = getEl("trend-text");
  specialNotice = getEl("special-notice");
  wireSettingsLink();
  wireMonitorButton();
  wireStopMonitoringButton();
  wireExportButton();
  wireCopyReportButton();
  void initOnboarding();
  void initPopup();
});
async function initPopup() {
  showStateMessage("Loading…", "loading");
  let tabs;
  try {
    tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  } catch {
    showStateMessage("Unable to determine the active tab.", "error");
    return;
  }
  const tab = tabs[0];
  if (!tab || typeof tab.id !== "number" || tab.url == null || tab.url.length === 0) {
    showStateMessage("No active tab found.", "error");
    return;
  }
  currentTabId = tab.id;
  if (isRestrictedUrl(tab.url)) {
    originText.textContent = tab.url;
    showStateMessage("Restricted page — browser pages cannot be inspected.", "restricted");
    return;
  }
  if (tab.url.toLowerCase().endsWith(".pdf") || tab.url.toLowerCase().includes(".pdf?")) {
    specialNotice.textContent = "📄 Static Document: This tab displays a PDF/document file where web application security headers and cookies do not apply.";
    specialNotice.className = "special-notice";
    specialNotice.hidden = false;
  }
  let origin;
  try {
    origin = new URL(tab.url).origin;
  } catch {
    showStateMessage("Unsupported URL scheme.", "restricted");
    return;
  }
  currentOrigin = origin;
  originText.textContent = origin;
  const hasPermission = await checkPermission(origin);
  if (!hasPermission) {
    showMonitorSection();
    showStateMessage("Permission required before this site can be analysed.", "permission");
    return;
  }
  showStateMessage("Analysing…", "loading");
  try {
    const response = await sendToBackground({ type: "REQUEST_STATE", tabId: currentTabId });
    if (response.type === "STATE_RESPONSE") {
      if (response.state) {
        renderState(response.state);
      } else {
        showStateMessage("Waiting for the first response on this page…", "waiting");
      }
    }
  } catch {
    showStateMessage("Could not reach the service worker. Try reloading.", "error");
  }
  openLivePort();
}
function openLivePort() {
  if (currentTabId === null) return;
  const port = chrome.runtime.connect({ name: POPUP_PORT_NAME });
  port.onMessage.addListener((msg) => {
    if (isStateResponse(msg) && msg.state?.tabId === currentTabId) {
      renderState(msg.state);
      return;
    }
    if (!isTabStateUpdate(msg)) return;
    if (msg.state.tabId === currentTabId) {
      renderState(msg.state);
    }
  });
  port.postMessage({ type: "REQUEST_STATE", tabId: currentTabId });
  port.onDisconnect.addListener(() => {
  });
}
function renderState(state) {
  currentState = state;
  clearStateMessage();
  setBadgeState("graded", state.grade, `Security grade ${state.grade}, score ${state.score} of 100`);
  scoreText.textContent = `Score: ${state.score}/100`;
  qualityScoreText.textContent = `Configuration quality: ${state.qualityScore ?? 100}/100 (${state.qualityGrade ?? "A"})`;
  originText.textContent = state.origin;
  void renderTrend(state.origin, state.score, state.grade);
  renderSpecialNotices(state);
  stopMonitoringBtn.hidden = false;
  renderCoverage(state.coverage, state.hops);
  if (state.findings.length > 0) {
    renderFindings(state.findings);
    findingsSection.hidden = false;
  } else {
    findingsSection.hidden = true;
  }
  renderBreakdown(state.scoreBreakdown);
  renderSubdomainTrust(state.subdomainTrust);
  exportBtn.hidden = false;
  copyReportBtn.hidden = false;
  monitorSection.hidden = true;
}
function renderCoverage(coverage, hops) {
  const warnings = [
    `Coverage: ${coverage.hopsCaptured}/${coverage.hopsExpected} response${coverage.hopsExpected === 1 ? "" : "s"}`,
    `Service worker: ${formatServiceWorkerStatus(coverage)}`
  ];
  if (coverage.isRestricted) warnings.push("Restricted page");
  if (coverage.hasCache) warnings.push("⚠ Response from cache — headers may be stale");
  if (coverage.metaCspFound) warnings.push("Meta CSP detected — policy contents not evaluated");
  const headersDiffer = hops.some((h) => h.headersDiffer);
  if (headersDiffer) warnings.push("⚠ Headers differ between capture points; source cannot be attributed");
  coverageBar.textContent = warnings.join(" | ");
  coverageBar.hidden = false;
}
function formatServiceWorkerStatus(coverage) {
  if (coverage.serviceWorkerStatus === "controlled") return "controlled";
  if (coverage.serviceWorkerStatus === "not-controlled") return "not detected";
  return "not verified";
}
function renderFindings(findings) {
  while (findingsList.firstChild) {
    findingsList.removeChild(findingsList.firstChild);
  }
  const sorted = [...findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );
  const top5 = sorted.slice(0, 5);
  for (const finding of top5) {
    findingsList.appendChild(buildFindingItem(finding));
  }
}
function buildFindingItem(finding) {
  const li = document.createElement("li");
  li.className = `finding-item severity-${finding.severity}`;
  const severitySpan = document.createElement("span");
  severitySpan.className = "finding-severity";
  severitySpan.textContent = finding.severity;
  const body = document.createElement("div");
  body.className = "finding-body";
  const titleSpan = document.createElement("span");
  titleSpan.className = "finding-title";
  titleSpan.textContent = finding.title;
  titleSpan.title = finding.title;
  const evidenceSpan = document.createElement("span");
  evidenceSpan.className = "finding-evidence";
  evidenceSpan.textContent = finding.evidence;
  evidenceSpan.title = finding.evidence;
  const referenceLink = document.createElement("a");
  referenceLink.className = "finding-reference";
  referenceLink.href = finding.reference;
  referenceLink.target = "_blank";
  referenceLink.rel = "noopener noreferrer";
  referenceLink.textContent = "Learn more →";
  body.appendChild(titleSpan);
  body.appendChild(evidenceSpan);
  if (finding.impact != null && finding.impact.length > 0) {
    const impactSpan = document.createElement("span");
    impactSpan.className = "finding-impact";
    impactSpan.textContent = `⚡ Impact: ${finding.impact}`;
    body.appendChild(impactSpan);
  }
  if (finding.sourceUrl != null) {
    const sourceLink = document.createElement("a");
    sourceLink.className = "finding-source";
    sourceLink.href = finding.sourceUrl;
    sourceLink.target = "_blank";
    sourceLink.rel = "noopener noreferrer";
    sourceLink.textContent = `Found on ${formatSourceHost(finding.sourceUrl)}`;
    sourceLink.title = finding.sourceUrl;
    body.appendChild(sourceLink);
  }
  body.appendChild(referenceLink);
  li.appendChild(severitySpan);
  li.appendChild(body);
  return li;
}
function renderBreakdown(breakdown) {
  while (breakdownBody.firstChild) {
    breakdownBody.removeChild(breakdownBody.firstChild);
  }
  const scoring = breakdown.filter((b) => b.penalty > 0);
  if (scoring.length === 0) {
    breakdownSection.hidden = true;
    return;
  }
  for (const item of scoring) {
    const tr = document.createElement("tr");
    const tdRule = document.createElement("td");
    tdRule.className = "col-rule";
    tdRule.textContent = item.ruleId;
    const tdTitle = document.createElement("td");
    tdTitle.className = "col-title";
    tdTitle.textContent = item.title;
    const tdPts = document.createElement("td");
    tdPts.className = "col-pts";
    tdPts.textContent = `−${item.penalty}`;
    tr.appendChild(tdRule);
    tr.appendChild(tdTitle);
    tr.appendChild(tdPts);
    breakdownBody.appendChild(tr);
  }
  breakdownSection.hidden = false;
}
function renderSubdomainTrust(trust) {
  if (!trust || trust.vectors.length === 0) {
    subdomainSection.hidden = true;
    return;
  }
  while (vectorList.firstChild) {
    vectorList.removeChild(vectorList.firstChild);
  }
  subdomainBadge.textContent = trust.hasEscalationPath ? "⚠ Escalation path found" : "✔ No escalation path";
  subdomainBadge.className = `subdomain-badge ${trust.hasEscalationPath ? "has-path" : "no-path"}`;
  renderTrustGraph(trust.vectors);
  for (const vector of trust.vectors) {
    vectorList.appendChild(buildVectorItem(vector));
  }
  subdomainSection.hidden = false;
}
function renderTrustGraph(vectors) {
  const svgNamespace = "http://www.w3.org/2000/svg";
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
    { x: 44, y: 150 }
  ];
  const graphLabel = vectors.map((vector) => {
    const status = vector.present === true ? "risk detected" : vector.present === false ? "protected" : "not applicable";
    return `${vector.id}: ${status}`;
  }).join(". ");
  const graphTitle = document.createElementNS(svgNamespace, "title");
  graphTitle.id = "trust-graph-title";
  graphTitle.textContent = "Subdomain trust graph";
  const graphDescription = document.createElementNS(svgNamespace, "desc");
  graphDescription.id = "trust-graph-description";
  graphDescription.textContent = `Spokes connect the analyzed page to each subdomain trust vector. ${graphLabel}`;
  trustGraph.replaceChildren(graphTitle, graphDescription);
  trustGraph.setAttribute("aria-labelledby", "trust-graph-title trust-graph-description");
  vectors.forEach((vector, index) => {
    const position = positions[index % positions.length];
    if (!position) return;
    const state = String(vector.present);
    const edgeGroup = document.createElementNS(svgNamespace, "g");
    const edgeTitle = document.createElementNS(svgNamespace, "title");
    edgeTitle.id = `trust-edge-title-${vector.id}`;
    edgeTitle.textContent = `${vector.id} link to analyzed page`;
    const edgeDescription = document.createElementNS(svgNamespace, "desc");
    edgeDescription.id = `trust-edge-description-${vector.id}`;
    edgeDescription.textContent = `Trust bridge status: ${graphLabelForVector(vector)}. Risk level: ${vector.risk}.`;
    edgeGroup.setAttribute("role", "img");
    edgeGroup.setAttribute("aria-labelledby", `${edgeTitle.id} ${edgeDescription.id}`);
    edgeGroup.append(edgeTitle, edgeDescription);
    const edge = document.createElementNS(svgNamespace, "line");
    edge.setAttribute("x1", String(centerX));
    edge.setAttribute("y1", String(centerY));
    edge.setAttribute("x2", String(position.x));
    edge.setAttribute("y2", String(position.y));
    edge.setAttribute("class", `trust-edge present-${state}`);
    edge.setAttribute("aria-hidden", "true");
    edgeGroup.appendChild(edge);
    trustGraph.appendChild(edgeGroup);
    const node = document.createElementNS(svgNamespace, "g");
    node.setAttribute("class", `trust-node present-${state} risk-${vector.risk}`);
    node.setAttribute("role", "img");
    const nodeTitle = document.createElementNS(svgNamespace, "title");
    nodeTitle.id = `trust-node-title-${vector.id}`;
    nodeTitle.textContent = `${vector.id}: ${vector.label}`;
    const nodeDescription = document.createElementNS(svgNamespace, "desc");
    nodeDescription.id = `trust-node-description-${vector.id}`;
    nodeDescription.textContent = `${graphLabelForVector(vector)}. ${vector.detail}`;
    node.setAttribute("aria-labelledby", `${nodeTitle.id} ${nodeDescription.id}`);
    node.append(nodeTitle, nodeDescription);
    const circle = document.createElementNS(svgNamespace, "circle");
    circle.setAttribute("cx", String(position.x));
    circle.setAttribute("cy", String(position.y));
    circle.setAttribute("r", "15");
    circle.setAttribute("class", "trust-node-circle");
    circle.setAttribute("aria-hidden", "true");
    node.appendChild(circle);
    const label = document.createElementNS(svgNamespace, "text");
    label.setAttribute("x", String(position.x));
    label.setAttribute("y", String(position.y + 3));
    label.textContent = vector.id.slice(-3);
    label.setAttribute("aria-hidden", "true");
    node.appendChild(label);
    trustGraph.appendChild(node);
  });
  const center = document.createElementNS(svgNamespace, "g");
  center.setAttribute("class", "trust-center");
  center.setAttribute("role", "img");
  center.setAttribute("aria-labelledby", "trust-center-title trust-center-description");
  const centerTitle = document.createElementNS(svgNamespace, "title");
  centerTitle.id = "trust-center-title";
  centerTitle.textContent = "Analyzed page";
  const centerDescription = document.createElementNS(svgNamespace, "desc");
  centerDescription.id = "trust-center-description";
  centerDescription.textContent = "Central page node for the subdomain trust bridge graph.";
  center.append(centerTitle, centerDescription);
  const centerCircle = document.createElementNS(svgNamespace, "circle");
  centerCircle.setAttribute("cx", String(centerX));
  centerCircle.setAttribute("cy", String(centerY));
  centerCircle.setAttribute("r", "28");
  centerCircle.setAttribute("aria-hidden", "true");
  center.appendChild(centerCircle);
  const centerLabel = document.createElementNS(svgNamespace, "text");
  centerLabel.setAttribute("x", String(centerX));
  centerLabel.setAttribute("y", String(centerY + 4));
  centerLabel.textContent = "PAGE";
  centerLabel.setAttribute("aria-hidden", "true");
  center.appendChild(centerLabel);
  trustGraph.appendChild(center);
}
function graphLabelForVector(vector) {
  if (vector.present === true) return "risk detected";
  if (vector.present === false) return "protected";
  return "not applicable";
}
function buildVectorItem(vector) {
  const li = document.createElement("li");
  li.className = `vector-item risk-${vector.risk}`;
  const dot = document.createElement("span");
  dot.className = `vector-dot present-${String(vector.present)}`;
  const body = document.createElement("div");
  body.className = "vector-body";
  const label = document.createElement("span");
  label.className = "vector-label";
  label.textContent = vector.label;
  const detail = document.createElement("span");
  detail.className = "vector-detail";
  detail.textContent = vector.detail;
  detail.title = vector.detail;
  body.appendChild(label);
  body.appendChild(detail);
  const idSpan = document.createElement("span");
  idSpan.className = "vector-id";
  idSpan.textContent = vector.id;
  li.appendChild(dot);
  li.appendChild(body);
  li.appendChild(idSpan);
  return li;
}
function wireStopMonitoringButton() {
  stopMonitoringBtn.addEventListener("click", () => {
    if (!currentOrigin) return;
    chrome.permissions.remove(
      { origins: [`${currentOrigin}/*`] },
      (removed) => {
        if (removed) {
          void sendToBackground({
            type: "PERMISSIONS_CHANGED",
            granted: false,
            origins: [`${currentOrigin}/*`]
          }).catch(() => void 0);
          stopMonitoringBtn.hidden = true;
          exportBtn.hidden = true;
          copyReportBtn.hidden = true;
          trendIndicator.hidden = true;
          specialNotice.hidden = true;
          breakdownSection.hidden = true;
          findingsSection.hidden = true;
          subdomainSection.hidden = true;
          setBadgeState("locked", void 0, "Site access locked");
          scoreText.textContent = "";
          qualityScoreText.textContent = "";
          currentState = null;
          showMonitorSection();
          clearStateMessage();
        }
      }
    );
  });
}
function wireExportButton() {
  exportBtn.addEventListener("click", () => {
    if (currentState === null) return;
    const exportData = {
      exportedAt: (/* @__PURE__ */ new Date()).toISOString(),
      origin: currentState.origin,
      url: currentState.url,
      grade: currentState.grade,
      score: currentState.score,
      qualityScore: currentState.qualityScore ?? 100,
      qualityGrade: currentState.qualityGrade ?? "A",
      scoreVersion: currentState.scoreVersion,
      findings: currentState.findings,
      scoreBreakdown: currentState.scoreBreakdown,
      cookies: currentState.cookies,
      // metadata only — no values
      coverage: currentState.coverage,
      subdomainTrust: currentState.subdomainTrust
      // E: include escalation analysis
    };
    const json = JSON.stringify(exportData, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    let hostname = "unknown";
    try {
      hostname = new URL(currentState.origin).hostname;
    } catch {
    }
    const date = (/* @__PURE__ */ new Date()).toISOString().slice(0, 10);
    const filename = `seccheck-${hostname}-${date}.json`;
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });
}
function generateMarkdownReport(state) {
  const date = (/* @__PURE__ */ new Date()).toLocaleString();
  let md = `# Security Audit Report — ${state.origin}

`;
  md += `**Date:** ${date}  
`;
  md += `**Target URL:** ${state.url}  
`;
  md += `**Overall Security Grade:** **${state.grade}** (${state.score} / 100)  

`;
  md += `**Configuration Quality:** ${state.qualityGrade ?? "A"} (${state.qualityScore ?? 100} / 100)  

`;
  md += `## Executive Summary
`;
  md += `SecCheck conducted an automated, passive inspection of HTTP response headers and cookies for \`${state.origin}\`.

`;
  if (state.subdomainTrust.hasEscalationPath) {
    md += `> ⚠️ **Subdomain Escalation Path Detected:** Trust bridges exist between this site and its subdomains that could allow a compromised subdomain to compromise main-domain sessions or data.

`;
  }
  md += `## Key Findings (${state.findings.length} total)

`;
  if (state.findings.length === 0) {
    md += `No security weaknesses detected. All standard headers and cookie protections are configured properly.

`;
  } else {
    for (const f of state.findings) {
      md += `### [${f.severity.toUpperCase()}] ${f.title}
`;
      md += `- **Rule ID:** \`${f.ruleId}\`
`;
      if (f.impact != null && f.impact.length > 0) md += `- **Real-World Impact:** ${f.impact}
`;
      if (f.evidence.length > 0) md += `- **Evidence:** \`${f.evidence}\`
`;
      md += `- **Recommendation:** ${f.recommendation}
`;
      md += `- **Reference:** ${f.reference}

`;
    }
  }
  if (state.subdomainTrust.vectors.length > 0) {
    md += `## Subdomain Trust Analysis

`;
    md += `| Vector ID | Assessment | Detail |
`;
    md += `|---|---|---|
`;
    for (const v of state.subdomainTrust.vectors) {
      const status = v.present === true ? "⚠️ Risk confirmed" : v.present === false ? "✅ Protected" : "ℹ️ N/A";
      md += `| \`${v.id}\` | ${status} | ${v.detail} |
`;
    }
    md += `
`;
  }
  md += `---
*Generated locally by SecCheck Security Extension*
`;
  return md;
}
function wireCopyReportButton() {
  copyReportBtn.addEventListener("click", () => {
    if (currentState === null) return;
    const report = generateMarkdownReport(currentState);
    void navigator.clipboard.writeText(report).then(() => {
      const original = copyReportBtn.textContent;
      copyReportBtn.textContent = "✔ Copied!";
      setTimeout(() => {
        copyReportBtn.textContent = original;
      }, 2e3);
    }).catch(() => {
      copyReportBtn.textContent = "Failed to copy";
    });
  });
}
async function initOnboarding() {
  try {
    const dismissed = await LocalStorage.isOnboardingDismissed();
    if (!dismissed) {
      onboardingCard.hidden = false;
    }
  } catch {
  }
  const dismiss = async () => {
    onboardingCard.hidden = true;
    try {
      await LocalStorage.setOnboardingDismissed(true);
    } catch {
    }
  };
  onboardingCloseBtn.addEventListener("click", () => {
    void dismiss();
  });
  onboardingActionBtn.addEventListener("click", () => {
    void dismiss();
  });
}
async function renderTrend(origin, currentScore, currentGrade) {
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
          const x = 4 + index / (points.length - 1) * 88;
          const y = maxScore === minScore ? 14 : 24 - (point.score - minScore) / (maxScore - minScore) * 20;
          return `${x},${y}`;
        });
        const line = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
        line.setAttribute("points", coordinates.join(" "));
        line.setAttribute("fill", "none");
        line.setAttribute("stroke", "currentColor");
        line.setAttribute("stroke-width", "2");
        trendChart.replaceChildren(line);
        trendChart.setAttribute("aria-label", `Score trend: ${points.map((point) => point.score).join(", ")}`);
        trendChart.removeAttribute("hidden");
      }
      const prev = history[history.length - 2];
      if (prev != null) {
        const diff = currentScore - prev.score;
        if (diff > 0) {
          trendText.textContent = `↗ +${diff} pts (was ${prev.grade}/${prev.score})`;
          trendIndicator.className = "trend-indicator trend-improved";
        } else if (diff < 0) {
          trendText.textContent = `↘ ${diff} pts (was ${prev.grade}/${prev.score})`;
          trendIndicator.className = "trend-indicator trend-regressed";
        } else {
          trendText.textContent = `• Stable ${currentGrade} (${currentScore})`;
          trendIndicator.className = "trend-indicator trend-stable";
        }
        trendIndicator.hidden = false;
        return;
      }
    }
  } catch {
  }
  trendChart.setAttribute("hidden", "");
  trendIndicator.hidden = true;
}
function renderSpecialNotices(state) {
  let isLocalhost = false;
  try {
    const hostname = new URL(state.origin).hostname;
    isLocalhost = hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
  } catch {
  }
  if (isLocalhost) {
    specialNotice.textContent = "🔧 Localhost Development: Public domain cookie rules and strict HSTS requirements are relaxed for local development servers.";
    specialNotice.className = "special-notice notice-warning";
    specialNotice.hidden = false;
    return;
  }
  if (state.url.startsWith("http://")) {
    specialNotice.textContent = "⚠️ Plain HTTP: Connection is unencrypted — network traffic and cookies can be intercepted.";
    specialNotice.className = "special-notice notice-warning";
    specialNotice.hidden = false;
    return;
  }
  if (state.cookies.length === 0) {
    specialNotice.textContent = "🌱 Clean Cookie Footprint: Zero cookies set on this page.";
    specialNotice.className = "special-notice notice-success";
    specialNotice.hidden = false;
    return;
  }
  specialNotice.hidden = true;
}
function showStateMessage(msg, mode = "waiting") {
  if (mode === "loading" || mode === "waiting") {
    setBadgeState("scanning", void 0, "Checking this page");
  } else if (mode === "permission" || mode === "restricted" || mode === "error") {
    setBadgeState("locked", void 0, mode === "permission" ? "Site access locked" : "Page not available for analysis");
  }
  stateMessage.textContent = msg;
  stateMessage.className = `state-message state-${mode}`;
}
function setBadgeState(state, grade, label) {
  gradeBadge.dataset["state"] = state;
  if (grade === void 0) {
    gradeBadge.removeAttribute("data-grade");
    badgeGrade.textContent = "?";
  } else {
    gradeBadge.dataset["grade"] = grade;
    badgeGrade.textContent = grade;
  }
  gradeBadge.setAttribute("aria-label", label);
}
function clearStateMessage() {
  stateMessage.textContent = "";
  stateMessage.className = "state-message";
}
function showMonitorSection() {
  monitorSection.hidden = false;
  findingsSection.hidden = true;
}
function wireSettingsLink() {
  settingsLink.addEventListener("click", (e) => {
    e.preventDefault();
    void chrome.runtime.openOptionsPage();
  });
}
function wireMonitorButton() {
  monitorBtn.addEventListener("click", () => {
    if (!currentOrigin) return;
    chrome.permissions.request(
      { origins: [`${currentOrigin}/*`] },
      (granted) => {
        if (granted) {
          monitorSection.hidden = true;
          showStateMessage("Waiting for the first response on this page…", "waiting");
          if (currentTabId !== null) {
            void chrome.scripting.executeScript({
              target: { tabId: currentTabId },
              func: reportPageSignals
            }).catch(() => void 0);
            void sendToBackground({
              type: "PERMISSIONS_CHANGED",
              granted: true,
              origins: [`${currentOrigin}/*`]
            }).catch(() => void 0);
          }
          openLivePort();
        }
      }
    );
  });
}
function getEl(id) {
  const el = document.querySelector(`#${CSS.escape(id)}`);
  if (!el) throw new Error(`Missing required element #${id}`);
  return el;
}
function isRestrictedUrl(url) {
  const RESTRICTED_PREFIXES = [
    "chrome://",
    "chrome-extension://",
    "about:",
    "edge://",
    "brave://",
    "data:",
    "javascript:",
    "view-source:"
  ];
  return RESTRICTED_PREFIXES.some((prefix) => url.startsWith(prefix));
}
function checkPermission(origin) {
  return new Promise((resolve) => {
    chrome.permissions.contains({ origins: [`${origin}/*`] }, resolve);
  });
}
function formatSourceHost(sourceUrl) {
  try {
    return new URL(sourceUrl).hostname;
  } catch {
    return sourceUrl;
  }
}
function isStateResponse(msg) {
  return typeof msg === "object" && msg !== null && msg["type"] === "STATE_RESPONSE" && "state" in msg;
}
function isTabStateUpdate(msg) {
  return typeof msg === "object" && msg !== null && msg["type"] === "TAB_STATE_UPDATE" && typeof msg["state"] === "object";
}
//# sourceMappingURL=popup.html-BzPNh07U.js.map
