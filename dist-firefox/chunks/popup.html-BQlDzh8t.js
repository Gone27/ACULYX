import { S as POPUP_PORT_NAME, T as SEVERITY_ORDER, r as sendToBackground } from "./messaging-BtJyJf3R.js";
import { b as SettingsService, f as isModeCaptureAllowed, l as patternFromOrigin, s as PermissionsService, v as LocalStorage } from "./capture-CCR6EOFJ.js";
import "./modulepreload-polyfill-BsPm7yBB.js";
/* empty css                       */
//#region src/shared/filters.ts
/**
* Pure presentation selector to filter findings by allowed severity levels.
*
* @param findings - Full list of findings computed by the rules engine
* @param severityFilter - Severities allowed for display (from user settings)
* @param showAllOverride - Whether the user has temporarily opted to show all findings
*/
function selectVisibleFindings(findings, severityFilter, showAllOverride = false) {
	if (showAllOverride || severityFilter.length === 0) return {
		visibleFindings: [...findings],
		hiddenCount: 0
	};
	const allowed = new Set(severityFilter);
	const visibleFindings = [];
	let hiddenCount = 0;
	for (const finding of findings) if (allowed.has(finding.severity)) visibleFindings.push(finding);
	else hiddenCount++;
	return {
		visibleFindings,
		hiddenCount
	};
}
//#endregion
//#region src/popup/popup.ts
var gradeBadge;
var badgeGrade;
var scoreText;
var qualityScoreText;
var originText;
var coverageBar;
var stateMessage;
var monitorSection;
var monitorBtn;
var stopMonitoringBtn;
var findingsSection;
var findingsList;
var breakdownSection;
var breakdownBody;
var exportBtn;
var copyReportBtn;
var settingsLink;
var subdomainSection;
var subdomainBadge;
var vectorList;
var trustGraph;
var apiEndpointsSection;
var apiEndpointsBadge;
var apiEndpointsList;
var onboardingCard;
var onboardingCloseBtn;
var onboardingActionBtn;
var trendIndicator;
var trendChart;
var trendText;
var specialNotice;
var authDiffSection;
var authDiffDelta;
var authDiffMeta;
var authDiffList;
var openGraphBtn;
var findingsFilterNotice;
var showAllFindingsBtn;
/** The tab ID currently being inspected by the popup. */
var currentTabId = null;
/** The normalised origin (scheme + host + port) of the active tab. */
var currentOrigin = "";
/** Last full TabState received — used by the export function. */
var currentState = null;
/** Cached settings used for presentation filtering. */
var currentSettings = null;
/** Current findings array for filtering re-renders. */
var currentFindings = [];
/** Temporary override to show all findings regardless of filter. */
var showAllFindingsOverride = false;
var currentBreakdown = [];
var breakdownRendered = false;
function setPopupState(s) {
	document.body.dataset["state"] = s;
}
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
	apiEndpointsSection = getEl("api-endpoints-section");
	apiEndpointsBadge = getEl("api-endpoints-badge");
	apiEndpointsList = getEl("api-endpoints-list");
	onboardingCard = getEl("onboarding-card");
	onboardingCloseBtn = getEl("onboarding-close-btn");
	onboardingActionBtn = getEl("onboarding-action-btn");
	trendIndicator = getEl("trend-indicator");
	trendChart = getEl("trend-chart");
	trendText = getEl("trend-text");
	specialNotice = getEl("special-notice");
	authDiffSection = getEl("auth-diff-section");
	authDiffDelta = getEl("auth-diff-delta");
	authDiffMeta = getEl("auth-diff-meta");
	authDiffList = getEl("auth-diff-list");
	openGraphBtn = getEl("open-graph-btn");
	findingsFilterNotice = getEl("findings-filter-notice");
	showAllFindingsBtn = getEl("show-all-findings-btn");
	showAllFindingsBtn.addEventListener("click", () => {
		showAllFindingsOverride = !showAllFindingsOverride;
		renderFindings(currentFindings);
	});
	breakdownSection.addEventListener("toggle", () => {
		if (breakdownSection.open && !breakdownRendered) renderBreakdown(currentBreakdown);
	});
	SettingsService.onSettingsChanged((newSettings) => {
		currentSettings = newSettings;
	});
	wireSettingsLink();
	wireMonitorButton();
	wireStopMonitoringButton();
	wireExportButton();
	wireCopyReportButton();
	wireOpenGraphButton();
	initOnboarding();
	initPopup();
});
async function initPopup() {
	showStateMessage("Loading…", "loading");
	const paramTabId = new URLSearchParams(window.location.search).get("tabId");
	let tab;
	if (paramTabId !== null && paramTabId.length > 0) {
		const id = parseInt(paramTabId, 10);
		if (!Number.isNaN(id)) try {
			tab = await chrome.tabs.get(id);
		} catch {}
	}
	if (tab === void 0) {
		let tabs;
		try {
			tabs = await chrome.tabs.query({
				active: true,
				currentWindow: true
			});
		} catch {
			showStateMessage("Unable to determine the active tab.", "error");
			return;
		}
		tab = tabs[0];
	}
	if (!tab || typeof tab.id !== "number" || tab.url == null || tab.url.length === 0) {
		showStateMessage("No active tab found.", "error");
		return;
	}
	currentTabId = tab.id;
	const settings = await SettingsService.getSettings();
	currentSettings = settings;
	const broadActive = await PermissionsService.isBroadGrantPresent();
	const gate = isModeCaptureAllowed(tab.url, settings, broadActive);
	if (!gate.allowed) {
		if (gate.reason === "off") {
			originText.textContent = tab.url;
			showStateMessage("Monitoring is turned off in Settings.");
			setPopupState("not-monitored");
			return;
		}
		if (gate.reason === "broad-access-conflict") {
			originText.textContent = tab.url;
			showBroadAccessConflictNotice();
			setPopupState("paused-conflict");
			return;
		}
		if (gate.reason === "restricted-url") {
			originText.textContent = tab.url;
			showStateMessage("Restricted page — browser pages cannot be inspected.", "restricted");
			setPopupState("restricted");
			return;
		}
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
		setPopupState("restricted");
		return;
	}
	currentOrigin = origin;
	originText.textContent = origin;
	if (!(broadActive || await checkPermission(origin))) {
		showMonitorSection();
		showStateMessage("Permission required before this site can be analysed.", "permission");
		setPopupState("permission-needed");
		return;
	}
	showStateMessage("Analysing…", "loading");
	try {
		const response = await sendToBackground({
			type: "REQUEST_STATE",
			tabId: currentTabId
		});
		if (response.type === "STATE_RESPONSE") {
			if (response.state) renderState(response.state);
			else {
				showStateMessage("Waiting for the first response on this page…", "waiting");
				setPopupState("capturing");
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
		if (msg.state.tabId === currentTabId) renderState(msg.state);
	});
	port.postMessage({
		type: "REQUEST_STATE",
		tabId: currentTabId
	});
	port.onDisconnect.addListener(() => {});
}
function renderState(state) {
	const savedScrollTop = document.documentElement.scrollTop || document.body.scrollTop;
	const savedFocusId = document.activeElement?.id;
	currentState = state;
	clearStateMessage();
	if (state.hops.length === 0) setPopupState("capturing");
	else setPopupState("results");
	setBadgeState("graded", state.grade, `Security grade ${state.grade}, score ${state.score} of 100`);
	gradeBadge.className = "grade-badge grade-" + (state.grade?.toLowerCase() ?? "unknown");
	scoreText.textContent = `Score: ${state.score}/100`;
	qualityScoreText.textContent = `Configuration quality: ${state.qualityScore ?? 100}/100 (${state.qualityGrade ?? "A"})`;
	originText.textContent = state.origin;
	renderTrend(state.origin, state.score, state.grade);
	renderSpecialNotices(state);
	stopMonitoringBtn.hidden = false;
	renderCoverage(state.coverage, state.hops);
	if (state.findings.length > 0) {
		renderFindings(state.findings);
		findingsSection.hidden = false;
	} else findingsSection.hidden = true;
	currentBreakdown = state.scoreBreakdown;
	if (currentBreakdown.filter((b) => b.penalty > 0).length === 0) breakdownSection.hidden = true;
	else {
		breakdownSection.hidden = false;
		if (breakdownSection.open) renderBreakdown(currentBreakdown);
		else {
			breakdownRendered = false;
			while (breakdownBody.firstChild) breakdownBody.removeChild(breakdownBody.firstChild);
		}
	}
	renderAuthDiff(state.origin);
	renderSubdomainTrust(state.subdomainTrust);
	renderApiEndpoints(state);
	exportBtn.hidden = false;
	copyReportBtn.hidden = false;
	monitorSection.hidden = true;
	if (savedScrollTop > 0) {
		document.documentElement.scrollTop = savedScrollTop;
		document.body.scrollTop = savedScrollTop;
	}
	if (savedFocusId !== void 0 && savedFocusId !== "") {
		const el = document.getElementById(savedFocusId);
		if (el) el.focus();
	}
}
function renderCoverage(coverage, hops) {
	const warnings = [`Coverage: ${coverage.hopsCaptured}/${coverage.hopsExpected} response${coverage.hopsExpected === 1 ? "" : "s"}`, `Service worker: ${formatServiceWorkerStatus(coverage)}`];
	if (coverage.isRestricted) warnings.push("Restricted page");
	if (coverage.hasCache) warnings.push("⚠ Response from cache — headers may be stale");
	if (coverage.metaCspFound) warnings.push("Meta CSP detected — policy contents not evaluated");
	if (hops.some((h) => h.headersDiffer)) warnings.push("⚠ Headers differ between capture points; source cannot be attributed");
	if (Array.isArray(coverage.blindSpots)) {
		for (const spot of coverage.blindSpots) if (!warnings.some((w) => w.toLowerCase().includes(spot.slice(0, 15).toLowerCase()))) warnings.push(`⚠ ${spot}`);
	}
	coverageBar.textContent = warnings.join(" | ");
	coverageBar.hidden = false;
}
function formatServiceWorkerStatus(coverage) {
	if (coverage.serviceWorkerStatus === "controlled") return "controlled";
	if (coverage.serviceWorkerStatus === "not-controlled") return "not detected";
	return "not verified";
}
function renderFindings(findings) {
	currentFindings = findings;
	while (findingsList.firstChild) findingsList.removeChild(findingsList.firstChild);
	const { visibleFindings, hiddenCount } = selectVisibleFindings(findings, currentSettings?.severityFilter ?? SEVERITY_ORDER, showAllFindingsOverride);
	if (hiddenCount > 0 && !showAllFindingsOverride) {
		findingsFilterNotice.textContent = `${hiddenCount} finding${hiddenCount === 1 ? "" : "s"} hidden by filter`;
		findingsFilterNotice.hidden = false;
		showAllFindingsBtn.textContent = "Show all";
		showAllFindingsBtn.hidden = false;
	} else if (showAllFindingsOverride && hiddenCount === 0 && findings.length > visibleFindings.length) {
		findingsFilterNotice.textContent = "Showing all findings (filter overridden)";
		findingsFilterNotice.hidden = false;
		showAllFindingsBtn.textContent = "Reset filter";
		showAllFindingsBtn.hidden = false;
	} else {
		findingsFilterNotice.textContent = "";
		findingsFilterNotice.hidden = true;
		showAllFindingsBtn.hidden = true;
	}
	const top5 = [...visibleFindings].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)).slice(0, 5);
	for (const finding of top5) findingsList.appendChild(buildFindingItem(finding));
}
function buildFindingItem(finding) {
	const li = document.createElement("li");
	li.className = `finding-item severity-${finding.severity}`;
	li.dataset["severity"] = finding.severity;
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
	if (finding.ruleId === "XFO-001" || finding.ruleId === "CSP-005") {
		const pocBtn = document.createElement("button");
		pocBtn.className = "sandbox-poc-btn";
		pocBtn.textContent = "🧪 Clickjacking PoC";
		pocBtn.title = "Generate safe client-side PoC in sandboxed tab";
		pocBtn.addEventListener("click", (e) => {
			e.stopPropagation();
			if (currentTabId !== null) sendToBackground({
				type: "GENERATE_POC",
				tabId: currentTabId,
				pocType: "clickjacking"
			});
		});
		body.appendChild(pocBtn);
	} else if (finding.ruleId === "SUB-006") {
		const pocBtn = document.createElement("button");
		pocBtn.className = "sandbox-poc-btn";
		pocBtn.textContent = "🧪 COOP PoC";
		pocBtn.title = "Generate safe client-side PoC in sandboxed tab";
		pocBtn.addEventListener("click", (e) => {
			e.stopPropagation();
			if (currentTabId !== null) sendToBackground({
				type: "GENERATE_POC",
				tabId: currentTabId,
				pocType: "coop"
			});
		});
		body.appendChild(pocBtn);
	}
	li.appendChild(severitySpan);
	li.appendChild(body);
	return li;
}
function renderBreakdown(breakdown) {
	while (breakdownBody.firstChild) breakdownBody.removeChild(breakdownBody.firstChild);
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
	breakdownRendered = true;
}
async function renderAuthDiff(origin) {
	try {
		const diff = await LocalStorage.getLatestAuthDiff(origin);
		if (diff === null) {
			authDiffSection.hidden = true;
			return;
		}
		const deltaPrefix = diff.scoreDelta > 0 ? "+" : "";
		authDiffDelta.textContent = `${deltaPrefix}${diff.scoreDelta} pts`;
		const deltaClass = diff.scoreDelta > 0 ? "positive" : diff.scoreDelta < 0 ? "negative" : "neutral";
		authDiffDelta.className = `auth-diff-delta ${deltaClass}`;
		const dateStr = new Date(diff.timestamp).toLocaleTimeString();
		authDiffMeta.textContent = `Triggered by cookie "${diff.triggeredByCookie}" at ${dateStr} • Pre: ${diff.preAuthScore} (${diff.preAuthGrade}) → Post: ${diff.postAuthScore} (${diff.postAuthGrade})`;
		while (authDiffList.firstChild) authDiffList.removeChild(authDiffList.firstChild);
		if (diff.changes.length === 0) {
			const li = document.createElement("li");
			li.className = "auth-diff-item";
			const text = document.createElement("span");
			text.className = "auth-diff-title";
			text.textContent = "No finding status changes detected between pre- and post-login.";
			li.appendChild(text);
			authDiffList.appendChild(li);
		} else for (const change of diff.changes) {
			const li = document.createElement("li");
			li.className = "auth-diff-item";
			const badge = document.createElement("span");
			badge.className = `auth-diff-badge ${change.type}`;
			badge.textContent = change.type === "added" ? "+ NEW" : "- RESOLVED";
			const rule = document.createElement("span");
			rule.className = "auth-diff-rule";
			rule.textContent = change.ruleId;
			const title = document.createElement("span");
			title.className = "auth-diff-title";
			title.textContent = change.title;
			li.appendChild(badge);
			li.appendChild(rule);
			li.appendChild(title);
			authDiffList.appendChild(li);
		}
		authDiffSection.hidden = false;
	} catch {
		authDiffSection.hidden = true;
	}
}
function renderSubdomainTrust(trust) {
	if (!trust || trust.vectors.length === 0) {
		subdomainSection.hidden = true;
		return;
	}
	while (vectorList.firstChild) vectorList.removeChild(vectorList.firstChild);
	subdomainBadge.textContent = trust.hasEscalationPath ? "⚠ Escalation path found" : "✔ No escalation path";
	subdomainBadge.className = `subdomain-badge ${trust.hasEscalationPath ? "has-path" : "no-path"}`;
	renderTrustGraph(trust.vectors);
	for (const vector of trust.vectors) vectorList.appendChild(buildVectorItem(vector));
	subdomainSection.hidden = false;
}
function renderTrustGraph(vectors) {
	const svgNamespace = "http://www.w3.org/2000/svg";
	const centerX = 160;
	const centerY = 90;
	const positions = [
		{
			x: 44,
			y: 28
		},
		{
			x: 116,
			y: 18
		},
		{
			x: 204,
			y: 18
		},
		{
			x: 276,
			y: 28
		},
		{
			x: 276,
			y: 150
		},
		{
			x: 204,
			y: 162
		},
		{
			x: 116,
			y: 162
		},
		{
			x: 44,
			y: 150
		}
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
	centerLabel.setAttribute("y", String(94));
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
function getApiEndpointsList(state) {
	const endpoints = state.apiEndpoints;
	if (endpoints === void 0 || endpoints === null) return [];
	if (endpoints instanceof Map) {
		const list = [];
		for (const val of endpoints.values()) if (val !== null && typeof val === "object" && "normalizedPath" in val) list.push(val);
		return list;
	}
	if (Array.isArray(endpoints)) {
		const list = [];
		for (const entry of endpoints) if (Array.isArray(entry) && entry.length >= 2 && entry[1] !== null && typeof entry[1] === "object") list.push(entry[1]);
		else if (entry !== null && typeof entry === "object" && "normalizedPath" in entry) list.push(entry);
		return list;
	}
	if (typeof endpoints === "object") {
		const list = [];
		for (const val of Object.values(endpoints)) if (val !== null && typeof val === "object" && "normalizedPath" in val) list.push(val);
		return list;
	}
	return [];
}
function renderApiEndpoints(state) {
	const endpoints = getApiEndpointsList(state);
	if (endpoints.length === 0) {
		apiEndpointsSection.hidden = true;
		return;
	}
	while (apiEndpointsList.firstChild) apiEndpointsList.removeChild(apiEndpointsList.firstChild);
	let totalFindings = 0;
	for (const ep of endpoints) totalFindings += ep.findings.length;
	apiEndpointsBadge.textContent = `${endpoints.length} endpoint${endpoints.length === 1 ? "" : "s"}${totalFindings > 0 ? ` (${totalFindings} finding${totalFindings === 1 ? "" : "s"})` : ""}`;
	if (totalFindings > 0) apiEndpointsBadge.classList.add("has-findings");
	else apiEndpointsBadge.classList.remove("has-findings");
	for (const ep of endpoints) {
		const card = document.createElement("li");
		card.className = "api-endpoint-card";
		const header = document.createElement("div");
		header.className = "api-endpoint-header";
		const pathSpan = document.createElement("span");
		pathSpan.className = "api-endpoint-path";
		pathSpan.textContent = ep.normalizedPath;
		pathSpan.title = ep.normalizedPath;
		const badges = document.createElement("div");
		badges.style.display = "flex";
		badges.style.gap = "4px";
		const methodBadge = document.createElement("span");
		methodBadge.className = "api-method-badge";
		methodBadge.textContent = ep.lastHop.method ?? "GET";
		const partyBadge = document.createElement("span");
		partyBadge.className = "api-party-badge";
		partyBadge.textContent = ep.isFirstParty ? "1st party" : "3rd party";
		badges.appendChild(methodBadge);
		badges.appendChild(partyBadge);
		header.appendChild(pathSpan);
		header.appendChild(badges);
		card.appendChild(header);
		if (ep.findings.length > 0) {
			const findingsContainer = document.createElement("div");
			findingsContainer.className = "api-endpoint-findings";
			for (const finding of ep.findings) {
				const pill = document.createElement("div");
				pill.className = `api-finding-pill severity-${finding.severity}`;
				const ruleSpan = document.createElement("strong");
				ruleSpan.textContent = finding.ruleId;
				const titleSpan = document.createElement("span");
				titleSpan.textContent = finding.title;
				pill.appendChild(ruleSpan);
				pill.appendChild(titleSpan);
				findingsContainer.appendChild(pill);
			}
			card.appendChild(findingsContainer);
		} else {
			const noFindings = document.createElement("div");
			noFindings.className = "api-no-findings";
			noFindings.textContent = "✔ No header or CORS issues detected";
			card.appendChild(noFindings);
		}
		apiEndpointsList.appendChild(card);
	}
	apiEndpointsSection.hidden = false;
}
function wireStopMonitoringButton() {
	stopMonitoringBtn.addEventListener("click", () => {
		if (!currentOrigin) return;
		const pattern = patternFromOrigin(currentOrigin);
		chrome.permissions.remove({ origins: [pattern] }, (removed) => {
			if (removed) {
				sendToBackground({
					type: "PERMISSIONS_CHANGED",
					granted: false,
					origins: [pattern]
				}).catch(() => void 0);
				stopMonitoringBtn.hidden = true;
				exportBtn.hidden = true;
				copyReportBtn.hidden = true;
				trendIndicator.hidden = true;
				specialNotice.hidden = true;
				breakdownSection.hidden = true;
				findingsSection.hidden = true;
				subdomainSection.hidden = true;
				apiEndpointsSection.hidden = true;
				setBadgeState("locked", void 0, "Site access locked");
				scoreText.textContent = "";
				qualityScoreText.textContent = "";
				currentState = null;
				showMonitorSection();
				clearStateMessage();
			}
		});
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
			coverage: currentState.coverage,
			subdomainTrust: currentState.subdomainTrust,
			apiEndpoints: getApiEndpointsList(currentState)
		};
		const json = JSON.stringify(exportData, null, 2);
		const blob = new Blob([json], { type: "application/json" });
		const url = URL.createObjectURL(blob);
		let hostname = "unknown";
		try {
			hostname = new URL(currentState.origin).hostname;
		} catch {}
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
	let md = `# Security Audit Report — ${state.origin}\n\n`;
	md += `**Date:** ${date}  \n`;
	md += `**Target URL:** ${state.url}  \n`;
	md += `**Overall Security Grade:** **${state.grade}** (${state.score} / 100)  \n\n`;
	md += `**Configuration Quality:** ${state.qualityGrade ?? "A"} (${state.qualityScore ?? 100} / 100)  \n\n`;
	md += `## Executive Summary\n`;
	md += `SecCheck conducted an automated, passive inspection of HTTP response headers and cookies for \`${state.origin}\`.\n\n`;
	if (state.subdomainTrust.hasEscalationPath) md += `> ⚠️ **Subdomain Escalation Path Detected:** Trust bridges exist between this site and its subdomains that could allow a compromised subdomain to compromise main-domain sessions or data.\n\n`;
	md += `## Key Findings (${state.findings.length} total)\n\n`;
	if (state.findings.length === 0) md += `No security weaknesses detected. All standard headers and cookie protections are configured properly.\n\n`;
	else for (const f of state.findings) {
		md += `### [${f.severity.toUpperCase()}] ${f.title}\n`;
		md += `- **Rule ID:** \`${f.ruleId}\`\n`;
		if (f.impact != null && f.impact.length > 0) md += `- **Real-World Impact:** ${f.impact}\n`;
		if (f.evidence.length > 0) md += `- **Evidence:** \`${f.evidence}\`\n`;
		md += `- **Recommendation:** ${f.recommendation}\n`;
		md += `- **Reference:** ${f.reference}\n\n`;
	}
	if (state.subdomainTrust.vectors.length > 0) {
		md += `## Subdomain Trust Analysis\n\n`;
		md += `| Vector ID | Assessment | Detail |\n`;
		md += `|---|---|---|\n`;
		for (const v of state.subdomainTrust.vectors) {
			const status = v.present === true ? "⚠️ Risk confirmed" : v.present === false ? "✅ Protected" : "ℹ️ N/A";
			md += `| \`${v.id}\` | ${status} | ${v.detail} |\n`;
		}
		md += `\n`;
	}
	md += `---\n*Generated locally by SecCheck Security Extension*\n`;
	return md;
}
function wireCopyReportButton() {
	copyReportBtn.addEventListener("click", () => {
		if (currentState === null) return;
		const report = generateMarkdownReport(currentState);
		navigator.clipboard.writeText(report).then(() => {
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
function openGraphInTab() {
	let apex = "";
	if (currentOrigin) try {
		apex = new URL(currentOrigin).hostname;
	} catch {}
	const tabParam = currentTabId !== null ? `&tabId=${currentTabId}` : "";
	const apexParam = apex ? `?apex=${encodeURIComponent(apex)}` : "";
	const url = chrome.runtime.getURL(`src/sidepanel/sidepanel.html${apexParam}${tabParam}`);
	chrome.tabs.create({ url });
}
function wireOpenGraphButton() {
	openGraphBtn.addEventListener("click", () => {
		if (chrome.sidePanel !== void 0 && typeof chrome.sidePanel.open === "function") {
			if (currentTabId !== null) chrome.sidePanel.open({ tabId: currentTabId }).catch(() => {
				chrome.windows.getCurrent((win) => {
					if (win.id !== void 0 && chrome.sidePanel !== void 0) chrome.sidePanel.open({ windowId: win.id }).catch(() => openGraphInTab());
					else openGraphInTab();
				});
			});
			else chrome.windows.getCurrent((win) => {
				if (win.id !== void 0 && chrome.sidePanel !== void 0) chrome.sidePanel.open({ windowId: win.id }).catch(() => openGraphInTab());
				else openGraphInTab();
			});
		} else openGraphInTab();
	});
}
async function initOnboarding() {
	try {
		if (!await LocalStorage.isOnboardingDismissed()) onboardingCard.hidden = false;
	} catch {}
	const dismiss = async () => {
		onboardingCard.hidden = true;
		try {
			await LocalStorage.setOnboardingDismissed(true);
		} catch {}
	};
	onboardingCloseBtn.addEventListener("click", () => {
		dismiss();
	});
	onboardingActionBtn.addEventListener("click", () => {
		dismiss();
	});
}
async function renderTrend(origin, currentScore, currentGrade) {
	try {
		const history = await LocalStorage.getOriginHistory(origin);
		if (history.length >= 2) {
			const points = history.slice(-8);
			const lastPoint = points[points.length - 1];
			if (!lastPoint || lastPoint.score !== currentScore || lastPoint.grade !== currentGrade) points.push({
				timestamp: Date.now(),
				score: currentScore,
				grade: currentGrade
			});
			if (points.length >= 2) {
				const minScore = Math.min(...points.map((point) => point.score));
				const maxScore = Math.max(...points.map((point) => point.score));
				const coordinates = points.map((point, index) => {
					return `${4 + index / (points.length - 1) * 88},${maxScore === minScore ? 14 : 24 - (point.score - minScore) / (maxScore - minScore) * 20}`;
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
	} catch {}
	trendChart.setAttribute("hidden", "");
	trendIndicator.hidden = true;
}
function renderSpecialNotices(state) {
	let isLocalhost = false;
	try {
		const hostname = new URL(state.origin).hostname;
		isLocalhost = hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
	} catch {}
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
	if (mode === "loading" || mode === "waiting") setBadgeState("scanning", void 0, "Checking this page");
	else if (mode === "permission" || mode === "restricted" || mode === "error") setBadgeState("locked", void 0, mode === "permission" ? "Site access locked" : "Page not available for analysis");
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
		chrome.runtime.openOptionsPage();
	});
}
function wireMonitorButton() {
	monitorBtn.addEventListener("click", () => {
		if (!currentOrigin) return;
		const pattern = patternFromOrigin(currentOrigin);
		chrome.permissions.request({ origins: [pattern] }, (granted) => {
			if (granted) {
				monitorSection.hidden = true;
				showStateMessage("Permission granted. Refreshing this page to begin monitoring…", "waiting");
				setPopupState("access-granted-reload");
				if (currentTabId !== null) {
					sendToBackground({
						type: "PERMISSIONS_CHANGED",
						granted: true,
						origins: [pattern]
					}).catch(() => void 0);
					openLivePort();
					chrome.tabs.reload(currentTabId, {}, () => {
						if (chrome.runtime.lastError != null) showStateMessage("Permission was granted, but this page could not be refreshed. Reload it to begin monitoring.", "error");
					});
				}
			} else setPopupState("permission-denied");
		});
	});
}
function getEl(id) {
	const el = document.querySelector(`#${CSS.escape(id)}`);
	if (!el) throw new Error(`Missing required element #${id}`);
	return el;
}
function showBroadAccessConflictNotice() {
	specialNotice.textContent = "";
	const p = document.createElement("p");
	p.textContent = "Broad access is active while monitoring mode is set to Per-site opt-in. Capture is paused until resolved:";
	const actions = document.createElement("div");
	actions.style.display = "flex";
	actions.style.gap = "8px";
	actions.style.marginTop = "8px";
	const removeBtn = document.createElement("button");
	removeBtn.className = "btn-secondary";
	removeBtn.textContent = "Remove broad access";
	removeBtn.addEventListener("click", () => {
		removeBtn.disabled = true;
		PermissionsService.removeAllBroadGrants().then((success) => {
			removeBtn.disabled = false;
			if (success) initPopup();
			else showStateMessage("Failed to remove broad access or broad grants still remain.", "error");
		});
	});
	const switchBtn = document.createElement("button");
	switchBtn.className = "btn-primary";
	switchBtn.textContent = "Switch to All sites";
	switchBtn.addEventListener("click", () => {
		SettingsService.updateSettings({ monitoringMode: "all-sites" }).then(() => {
			initPopup();
		});
	});
	actions.appendChild(removeBtn);
	actions.appendChild(switchBtn);
	specialNotice.appendChild(p);
	specialNotice.appendChild(actions);
	specialNotice.className = "special-notice conflict-notice";
	specialNotice.hidden = false;
	showStateMessage("Capture paused due to broad access conflict.", "waiting");
}
function checkPermission(origin) {
	const pattern = patternFromOrigin(origin);
	return new Promise((resolve) => {
		chrome.permissions.contains({ origins: [pattern] }, (result) => {
			if (result) {
				resolve(true);
				return;
			}
			const direct = `${origin}/*`;
			if (direct !== pattern) chrome.permissions.contains({ origins: [direct] }, resolve);
			else resolve(false);
		});
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
//#endregion

//# sourceMappingURL=popup.html-BQlDzh8t.js.map