import "./modulepreload-polyfill-BsPm7yBB.js";
//#region src/sandbox/poc.ts
/**
* poc.ts — Client-side verification sandbox logic
*
* Runs inside a sandboxed iframe/tab with unique origin (null / sandboxed origin).
* Strictly ethical verification tool for defensive testing.
*
* Rules:
*  - ZERO innerHTML
*  - Only safe DOM manipulation (textContent, createElement, etc.)
*/
function getEl(id) {
	const el = document.getElementById(id);
	if (!el) throw new Error(`Required element #${id} not found in DOM`);
	return el;
}
document.addEventListener("DOMContentLoaded", () => {
	const gateOverlay = getEl("gate-overlay");
	const gateCheckbox = getEl("gate-agree-checkbox");
	const gateProceedBtn = getEl("gate-proceed-btn");
	const targetUrlDisplay = getEl("target-url-display");
	const pocTypeBadge = getEl("poc-type-badge");
	const tabClickjacking = getEl("tab-clickjacking");
	const tabCoop = getEl("tab-coop");
	const sectionClickjacking = getEl("section-clickjacking");
	const sectionCoop = getEl("section-coop");
	const opacitySlider = getEl("opacity-slider");
	const opacityVal = getEl("opacity-val");
	const frameWrapper = getEl("frame-wrapper");
	const targetIframe = getEl("target-iframe");
	const frameStatusText = getEl("frame-status-text");
	const decoyBtn = getEl("decoy-btn");
	const decoyClickCounter = getEl("decoy-click-counter");
	const coopLaunchBtn = getEl("coop-launch-btn");
	const coopTestBtn = getEl("coop-test-btn");
	const coopStatusText = getEl("coop-status-text");
	const coopResults = getEl("coop-results");
	const coopChildState = getEl("coop-child-state");
	const coopCouplingState = getEl("coop-coupling-state");
	const coopVulnAssessment = getEl("coop-vuln-assessment");
	const params = new URLSearchParams(window.location.search);
	const rawTarget = params.get("target") ?? "";
	const initialType = (params.get("type") ?? "clickjacking").toLowerCase();
	let targetUrl = "";
	try {
		const parsed = new URL(rawTarget);
		if (parsed.protocol === "http:" || parsed.protocol === "https:") targetUrl = parsed.href;
	} catch {
		targetUrl = "";
	}
	if (targetUrl.length === 0) {
		targetUrlDisplay.textContent = "Invalid or missing target URL parameter";
		frameStatusText.textContent = "Error: Invalid target URL provided.";
		return;
	}
	targetUrlDisplay.textContent = targetUrl;
	let isAuthorized = false;
	try {
		isAuthorized = localStorage.getItem("seccheck_poc_authorized") === "true";
	} catch {
		isAuthorized = false;
	}
	if (!isAuthorized) {
		gateOverlay.hidden = false;
		gateCheckbox.addEventListener("change", () => {
			gateProceedBtn.disabled = !gateCheckbox.checked;
		});
		gateProceedBtn.addEventListener("click", () => {
			try {
				localStorage.setItem("seccheck_poc_authorized", "true");
			} catch {}
			gateOverlay.hidden = true;
			initializePoc();
		});
	} else {
		gateOverlay.hidden = true;
		initializePoc();
	}
	function initializePoc() {
		if (initialType === "coop") selectTab("coop");
		else selectTab("clickjacking");
		targetIframe.src = targetUrl;
		frameStatusText.textContent = "Target URL loaded in frame. If the frame remains blank or fails to load, XFO or CSP frame-ancestors is active.";
		targetIframe.addEventListener("load", () => {
			frameStatusText.textContent = "Frame load event fired. If content is visible, page is vulnerable to UI redressing (Clickjacking).";
		});
		targetIframe.addEventListener("error", () => {
			frameStatusText.textContent = "Frame loading blocked by browser security policy (X-Frame-Options or Content-Security-Policy).";
		});
	}
	function selectTab(type) {
		if (type === "clickjacking") {
			tabClickjacking.classList.add("active");
			tabCoop.classList.remove("active");
			sectionClickjacking.hidden = false;
			sectionCoop.hidden = true;
			pocTypeBadge.textContent = "Clickjacking Verification";
		} else {
			tabCoop.classList.add("active");
			tabClickjacking.classList.remove("active");
			sectionCoop.hidden = false;
			sectionClickjacking.hidden = true;
			pocTypeBadge.textContent = "COOP Verification";
		}
	}
	tabClickjacking.addEventListener("click", () => selectTab("clickjacking"));
	tabCoop.addEventListener("click", () => selectTab("coop"));
	opacitySlider.addEventListener("input", () => {
		const val = parseInt(opacitySlider.value, 10);
		const opacityFloat = val / 100;
		frameWrapper.style.opacity = opacityFloat.toString();
		opacityVal.textContent = `${val}%`;
	});
	let decoyClicks = 0;
	decoyBtn.addEventListener("click", () => {
		decoyClicks++;
		decoyClickCounter.textContent = `Clicks registered on decoy: ${decoyClicks}`;
	});
	let openedWindow = null;
	coopLaunchBtn.addEventListener("click", () => {
		try {
			openedWindow = window.open(targetUrl, "_blank");
			if (openedWindow !== null) {
				coopStatusText.textContent = "Child window opened. Click \"2. Test Opener Coupling\" to evaluate window.opener isolation.";
				coopTestBtn.disabled = false;
			} else coopStatusText.textContent = "Popup was blocked by the browser. Please allow popups for this sandboxed tool and retry.";
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			coopStatusText.textContent = `Error launching window: ${msg}`;
		}
	});
	coopTestBtn.addEventListener("click", () => {
		if (openedWindow === null) {
			coopStatusText.textContent = "No active window launched. Click Step 1 first.";
			return;
		}
		coopResults.hidden = false;
		if (openedWindow.closed) {
			coopChildState.textContent = "Closed by user";
			coopCouplingState.textContent = "N/A";
			coopVulnAssessment.textContent = "Window was closed. Re-launch to test.";
			coopVulnAssessment.className = "result-value";
			return;
		}
		coopChildState.textContent = "Active (Open)";
		try {
			if (!openedWindow.closed) {
				coopCouplingState.textContent = "Coupled (Browsing context group shared)";
				coopVulnAssessment.textContent = "VULNERABLE — Page lacks COOP: same-origin; opener context is coupled to opener.";
				coopVulnAssessment.className = "result-value vulnerable";
				coopStatusText.textContent = "Vulnerability confirmed: External opener maintains a reference to the opened target browsing context.";
			} else {
				coopCouplingState.textContent = "Decoupled (Opener severed by COOP)";
				coopVulnAssessment.textContent = "PROTECTED — COOP isolated the browsing context.";
				coopVulnAssessment.className = "result-value protected";
				coopStatusText.textContent = "Protection confirmed: Opener context decoupled.";
			}
		} catch {
			coopCouplingState.textContent = "Cross-origin restricted";
			coopVulnAssessment.textContent = "Opener coupling active across origin boundary";
			coopVulnAssessment.className = "result-value vulnerable";
		}
	});
});
//#endregion

//# sourceMappingURL=poc.html-BUCLNufp.js.map