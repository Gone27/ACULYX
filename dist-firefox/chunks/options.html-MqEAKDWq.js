import { f as SEVERITY_ORDER, r as sendToBackground } from "./messaging-BCRf7spF.js";
import { a as resolveCookieOverlaps, i as normalizeCookieList, r as SettingsService } from "./storage-DkrZ3D78.js";
import { t as PermissionsService } from "./permissions-C601rqBC.js";
import "./modulepreload-polyfill-BsPm7yBB.js";
//#region src/options/options.ts
var ALL_SEVERITIES = [...SEVERITY_ORDER];
var modeRadios;
var severityCheckboxes;
var retainDaysInput;
var alwaysSensitiveInput;
var alwaysIgnoreInput;
var allowlistEl;
var allowlistEmptyMsg;
var saveBtn;
var saveStatus;
var sectionAllowlist;
var proModeToggle;
var currentMode = "per-site";
/**
* In-memory working copy of the allowedOrigins array.
* Mutated by remove buttons; committed to storage on Save.
*/
var workingOrigins = [];
document.addEventListener("DOMContentLoaded", () => {
	modeRadios = document.querySelectorAll("input[name=\"monitoringMode\"]");
	severityCheckboxes = document.querySelectorAll("input[name=\"severity\"]");
	retainDaysInput = getEl("retain-history-days");
	alwaysSensitiveInput = getEl("always-sensitive");
	alwaysIgnoreInput = getEl("always-ignore");
	allowlistEl = getEl("allowlist");
	allowlistEmptyMsg = getEl("allowlist-empty");
	saveBtn = getEl("save-btn");
	saveStatus = getEl("save-status");
	sectionAllowlist = getEl("section-allowlist");
	proModeToggle = getEl("pro-mode-toggle");
	wireModeRadios();
	wireSaveButton();
	loadAndPopulate();
});
async function loadAndPopulate() {
	let settings;
	try {
		settings = await SettingsService.getSettings();
	} catch {
		setStatus("Failed to load settings.", true);
		return;
	}
	currentMode = settings.monitoringMode;
	for (const radio of modeRadios) radio.checked = radio.value === settings.monitoringMode;
	updateAllowlistVisibility(settings.monitoringMode);
	const filterSet = new Set(settings.severityFilter);
	for (const cb of severityCheckboxes) cb.checked = filterSet.has(cb.value);
	retainDaysInput.value = String(settings.retainHistoryDays);
	alwaysSensitiveInput.value = (settings.sensitiveCookieNames ?? settings.alwaysSensitiveCookies ?? []).join(", ");
	alwaysIgnoreInput.value = (settings.ignoredCookieNames ?? settings.alwaysIgnoreCookies ?? []).join(", ");
	proModeToggle.checked = Boolean(settings.evaluationMode ?? settings.isPro);
	try {
		workingOrigins = await PermissionsService.getAllGrantedOrigins();
	} catch {
		workingOrigins = [...settings.legacyAllowedOrigins ?? settings.allowedOrigins ?? []];
	}
	renderAllowlist();
}
function wireSaveButton() {
	saveBtn.addEventListener("click", () => {
		handleSave();
	});
}
async function handleSave() {
	clearStatus();
	const settings = readFormValues();
	if (settings.retainHistoryDays < 0 || settings.retainHistoryDays > 365) {
		setStatus("Retain days must be between 0 and 365.", true);
		return;
	}
	try {
		await SettingsService.updateSettings(settings);
		await sendToBackground({
			type: "SETTINGS_CHANGED",
			settings
		});
		setStatus("Settings saved ✓", false);
	} catch {
		setStatus("Failed to save settings.", true);
		return;
	}
	setTimeout(() => clearStatus(), 3e3);
}
function readFormValues() {
	let monitoringMode = "per-site";
	for (const radio of modeRadios) if (radio.checked) {
		const val = radio.value;
		if (val === "per-site" || val === "all-sites" || val === "off") monitoringMode = val;
		break;
	}
	const severityFilter = [];
	for (const cb of severityCheckboxes) if (cb.checked) {
		const val = cb.value;
		if (ALL_SEVERITIES.includes(val)) severityFilter.push(val);
	}
	const retainHistoryDays = Math.max(0, Math.min(365, parseInt(retainDaysInput.value, 10) || 0));
	const rawSensitive = alwaysSensitiveInput.value.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
	const rawIgnored = alwaysIgnoreInput.value.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
	const { sensitive, ignored, overlaps } = resolveCookieOverlaps(normalizeCookieList(rawSensitive), normalizeCookieList(rawIgnored));
	if (overlaps.length > 0) setStatus(`Notice: Cookie names in both lists are treated as ignored: ${overlaps.join(", ")}`, false);
	return {
		schemaVersion: 2,
		monitoringMode,
		allowedOrigins: [...workingOrigins],
		severityFilter,
		retainHistoryDays,
		maxHistoryPerOrigin: 10,
		sensitiveCookieNames: sensitive,
		ignoredCookieNames: ignored,
		evaluationMode: proModeToggle.checked,
		alwaysSensitiveCookies: sensitive,
		alwaysIgnoreCookies: ignored,
		isPro: proModeToggle.checked
	};
}
/**
* Rebuild the allowlist <ul> from workingOrigins.
* Clears all child nodes first, then appends fresh <li> elements.
*/
function renderAllowlist() {
	while (allowlistEl.firstChild) allowlistEl.removeChild(allowlistEl.firstChild);
	if (workingOrigins.length === 0) {
		allowlistEmptyMsg.hidden = false;
		return;
	}
	allowlistEmptyMsg.hidden = true;
	for (const origin of workingOrigins) allowlistEl.appendChild(buildAllowlistItem(origin));
}
/**
* Build a single allowlist <li> row:
*   <li class="allowlist-item">
*     <span class="allowlist-origin">{origin}</span>
*     <button class="btn-remove">Remove</button>
*   </li>
*/
function buildAllowlistItem(origin) {
	const li = document.createElement("li");
	li.className = "allowlist-item";
	const originSpan = document.createElement("span");
	originSpan.className = "allowlist-origin";
	originSpan.textContent = origin;
	originSpan.title = origin;
	const removeBtn = document.createElement("button");
	removeBtn.type = "button";
	removeBtn.className = "btn-remove";
	removeBtn.textContent = "Remove";
	removeBtn.addEventListener("click", () => {
		removeOrigin(origin);
	});
	li.appendChild(originSpan);
	li.appendChild(removeBtn);
	return li;
}
/** Remove an origin from browser permissions and re-render the list. */
function removeOrigin(origin) {
	(async () => {
		try {
			if (await PermissionsService.removeOriginPermission(origin)) {
				workingOrigins = workingOrigins.filter((o) => o !== origin);
				renderAllowlist();
				setStatus(`Revoked access for ${origin}`, false);
			} else setStatus(`Failed to revoke access for ${origin}`, true);
		} catch {
			workingOrigins = workingOrigins.filter((o) => o !== origin);
			renderAllowlist();
		}
	})();
}
function wireModeRadios() {
	for (const radio of modeRadios) radio.addEventListener("change", () => {
		if (!radio.checked) return;
		const targetMode = radio.value;
		if (targetMode === "all-sites" && currentMode !== "all-sites") {
			if (typeof chrome !== "undefined" && typeof chrome.permissions !== "undefined") chrome.permissions.request({ origins: ["<all_urls>"] }, (granted) => {
				if (!granted) {
					for (const r of modeRadios) r.checked = r.value === currentMode;
					updateAllowlistVisibility(currentMode);
					setStatus("All-sites monitoring requires permission for all URLs. Kept previous mode.", true);
				} else {
					currentMode = "all-sites";
					updateAllowlistVisibility("all-sites");
				}
			});
			else {
				currentMode = "all-sites";
				updateAllowlistVisibility("all-sites");
			}
		} else {
			currentMode = targetMode;
			updateAllowlistVisibility(targetMode);
		}
	});
}
/**
* The allowlist section is only relevant when mode is 'per-site'.
* We toggle aria-hidden and the CSS hidden attribute together.
*/
function updateAllowlistVisibility(mode) {
	if (mode === "per-site") sectionAllowlist.removeAttribute("hidden");
	else sectionAllowlist.setAttribute("hidden", "");
}
function setStatus(msg, isError) {
	saveStatus.textContent = msg;
	if (isError) saveStatus.classList.add("error");
	else saveStatus.classList.remove("error");
}
function clearStatus() {
	saveStatus.textContent = "";
	saveStatus.classList.remove("error");
}
/** Returns a typed, non-null reference to a DOM element by ID. */
function getEl(id) {
	const el = document.getElementById(id);
	if (!el) throw new Error(`Missing required element #${id}`);
	return el;
}
if (typeof chrome !== "undefined" && typeof chrome.permissions !== "undefined") {
	if (typeof chrome.permissions.onRemoved !== "undefined") chrome.permissions.onRemoved.addListener(() => {
		PermissionsService.getAllGrantedOrigins().then((origins) => {
			workingOrigins = origins;
			renderAllowlist();
		});
	});
	if (typeof chrome.permissions.onAdded !== "undefined") chrome.permissions.onAdded.addListener(() => {
		PermissionsService.getAllGrantedOrigins().then((origins) => {
			workingOrigins = origins;
			renderAllowlist();
		});
	});
}
//#endregion

//# sourceMappingURL=options.html-MqEAKDWq.js.map