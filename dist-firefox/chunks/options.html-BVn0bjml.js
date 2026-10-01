import { T as SEVERITY_ORDER, r as sendToBackground } from "./messaging-cpmoITPm.js";
import { _ as normalizeCookieList, g as SettingsService, m as LocalStorage, t as PermissionsService, v as resolveCookieOverlaps } from "./permissions-BZvSKL0Y.js";
import "./modulepreload-polyfill-BsPm7yBB.js";
//#region src/options/options.ts
var ALL_SEVERITIES = [...SEVERITY_ORDER];
var modeRadios;
var severityCheckboxes;
var retainDaysInput;
var maxHistoryInput;
var alwaysSensitiveInput;
var alwaysIgnoreInput;
var allowlistEl;
var allowlistEmptyMsg;
var saveBtn;
var saveStatus;
var sectionAllowlist;
var proModeToggle;
var modeConflictBanner;
var btnRemoveBroadAccess;
var btnSwitchToAllSites;
var currentMode = "per-site";
/**
* In-memory working copy of the allowedOrigins array.
* Mutated by remove buttons; committed to storage on Save.
*/
var workingOrigins = [];
var initialSettingsSnapshot = "";
document.addEventListener("DOMContentLoaded", () => {
	modeRadios = document.querySelectorAll("input[name=\"monitoringMode\"]");
	severityCheckboxes = document.querySelectorAll("input[name=\"severity\"]");
	retainDaysInput = getEl("retain-history-days");
	maxHistoryInput = getEl("max-history-per-origin");
	alwaysSensitiveInput = getEl("always-sensitive");
	alwaysIgnoreInput = getEl("always-ignore");
	allowlistEl = getEl("allowlist");
	allowlistEmptyMsg = getEl("allowlist-empty");
	saveBtn = getEl("save-btn");
	saveStatus = getEl("save-status");
	sectionAllowlist = getEl("section-allowlist");
	proModeToggle = getEl("pro-mode-toggle");
	modeConflictBanner = getEl("mode-conflict-banner");
	btnRemoveBroadAccess = getEl("btn-remove-broad-access");
	btnSwitchToAllSites = getEl("btn-switch-to-all-sites");
	wireModeRadios();
	wireConflictBanner();
	wireSaveButton();
	wireDirtyTracking();
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
	maxHistoryInput.value = String(settings.maxHistoryPerOrigin ?? 10);
	alwaysSensitiveInput.value = (settings.sensitiveCookieNames ?? settings.alwaysSensitiveCookies ?? []).join(", ");
	alwaysIgnoreInput.value = (settings.ignoredCookieNames ?? settings.alwaysIgnoreCookies ?? []).join(", ");
	proModeToggle.checked = Boolean(settings.evaluationMode ?? settings.isPro);
	try {
		workingOrigins = await PermissionsService.getAllGrantedOrigins();
	} catch {
		workingOrigins = [...settings.legacyAllowedOrigins ?? settings.allowedOrigins ?? []];
	}
	renderAllowlist();
	await checkAndRenderBroadConflict();
	initialSettingsSnapshot = getFormStateString();
	updateDirtyState();
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
	if (settings.maxHistoryPerOrigin < 1 || settings.maxHistoryPerOrigin > 50) {
		setStatus("Max history per origin must be between 1 and 50.", true);
		return;
	}
	saveBtn.disabled = true;
	saveBtn.textContent = "Saving…";
	try {
		await SettingsService.updateSettings(settings);
		await sendToBackground({
			type: "SETTINGS_CHANGED",
			settings
		});
		initialSettingsSnapshot = getFormStateString();
		setStatus("Settings saved ✓", false);
	} catch {
		setStatus("Failed to save settings.", true);
	} finally {
		saveBtn.disabled = false;
		saveBtn.textContent = "Save settings";
	}
	setTimeout(() => {
		if (getFormStateString() === initialSettingsSnapshot) clearStatus();
	}, 3e3);
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
	const maxHistoryPerOrigin = Math.max(1, Math.min(50, parseInt(maxHistoryInput.value, 10) || 10));
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
		maxHistoryPerOrigin,
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
	const actionsDiv = document.createElement("div");
	actionsDiv.className = "allowlist-actions";
	const purgeBtn = document.createElement("button");
	purgeBtn.type = "button";
	purgeBtn.className = "btn-purge";
	purgeBtn.textContent = "Delete stored data";
	purgeBtn.title = `Delete stored audit history and graph data for ${origin}`;
	purgeBtn.addEventListener("click", () => {
		purgeOrigin(origin);
	});
	const removeBtn = document.createElement("button");
	removeBtn.type = "button";
	removeBtn.className = "btn-remove";
	removeBtn.textContent = "Remove";
	removeBtn.title = `Revoke browser host permission for ${origin}`;
	removeBtn.addEventListener("click", () => {
		removeOrigin(origin);
	});
	actionsDiv.appendChild(purgeBtn);
	actionsDiv.appendChild(removeBtn);
	li.appendChild(originSpan);
	li.appendChild(actionsDiv);
	return li;
}
/** Purge stored data for an origin without revoking permissions */
async function purgeOrigin(origin) {
	try {
		await LocalStorage.purgeOriginData(origin);
		setStatus(`Deleted stored data for ${origin}`, false);
	} catch {
		setStatus(`Failed to delete stored data for ${origin}`, true);
	}
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
					checkAndRenderBroadConflict();
					setStatus("All-sites monitoring requires permission for all URLs. Kept previous mode.", true);
				} else {
					currentMode = "all-sites";
					updateAllowlistVisibility("all-sites");
					checkAndRenderBroadConflict();
				}
			});
			else {
				currentMode = "all-sites";
				updateAllowlistVisibility("all-sites");
				checkAndRenderBroadConflict();
			}
		} else {
			currentMode = targetMode;
			updateAllowlistVisibility(targetMode);
			checkAndRenderBroadConflict();
		}
	});
}
async function checkAndRenderBroadConflict() {
	const broadActive = await PermissionsService.isBroadGrantPresent();
	if (currentMode === "per-site" && broadActive) modeConflictBanner.removeAttribute("hidden");
	else modeConflictBanner.setAttribute("hidden", "");
}
function wireConflictBanner() {
	btnRemoveBroadAccess.addEventListener("click", () => {
		btnRemoveBroadAccess.disabled = true;
		PermissionsService.removeAllBroadGrants().then(async (success) => {
			btnRemoveBroadAccess.disabled = false;
			await checkAndRenderBroadConflict();
			if (success) setStatus("Broad access removed", false);
			else setStatus("Failed to remove broad access or broad grants still remain in browser", true);
		});
	});
	btnSwitchToAllSites.addEventListener("click", () => {
		currentMode = "all-sites";
		for (const r of modeRadios) r.checked = r.value === "all-sites";
		updateAllowlistVisibility("all-sites");
		modeConflictBanner.setAttribute("hidden", "");
		handleSave();
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
function getFormStateString() {
	const current = readFormValues();
	return JSON.stringify({
		monitoringMode: current.monitoringMode,
		severityFilter: [...current.severityFilter].sort(),
		retainHistoryDays: current.retainHistoryDays,
		maxHistoryPerOrigin: current.maxHistoryPerOrigin,
		sensitiveCookieNames: [...current.sensitiveCookieNames].sort(),
		ignoredCookieNames: [...current.ignoredCookieNames].sort(),
		evaluationMode: current.evaluationMode
	});
}
function updateDirtyState() {
	if (!initialSettingsSnapshot) return;
	if (getFormStateString() !== initialSettingsSnapshot) setStatus("Unsaved changes", false, true);
	else if (saveStatus.classList.contains("dirty")) clearStatus();
}
function wireDirtyTracking() {
	for (const radio of modeRadios) radio.addEventListener("change", updateDirtyState);
	for (const cb of severityCheckboxes) cb.addEventListener("change", updateDirtyState);
	retainDaysInput.addEventListener("input", updateDirtyState);
	maxHistoryInput.addEventListener("input", updateDirtyState);
	alwaysSensitiveInput.addEventListener("input", updateDirtyState);
	alwaysIgnoreInput.addEventListener("input", updateDirtyState);
	proModeToggle.addEventListener("change", updateDirtyState);
}
function setStatus(msg, isError, isDirty = false) {
	saveStatus.textContent = msg;
	saveStatus.className = "save-status";
	if (isError) saveStatus.classList.add("error");
	else if (isDirty) saveStatus.classList.add("dirty");
}
function clearStatus() {
	saveStatus.textContent = "";
	saveStatus.className = "save-status";
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
			checkAndRenderBroadConflict();
		});
	});
	if (typeof chrome.permissions.onAdded !== "undefined") chrome.permissions.onAdded.addListener(() => {
		PermissionsService.getAllGrantedOrigins().then((origins) => {
			workingOrigins = origins;
			renderAllowlist();
			checkAndRenderBroadConflict();
		});
	});
}
//#endregion

//# sourceMappingURL=options.html-BVn0bjml.js.map