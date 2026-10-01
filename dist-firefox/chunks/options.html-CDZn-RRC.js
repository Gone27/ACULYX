import { f as SEVERITY_ORDER, r as sendToBackground } from "./messaging-BiWicsg3.js";
import { t as LocalStorage } from "./storage-CJOthBSi.js";
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
		settings = await LocalStorage.getSettings();
	} catch {
		setStatus("Failed to load settings.", true);
		return;
	}
	for (const radio of modeRadios) radio.checked = radio.value === settings.monitoringMode;
	updateAllowlistVisibility(settings.monitoringMode);
	const filterSet = new Set(settings.severityFilter);
	for (const cb of severityCheckboxes) cb.checked = filterSet.has(cb.value);
	retainDaysInput.value = String(settings.retainHistoryDays);
	alwaysSensitiveInput.value = settings.alwaysSensitiveCookies.join(", ");
	alwaysIgnoreInput.value = settings.alwaysIgnoreCookies.join(", ");
	proModeToggle.checked = Boolean(settings.isPro);
	workingOrigins = [...settings.allowedOrigins];
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
		await LocalStorage.setSettings(settings);
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
	const alwaysSensitiveCookies = alwaysSensitiveInput.value.split(",").map((s) => s.trim()).filter(Boolean);
	const alwaysIgnoreCookies = alwaysIgnoreInput.value.split(",").map((s) => s.trim()).filter(Boolean);
	return {
		monitoringMode,
		allowedOrigins: [...workingOrigins],
		severityFilter,
		retainHistoryDays,
		alwaysSensitiveCookies,
		alwaysIgnoreCookies,
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
/** Remove an origin from the working array and re-render the list. */
function removeOrigin(origin) {
	workingOrigins = workingOrigins.filter((o) => o !== origin);
	renderAllowlist();
}
function wireModeRadios() {
	for (const radio of modeRadios) radio.addEventListener("change", () => {
		if (radio.checked) updateAllowlistVisibility(radio.value);
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
//#endregion

//# sourceMappingURL=options.html-CDZn-RRC.js.map