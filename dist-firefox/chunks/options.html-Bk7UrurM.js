import { A as DEFAULT_SETTINGS, C as resolveCookieOverlaps, I as SEVERITY_ORDER, S as normalizeCookieList, i as LocalStorage, r as sendToBackground, x as SettingsService } from "./messaging-BeCmlDYm.js";
import { d as PermissionsService } from "./lifecycle-DkYubn-s.js";
import { t as normalizeScopeTarget } from "./normalize-BcYjnt_z.js";
import "./modulepreload-polyfill-BsPm7yBB.js";
import { t as applyAppearance } from "./appearance-BuGLOsv_.js";
import { t as TriageStore } from "./triage-store-BNdFsfqI.js";
//#region src/shared/scope/validate.ts
/**
* Validates a single scope rule.
*/
function validateScopeRule(rule) {
	if (typeof rule !== "object" || rule === null) return {
		valid: false,
		error: "Rule must be an object"
	};
	const r = rule;
	if (typeof r.pattern !== "string" || r.pattern.trim().length === 0) return {
		valid: false,
		error: "Rule pattern must be a non-empty string"
	};
	if (r.type !== "include" && r.type !== "exclude") return {
		valid: false,
		error: "Rule type must be either \"include\" or \"exclude\""
	};
	if (r.description !== void 0 && r.description !== null && typeof r.description !== "string") return {
		valid: false,
		error: "Rule description must be a string if provided"
	};
	try {
		normalizeScopeTarget(r.pattern);
	} catch (err) {
		return {
			valid: false,
			error: `Invalid rule pattern "${r.pattern}": ${err instanceof Error ? err.message : String(err)}`
		};
	}
	return { valid: true };
}
//#endregion
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
var discardBtn;
var saveStatus;
var sectionAllowlist;
var evalModeToggle;
var modeConflictBanner;
var btnRemoveBroadAccess;
var btnSwitchToAllSites;
var navDirtyBadge;
var unsavedDialog;
var triageCountBadge;
var btnClearTriage;
var activeScopeProfileSelect;
var scopeProfilesContainer;
var btnAddScopeProfile;
var currentMode = "per-site";
var pendingNavSection = null;
/** In-memory working copy of the allowedOrigins array. */
var workingOrigins = [];
var workingScopeProfiles = [];
var workingActiveScopeProfileId = null;
var initialSettingsSnapshot = "";
var isDirty = false;
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
	discardBtn = getEl("btn-discard");
	saveStatus = getEl("save-status");
	sectionAllowlist = getEl("section-allowlist");
	evalModeToggle = getEl("eval-mode-toggle");
	modeConflictBanner = getEl("mode-conflict-banner");
	btnRemoveBroadAccess = getEl("btn-remove-broad-access");
	btnSwitchToAllSites = getEl("btn-switch-to-all-sites");
	navDirtyBadge = getEl("nav-dirty-badge");
	unsavedDialog = getEl("unsaved-dialog");
	triageCountBadge = getEl("triage-count-badge");
	btnClearTriage = getEl("btn-clear-triage");
	activeScopeProfileSelect = getEl("active-scope-profile-select");
	scopeProfilesContainer = getEl("scope-profiles-container");
	btnAddScopeProfile = getEl("btn-add-scope-profile");
	wireNav();
	wireNavCards();
	wireModeRadios();
	wireConflictBanner();
	wireSaveButton();
	wireDiscardButton();
	wireDirtyTracking();
	wireDataManagement();
	wireAppearanceLivePreview();
	wireUnsavedDialog();
	wireTriageManagement();
	wireScopeManagement();
	if (typeof chrome !== "undefined" && typeof chrome.runtime !== "undefined") {
		const manifest = chrome.runtime.getManifest();
		const versionEl = document.getElementById("home-version-badge");
		if (versionEl) versionEl.textContent = `ACULYX v${manifest.version}`;
		const aboutEl = document.getElementById("about-version");
		if (aboutEl) aboutEl.textContent = manifest.version;
	}
	loadAndPopulate();
});
var SECTION_IDS = [
	"home",
	"monitoring",
	"findings",
	"cookies",
	"history",
	"scope",
	"appearance",
	"advanced",
	"about"
];
function navigateToSection(target) {
	if (isDirty) {
		pendingNavSection = target;
		showUnsavedDialog();
	} else activateSection(target);
}
function wireNav() {
	document.querySelectorAll(".nav-item[data-section]").forEach((btn) => {
		btn.addEventListener("click", () => {
			navigateToSection(btn.dataset["section"] ?? "home");
		});
	});
}
function wireNavCards() {
	document.querySelectorAll(".home-nav-card[data-goto]").forEach((card) => {
		card.addEventListener("click", () => {
			navigateToSection(card.dataset["goto"] ?? "home");
		});
	});
	const calloutAction = document.getElementById("home-callout-action");
	if (calloutAction) calloutAction.addEventListener("click", () => {
		navigateToSection("monitoring");
	});
}
function activateSection(sectionId) {
	const target = SECTION_IDS.includes(sectionId) ? sectionId : "home";
	SECTION_IDS.forEach((id) => {
		const section = document.getElementById(`section-${id}`);
		if (!section) return;
		if (id === target) {
			section.removeAttribute("hidden");
			section.classList.add("active");
		} else {
			section.setAttribute("hidden", "");
			section.classList.remove("active");
		}
	});
	document.querySelectorAll(".nav-item[data-section]").forEach((btn) => {
		const isActive = btn.dataset["section"] === target;
		btn.classList.toggle("active", isActive);
		if (isActive) btn.setAttribute("aria-current", "page");
		else btn.removeAttribute("aria-current");
	});
	if (target === "home") refreshHomeView();
}
async function refreshHomeView() {
	const modeEl = document.getElementById("home-mode-value");
	const permsEl = document.getElementById("home-perms-value");
	const callout = document.getElementById("home-callout");
	const calloutTitle = document.getElementById("home-callout-title");
	const calloutDesc = document.getElementById("home-callout-desc");
	const calloutAction = document.getElementById("home-callout-action");
	if (!modeEl || !permsEl || !callout || !calloutTitle || !calloutDesc) return;
	let settings;
	try {
		settings = await SettingsService.getSettings();
	} catch {
		modeEl.textContent = "Unknown";
		return;
	}
	modeEl.textContent = {
		"per-site": "Per-site opt-in",
		"all-sites": "All sites",
		"off": "Off"
	}[settings.monitoringMode] ?? settings.monitoringMode;
	let permText = "—";
	let needsAction = false;
	let actionText = "";
	let actionDesc = "";
	if (typeof chrome !== "undefined" && typeof chrome.permissions !== "undefined") try {
		const granted = await PermissionsService.getAllGrantedOrigins();
		const hasComplete = await PermissionsService.hasCompleteBroadGrant();
		const hasBroad = await PermissionsService.isBroadGrantPresent();
		if (settings.monitoringMode === "off") permText = "Capture disabled";
		else if (settings.monitoringMode === "all-sites") {
			if (hasComplete) permText = "All sites (complete)";
			else if (hasBroad) {
				permText = "⚠ Incomplete broad access";
				needsAction = true;
				actionText = "Fix permissions";
				actionDesc = "All-sites mode requires complete HTTP + HTTPS broad access. Capture is paused.";
			} else {
				permText = "⚠ No broad access granted";
				needsAction = true;
				actionText = "Grant access";
				actionDesc = "All-sites mode requires broad host permission. Go to Monitoring to grant it.";
			}
		} else if (hasBroad) {
			permText = "⚠ Conflict: broad access active";
			needsAction = true;
			actionText = "Resolve conflict";
			actionDesc = "Per-site mode is active but broad access is also granted. Capture is paused.";
		} else if (granted.length === 0) permText = "No origins granted yet";
		else permText = `${granted.length} origin${granted.length !== 1 ? "s" : ""} granted`;
	} catch {
		permText = "Unable to read permissions";
	}
	else permText = "Permissions API unavailable";
	permsEl.textContent = permText;
	if (needsAction) {
		callout.removeAttribute("hidden");
		calloutTitle.textContent = actionText;
		calloutDesc.textContent = actionDesc;
		if (calloutAction) {
			calloutAction.removeAttribute("hidden");
			calloutAction.textContent = "Go to Monitoring";
		}
	} else callout.setAttribute("hidden", "");
}
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
	maxHistoryInput.value = String(settings.maxHistoryPerOrigin ?? DEFAULT_SETTINGS.maxHistoryPerOrigin);
	alwaysSensitiveInput.value = settings.sensitiveCookieNames.join(", ");
	alwaysIgnoreInput.value = settings.ignoredCookieNames.join(", ");
	evalModeToggle.checked = Boolean(settings.evaluationMode);
	applyThemeRadio(settings.theme ?? DEFAULT_SETTINGS.theme ?? "system");
	applyDensityRadio(settings.density ?? DEFAULT_SETTINGS.density ?? "comfortable");
	applyMotionRadio(settings.reducedMotion ?? DEFAULT_SETTINGS.reducedMotion ?? "system");
	applyTheme(settings.theme ?? "system");
	applyDensity(settings.density ?? "comfortable");
	applyMotion(settings.reducedMotion ?? "system");
	try {
		workingOrigins = await PermissionsService.getAllGrantedOrigins();
	} catch {
		workingOrigins = [];
	}
	renderAllowlist();
	await checkAndRenderBroadConflict();
	workingScopeProfiles = settings.scopeProfiles !== void 0 ? settings.scopeProfiles.map((p) => ({
		...p,
		rules: p.rules.map((r) => ({ ...r }))
	})) : [];
	workingActiveScopeProfileId = settings.activeScopeProfileId ?? null;
	renderScopeProfiles();
	await refreshHomeView();
	initialSettingsSnapshot = getFormStateString();
	isDirty = false;
	updateDirtyUI();
}
function applyThemeRadio(value) {
	document.querySelectorAll("input[name=\"theme\"]").forEach((r) => {
		r.checked = r.value === value;
	});
}
function applyDensityRadio(value) {
	document.querySelectorAll("input[name=\"density\"]").forEach((r) => {
		r.checked = r.value === value;
	});
}
function applyMotionRadio(value) {
	document.querySelectorAll("input[name=\"reducedMotion\"]").forEach((r) => {
		r.checked = r.value === value;
	});
}
function wireAppearanceLivePreview() {
	document.querySelectorAll("input[name=\"theme\"]").forEach((r) => {
		r.addEventListener("change", () => {
			if (r.checked) applyTheme(r.value);
		});
	});
	document.querySelectorAll("input[name=\"density\"]").forEach((r) => {
		r.addEventListener("change", () => {
			if (r.checked) applyDensity(r.value);
		});
	});
	document.querySelectorAll("input[name=\"reducedMotion\"]").forEach((r) => {
		r.addEventListener("change", () => {
			if (r.checked) applyMotion(r.value);
		});
	});
}
function applyTheme(theme) {
	applyAppearance(theme);
}
function applyDensity(density) {
	applyAppearance(void 0, density);
}
function applyMotion(motion) {
	applyAppearance(void 0, void 0, motion);
}
function wireSaveButton() {
	saveBtn.addEventListener("click", () => {
		handleSave();
	});
}
function wireDiscardButton() {
	discardBtn.addEventListener("click", () => {
		loadAndPopulate();
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
		const resp = await sendToBackground({
			type: "SETTINGS_CHANGED",
			settings
		});
		if (resp?.success === false) throw new Error(resp.error ?? "Failed to apply settings transition");
		initialSettingsSnapshot = getFormStateString();
		isDirty = false;
		updateDirtyUI();
		setStatus("Settings saved ✓", false);
	} catch (err) {
		setStatus(`Failed to save settings: ${err instanceof Error ? err.message : "Failed to save settings."}`, true);
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
	let theme = "system";
	document.querySelectorAll("input[name=\"theme\"]").forEach((r) => {
		if (r.checked && (r.value === "system" || r.value === "dark" || r.value === "light")) theme = r.value;
	});
	let density = "comfortable";
	document.querySelectorAll("input[name=\"density\"]").forEach((r) => {
		if (r.checked && (r.value === "comfortable" || r.value === "compact")) density = r.value;
	});
	let reducedMotion = "system";
	document.querySelectorAll("input[name=\"reducedMotion\"]").forEach((r) => {
		if (r.checked && (r.value === "system" || r.value === "always" || r.value === "never")) reducedMotion = r.value;
	});
	return {
		schemaVersion: 2,
		monitoringMode,
		allowedOrigins: [...workingOrigins],
		severityFilter,
		retainHistoryDays,
		maxHistoryPerOrigin,
		sensitiveCookieNames: sensitive,
		ignoredCookieNames: ignored,
		evaluationMode: evalModeToggle.checked,
		scopeProfiles: [...workingScopeProfiles],
		activeScopeProfileId: workingActiveScopeProfileId,
		theme,
		density,
		reducedMotion
	};
}
function renderAllowlist() {
	while (allowlistEl.firstChild) allowlistEl.removeChild(allowlistEl.firstChild);
	if (workingOrigins.length === 0) {
		allowlistEmptyMsg.hidden = false;
		return;
	}
	allowlistEmptyMsg.hidden = true;
	for (const origin of workingOrigins) allowlistEl.appendChild(buildAllowlistItem(origin));
}
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
	purgeBtn.setAttribute("aria-label", `Delete stored audit history and graph data for ${origin}`);
	purgeBtn.addEventListener("click", () => {
		purgeOrigin(origin);
	});
	const removeBtn = document.createElement("button");
	removeBtn.type = "button";
	removeBtn.className = "btn-remove";
	removeBtn.textContent = "Remove";
	removeBtn.title = `Revoke browser host permission for ${origin}`;
	removeBtn.setAttribute("aria-label", `Revoke browser host permission for ${origin}`);
	removeBtn.addEventListener("click", () => {
		removeOrigin(origin);
	});
	actionsDiv.appendChild(purgeBtn);
	actionsDiv.appendChild(removeBtn);
	li.appendChild(originSpan);
	li.appendChild(actionsDiv);
	return li;
}
async function purgeOrigin(origin) {
	try {
		await LocalStorage.purgeOriginData(origin);
		setStatus(`Deleted stored data for ${origin}`, false);
	} catch {
		setStatus(`Failed to delete stored data for ${origin}`, true);
	}
}
function removeOrigin(origin) {
	(async () => {
		try {
			if (await PermissionsService.removeOriginPermission(origin)) {
				workingOrigins = workingOrigins.filter((o) => o !== origin);
				renderAllowlist();
				setStatus(`Revoked access for ${origin}`, false);
			} else setStatus(`Failed to revoke access for ${origin}`, true);
		} catch {
			setStatus(`Failed to revoke access for ${origin}`, true);
		}
	})();
}
function wireModeRadios() {
	for (const radio of modeRadios) radio.addEventListener("change", () => {
		if (!radio.checked) return;
		const targetMode = radio.value;
		if (targetMode === "all-sites" && currentMode !== "all-sites") {
			const revertToPriorMode = () => {
				for (const r of modeRadios) r.checked = r.value === currentMode;
				updateAllowlistVisibility(currentMode);
				checkAndRenderBroadConflict();
				setStatus("All-sites monitoring requires permission for all URLs. Kept previous mode.", true);
			};
			if (typeof chrome !== "undefined" && typeof chrome.permissions !== "undefined") try {
				chrome.permissions.request({ origins: ["<all_urls>"] }, (granted) => {
					if (!granted) revertToPriorMode();
					else {
						currentMode = "all-sites";
						updateAllowlistVisibility("all-sites");
						checkAndRenderBroadConflict();
					}
				});
			} catch {
				revertToPriorMode();
			}
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
	const hasComplete = await PermissionsService.hasCompleteBroadGrant();
	if (currentMode === "per-site" && broadActive) modeConflictBanner.removeAttribute("hidden");
	else if (currentMode === "all-sites" && !hasComplete) {
		modeConflictBanner.setAttribute("hidden", "");
		setStatus("All-sites mode requires complete broad permissions. Capture is currently paused.", true);
	} else modeConflictBanner.setAttribute("hidden", "");
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
function updateAllowlistVisibility(mode) {
	if (mode === "per-site") sectionAllowlist.removeAttribute("hidden");
	else sectionAllowlist.setAttribute("hidden", "");
}
function wireDataManagement() {
	const deleteOriginInput = getEl("delete-origin-input");
	const btnDeleteOrigin = getEl("btn-delete-origin");
	const btnClearHistory = getEl("btn-clear-history");
	const btnClearPrivate = getEl("btn-clear-private");
	const btnClearAll = getEl("btn-clear-all");
	const dataMgmtStatus = getEl("data-mgmt-status");
	function showDataStatus(msg, isError = false) {
		dataMgmtStatus.textContent = msg;
		dataMgmtStatus.className = "status-message " + (isError ? "status-error" : "status-success");
		setTimeout(() => {
			dataMgmtStatus.textContent = "";
			dataMgmtStatus.className = "status-message";
		}, 4e3);
	}
	btnDeleteOrigin.addEventListener("click", () => {
		const origin = deleteOriginInput.value.trim();
		if (!origin) {
			showDataStatus("Enter an origin first.", true);
			return;
		}
		try {
			new URL(origin);
		} catch {
			showDataStatus("Invalid origin URL.", true);
			return;
		}
		LocalStorage.deleteOriginData(origin).then(() => {
			showDataStatus(`Deleted data for ${origin}.`);
			deleteOriginInput.value = "";
		}).catch((err) => {
			showDataStatus(`Failed: ${String(err)}`, true);
		});
	});
	btnClearHistory.addEventListener("click", () => {
		if (!confirm("Clear ALL history? This cannot be undone.")) return;
		LocalStorage.deleteAllHistory().then(() => showDataStatus("All history cleared.")).catch((err) => showDataStatus(`Failed: ${String(err)}`, true));
	});
	btnClearPrivate.addEventListener("click", () => {
		LocalStorage.deletePrivateRecords().then(() => showDataStatus("Private records cleared.")).catch((err) => showDataStatus(`Failed: ${String(err)}`, true));
	});
	btnClearAll.addEventListener("click", () => {
		if (!confirm("Reset ALL local ACULYX data? This cannot be undone.")) return;
		sendToBackground({ type: "RESET_ALL_DATA" }).then(() => {
			showDataStatus("All data reset. Reloading…");
			setTimeout(() => window.location.reload(), 1500);
		}).catch((err) => showDataStatus(`Failed: ${String(err)}`, true));
	});
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
		evaluationMode: current.evaluationMode,
		activeScopeProfileId: current.activeScopeProfileId ?? null,
		scopeProfiles: current.scopeProfiles ?? [],
		theme: current.theme ?? "system",
		density: current.density ?? "comfortable",
		reducedMotion: current.reducedMotion ?? "system"
	});
}
function updateDirtyState() {
	if (!initialSettingsSnapshot) return;
	isDirty = getFormStateString() !== initialSettingsSnapshot;
	updateDirtyUI();
}
function updateDirtyUI() {
	navDirtyBadge.hidden = !isDirty;
	navDirtyBadge.setAttribute("aria-hidden", String(!isDirty));
	discardBtn.hidden = !isDirty;
	if (isDirty) setStatus("Unsaved changes", false, true);
	else if (saveStatus.classList.contains("dirty")) clearStatus();
}
function wireDirtyTracking() {
	for (const radio of modeRadios) radio.addEventListener("change", updateDirtyState);
	for (const cb of severityCheckboxes) cb.addEventListener("change", updateDirtyState);
	retainDaysInput.addEventListener("input", updateDirtyState);
	maxHistoryInput.addEventListener("input", updateDirtyState);
	alwaysSensitiveInput.addEventListener("input", updateDirtyState);
	alwaysIgnoreInput.addEventListener("input", updateDirtyState);
	evalModeToggle.addEventListener("change", updateDirtyState);
	document.querySelectorAll("input[name=\"theme\"], input[name=\"density\"], input[name=\"reducedMotion\"]").forEach((r) => r.addEventListener("change", updateDirtyState));
}
function wireUnsavedDialog() {
	const dialogSave = getEl("dialog-save");
	const dialogDiscard = getEl("dialog-discard");
	const dialogCancel = getEl("dialog-cancel");
	dialogSave.addEventListener("click", () => {
		unsavedDialog.close();
		handleSave().then(() => {
			if (pendingNavSection !== null) {
				const target = pendingNavSection;
				pendingNavSection = null;
				activateSection(target);
			}
		});
	});
	dialogDiscard.addEventListener("click", () => {
		unsavedDialog.close();
		loadAndPopulate().then(() => {
			if (pendingNavSection !== null) {
				const target = pendingNavSection;
				pendingNavSection = null;
				activateSection(target);
			}
		});
	});
	dialogCancel.addEventListener("click", () => {
		unsavedDialog.close();
		pendingNavSection = null;
	});
}
function showUnsavedDialog() {
	if (typeof unsavedDialog.showModal === "function") unsavedDialog.showModal();
}
function setStatus(msg, isError, dirtyFlag = false) {
	saveStatus.textContent = msg;
	saveStatus.className = "save-status";
	if (isError) saveStatus.classList.add("error");
	else if (dirtyFlag) saveStatus.classList.add("dirty");
}
function clearStatus() {
	saveStatus.textContent = "";
	saveStatus.className = "save-status";
}
function wireTriageManagement() {
	const refreshTriageCount = async () => {
		try {
			const annotations = await TriageStore.getAnnotations();
			const count = Object.keys(annotations).length;
			triageCountBadge.textContent = `${count} triaged finding${count === 1 ? "" : "s"}`;
		} catch {
			triageCountBadge.textContent = "0 triaged findings";
		}
	};
	btnClearTriage.addEventListener("click", () => {
		if (window.confirm("Reset all researcher triage annotations and notes? This cannot be undone.")) TriageStore.clearAll().then(() => refreshTriageCount());
	});
	refreshTriageCount();
}
function wireScopeManagement() {
	activeScopeProfileSelect.addEventListener("change", () => {
		workingActiveScopeProfileId = activeScopeProfileSelect.value.length > 0 ? activeScopeProfileSelect.value : null;
		updateDirtyState();
	});
	btnAddScopeProfile.addEventListener("click", () => {
		const newId = `profile-${Date.now()}`;
		const newProfile = {
			id: newId,
			name: `Program ${workingScopeProfiles.length + 1}`,
			rules: [{
				pattern: "*.example.com",
				type: "include"
			}],
			lastReviewed: Date.now()
		};
		workingScopeProfiles.push(newProfile);
		if (workingActiveScopeProfileId === null || workingActiveScopeProfileId.length === 0) workingActiveScopeProfileId = newId;
		renderScopeProfiles();
		updateDirtyState();
	});
}
function renderScopeProfiles() {
	while (activeScopeProfileSelect.firstChild !== null) activeScopeProfileSelect.removeChild(activeScopeProfileSelect.firstChild);
	const noneOpt = document.createElement("option");
	noneOpt.value = "";
	noneOpt.textContent = "(None — Global Unscoped Monitoring)";
	activeScopeProfileSelect.appendChild(noneOpt);
	for (const prof of workingScopeProfiles) {
		const opt = document.createElement("option");
		opt.value = prof.id;
		opt.textContent = prof.name;
		if (prof.id === workingActiveScopeProfileId) opt.selected = true;
		activeScopeProfileSelect.appendChild(opt);
	}
	if (workingActiveScopeProfileId === null || workingActiveScopeProfileId.length === 0) noneOpt.selected = true;
	while (scopeProfilesContainer.firstChild !== null) scopeProfilesContainer.removeChild(scopeProfilesContainer.firstChild);
	if (workingScopeProfiles.length === 0) {
		const emptyP = document.createElement("p");
		emptyP.className = "field-hint";
		emptyP.textContent = "No scope profiles defined yet. Click \"+ New Profile\" to configure authorized targets for a bounty program.";
		scopeProfilesContainer.appendChild(emptyP);
		return;
	}
	workingScopeProfiles.forEach((profile, profIdx) => {
		const card = document.createElement("div");
		card.className = "scope-profile-card field-row";
		card.style.flexDirection = "column";
		card.style.alignItems = "stretch";
		card.style.border = "1px solid var(--border-color, #2a2e39)";
		card.style.borderRadius = "6px";
		card.style.padding = "12px";
		card.style.marginBottom = "12px";
		const headerDiv = document.createElement("div");
		headerDiv.className = "flex-between";
		headerDiv.style.display = "flex";
		headerDiv.style.justifyContent = "space-between";
		headerDiv.style.alignItems = "center";
		headerDiv.style.marginBottom = "8px";
		const nameInput = document.createElement("input");
		nameInput.type = "text";
		nameInput.className = "text-input";
		nameInput.value = profile.name;
		nameInput.placeholder = "Program / Profile Name";
		nameInput.style.fontWeight = "bold";
		nameInput.style.maxWidth = "240px";
		nameInput.addEventListener("input", () => {
			profile.name = nameInput.value.trim() || `Program ${profIdx + 1}`;
			updateDirtyState();
			const opt = activeScopeProfileSelect.querySelector(`option[value="${profile.id}"]`);
			if (opt) opt.textContent = profile.name;
		});
		const delProfBtn = document.createElement("button");
		delProfBtn.type = "button";
		delProfBtn.className = "btn-danger btn-sm";
		delProfBtn.textContent = "Delete Profile";
		delProfBtn.addEventListener("click", () => {
			workingScopeProfiles.splice(profIdx, 1);
			if (workingActiveScopeProfileId === profile.id) workingActiveScopeProfileId = workingScopeProfiles[0]?.id ?? null;
			renderScopeProfiles();
			updateDirtyState();
		});
		headerDiv.appendChild(nameInput);
		headerDiv.appendChild(delProfBtn);
		card.appendChild(headerDiv);
		const rulesTable = document.createElement("div");
		rulesTable.className = "scope-rules-table";
		profile.rules.forEach((rule, ruleIdx) => {
			const row = document.createElement("div");
			row.style.display = "flex";
			row.style.alignItems = "center";
			row.style.gap = "8px";
			row.style.marginBottom = "4px";
			const typeBadge = document.createElement("span");
			typeBadge.textContent = rule.type.toUpperCase();
			typeBadge.style.fontSize = "11px";
			typeBadge.style.padding = "2px 6px";
			typeBadge.style.borderRadius = "3px";
			typeBadge.style.fontWeight = "bold";
			typeBadge.style.color = "#fff";
			typeBadge.style.backgroundColor = rule.type === "include" ? "#27ae60" : "#c0392b";
			const patternSpan = document.createElement("code");
			patternSpan.textContent = rule.pattern;
			patternSpan.style.flex = "1";
			const delRuleBtn = document.createElement("button");
			delRuleBtn.type = "button";
			delRuleBtn.className = "btn-sm btn-remove";
			delRuleBtn.textContent = "×";
			delRuleBtn.title = "Remove rule";
			delRuleBtn.addEventListener("click", () => {
				profile.rules.splice(ruleIdx, 1);
				renderScopeProfiles();
				updateDirtyState();
			});
			row.appendChild(typeBadge);
			row.appendChild(patternSpan);
			row.appendChild(delRuleBtn);
			rulesTable.appendChild(row);
		});
		card.appendChild(rulesTable);
		const addRuleDiv = document.createElement("div");
		addRuleDiv.style.display = "flex";
		addRuleDiv.style.alignItems = "center";
		addRuleDiv.style.gap = "8px";
		addRuleDiv.style.marginTop = "8px";
		const rulePatternInput = document.createElement("input");
		rulePatternInput.type = "text";
		rulePatternInput.placeholder = "*.domain.com or host:port";
		rulePatternInput.className = "text-input";
		rulePatternInput.style.flex = "1";
		const ruleTypeSelect = document.createElement("select");
		ruleTypeSelect.className = "select-input";
		const incOpt = document.createElement("option");
		incOpt.value = "include";
		incOpt.textContent = "Include";
		const excOpt = document.createElement("option");
		excOpt.value = "exclude";
		excOpt.textContent = "Exclude";
		ruleTypeSelect.appendChild(incOpt);
		ruleTypeSelect.appendChild(excOpt);
		const addRuleBtn = document.createElement("button");
		addRuleBtn.type = "button";
		addRuleBtn.className = "btn-secondary btn-sm";
		addRuleBtn.textContent = "Add Rule";
		const ruleErrorMsg = document.createElement("span");
		ruleErrorMsg.style.color = "#e74c3c";
		ruleErrorMsg.style.fontSize = "12px";
		ruleErrorMsg.style.marginLeft = "8px";
		addRuleBtn.addEventListener("click", () => {
			ruleErrorMsg.textContent = "";
			const pat = rulePatternInput.value.trim();
			const typ = ruleTypeSelect.value;
			const validRes = validateScopeRule({
				pattern: pat,
				type: typ
			});
			if (!validRes.valid) {
				ruleErrorMsg.textContent = validRes.error ?? "Invalid rule pattern";
				return;
			}
			profile.rules.push({
				pattern: pat,
				type: typ
			});
			rulePatternInput.value = "";
			renderScopeProfiles();
			updateDirtyState();
		});
		addRuleDiv.appendChild(rulePatternInput);
		addRuleDiv.appendChild(ruleTypeSelect);
		addRuleDiv.appendChild(addRuleBtn);
		card.appendChild(addRuleDiv);
		card.appendChild(ruleErrorMsg);
		scopeProfilesContainer.appendChild(card);
	});
}
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
			refreshHomeView();
		});
	});
	if (typeof chrome.permissions.onAdded !== "undefined") chrome.permissions.onAdded.addListener(() => {
		PermissionsService.getAllGrantedOrigins().then((origins) => {
			workingOrigins = origins;
			renderAllowlist();
			checkAndRenderBroadConflict();
			refreshHomeView();
		});
	});
}
//#endregion

//# sourceMappingURL=options.html-Bk7UrurM.js.map