import { C as sanitizeUrlForStorage, _ as originFromUrl, a as SessionStorage, b as redactUrlPath, g as normalizeHeaders, i as LocalStorage, j as MAINTENANCE_ALARM, m as headersDiffer, w as SettingsService, y as redactHeaderValue } from "./messaging-BvANQDmr.js";
//#region src/background/generations.ts
/**
* generations.ts
*
* Per-tab navigation generation counter.
* Incremented on onBeforeNavigate (top-level frameId === 0).
* Tags hops, API hops, cookie changes, and page signals.
* Late arrivals for older generations are discarded immediately.
*/
var tabGenerations = /* @__PURE__ */ new Map();
function getTabGeneration(tabId) {
	return tabGenerations.get(tabId) ?? 0;
}
function incrementTabGeneration(tabId) {
	const next = (tabGenerations.get(tabId) ?? 0) + 1;
	tabGenerations.set(tabId, next);
	return next;
}
function setTabGeneration(tabId, gen) {
	tabGenerations.set(tabId, gen);
}
function clearTabGenerations() {
	tabGenerations.clear();
}
//#endregion
//#region src/shared/gating.ts
var RESTRICTED_SCHEME_PREFIXES = [
	"chrome://",
	"chrome-extension://",
	"edge://",
	"devtools://",
	"about:",
	"data:",
	"blob:",
	"view-source:"
];
/**
* Checks whether a URL is restricted from inspection (browser internals, extensions, web stores).
*/
function isRestrictedUrl(url, options) {
	if (!url || url.trim().length === 0) return true;
	const lower = url.trim().toLowerCase();
	for (const prefix of RESTRICTED_SCHEME_PREFIXES) if (lower.startsWith(prefix)) return true;
	if (lower.startsWith("file://")) return options?.fileAccessAllowed !== true;
	try {
		const parsed = new URL(lower);
		const host = parsed.hostname;
		if (host === "chromewebstore.google.com" || host === "addons.mozilla.org") return true;
		if (host === "chrome.google.com" && parsed.pathname.startsWith("/webstore")) return true;
	} catch {
		if (!lower.startsWith("http://") && !lower.startsWith("https://")) return true;
	}
	return false;
}
/**
* Pure synchronous function to evaluate whether traffic for a URL qualifies for capture.
*
* Invariant: Evaluation mode or presentation settings NEVER affect this decision.
*/
function isModeCaptureAllowed(url, settings, broadGrantPresent, options, completeBroadGrant) {
	if (isRestrictedUrl(url, options)) return {
		allowed: false,
		reason: "restricted-url"
	};
	if (settings.monitoringMode === "off") return {
		allowed: false,
		reason: "off"
	};
	if (settings.monitoringMode === "per-site" && broadGrantPresent) return {
		allowed: false,
		reason: "broad-access-conflict"
	};
	if (settings.monitoringMode === "all-sites" && completeBroadGrant === false) return {
		allowed: false,
		reason: "all-sites-missing-grant"
	};
	return {
		allowed: true,
		reason: "ok"
	};
}
//#endregion
//#region src/background/permissions.ts
var BROAD_GRANT_PATTERNS = /* @__PURE__ */ new Set([
	"<all_urls>",
	"*://*/*",
	"*://*",
	"http://*/*",
	"https://*/*",
	"http://*/",
	"https://*/"
]);
/**
* Checks if a permission pattern represents a broad (all-urls) grant.
*/
function isBroadGrant(pattern) {
	if (!pattern) return false;
	const trimmed = pattern.trim();
	if (BROAD_GRANT_PATTERNS.has(trimmed)) return true;
	return trimmed.includes("://*/*") || trimmed.includes("://*/");
}
/**
* Checks whether a collection of permission patterns satisfies complete "All-sites" coverage
* across all supported web schemes (http://* and https://*, or <all_urls> / *://*).
*/
function hasAllSitesCoverage(patterns) {
	if (patterns.length === 0) return false;
	let hasHttp = false;
	let hasHttps = false;
	for (const raw of patterns) {
		if (!raw) continue;
		const trimmed = raw.trim();
		if (trimmed === "<all_urls>" || trimmed === "*://*/*" || trimmed === "*://*") return true;
		if (trimmed === "http://*/*" || trimmed === "http://*" || trimmed === "http://*/") hasHttp = true;
		if (trimmed === "https://*/*" || trimmed === "https://*" || trimmed === "https://*/") hasHttps = true;
	}
	return hasHttp && hasHttps;
}
/**
* Normalizes a Chrome permission origin pattern into an origin string (scheme + host[:port]).
* E.g., "https://example.com/*" -> "https://example.com"
*/
function normalizePermissionOrigin(pattern) {
	if (!pattern) return "";
	const trimmed = pattern.trim();
	if (isBroadGrant(trimmed)) return trimmed;
	try {
		const withoutWildcard = trimmed.replace(/\/\*.*$/, "");
		return new URL(withoutWildcard.endsWith("/") ? withoutWildcard : `${withoutWildcard}/`).origin;
	} catch {
		return trimmed.replace(/\/\*.*$/, "").replace(/\/+$/, "");
	}
}
/**
* Generates a valid Chrome match pattern from an origin or URL string.
* Chrome match patterns cannot specify ports.
* E.g., "http://127.0.0.1:3464" -> "http://127.0.0.1/*"
*       "https://example.com" -> "https://example.com/*"
*/
function patternFromOrigin(originOrUrl) {
	if (!originOrUrl) return "";
	const trimmed = originOrUrl.trim();
	if (isBroadGrant(trimmed)) return trimmed;
	try {
		const u = new URL(trimmed.endsWith("/") ? trimmed : `${trimmed}/`);
		return `${u.protocol}//${u.hostname}/*`;
	} catch {
		return `${trimmed.replace(/\/\*.*$/, "").replace(/\/+$/, "")}/*`;
	}
}
var PermissionsService = {
	/**
	* Queries chrome.permissions.getAll() and returns true if any broad grant exists.
	*/
	async isBroadGrantPresent() {
		if (typeof chrome === "undefined" || typeof chrome.permissions === "undefined" || typeof chrome.permissions.getAll === "undefined") return false;
		return ((await chrome.permissions.getAll()).origins ?? []).some((o) => isBroadGrant(o));
	},
	/**
	* Authoritative query: returns true if the granted permissions satisfy complete
	* All-sites coverage across all supported web schemes.
	*/
	async hasCompleteBroadGrant() {
		if (typeof chrome === "undefined" || typeof chrome.permissions === "undefined" || typeof chrome.permissions.getAll === "undefined") return false;
		return hasAllSitesCoverage((await chrome.permissions.getAll()).origins ?? []);
	},
	/**
	* Authoritative query: returns all explicitly granted origins (excluding broad patterns).
	* Normalizes patterns to canonical origins (e.g., https://example.com).
	*/
	async getAllGrantedOrigins() {
		if (typeof chrome === "undefined" || typeof chrome.permissions === "undefined" || typeof chrome.permissions.getAll === "undefined") return [];
		const origins = (await chrome.permissions.getAll()).origins ?? [];
		const set = /* @__PURE__ */ new Set();
		for (const pattern of origins) if (!isBroadGrant(pattern)) {
			const norm = normalizePermissionOrigin(pattern);
			if (norm.length > 0) set.add(norm);
		}
		return Array.from(set);
	},
	/**
	* Checks whether the browser currently has permission for the specified origin.
	*/
	async hasPermissionForOrigin(origin) {
		if (!origin || typeof chrome === "undefined" || typeof chrome.permissions === "undefined") return false;
		const pattern = patternFromOrigin(origin);
		if (await new Promise((resolve) => {
			chrome.permissions.contains({ origins: [pattern] }, (result) => {
				if (chrome.runtime?.lastError) resolve(false);
				else resolve(Boolean(result));
			});
		})) return true;
		const norm = normalizePermissionOrigin(origin);
		if (`${norm}/*` !== pattern) return new Promise((resolve) => {
			chrome.permissions.contains({ origins: [`${norm}/*`] }, (result) => {
				if (chrome.runtime?.lastError) resolve(false);
				else resolve(Boolean(result));
			});
		});
		return false;
	},
	/**
	* Revokes host permission for a specific origin.
	*/
	async removeOriginPermission(origin) {
		if (!origin || typeof chrome === "undefined" || typeof chrome.permissions === "undefined") return false;
		const pattern = patternFromOrigin(origin);
		if (await new Promise((resolve) => {
			chrome.permissions.remove({ origins: [pattern] }, (result) => {
				if (chrome.runtime?.lastError) resolve(false);
				else resolve(Boolean(result));
			});
		})) return true;
		const norm = normalizePermissionOrigin(origin);
		if (`${norm}/*` !== pattern) return new Promise((resolve) => {
			chrome.permissions.remove({ origins: [`${norm}/*`] }, (result) => {
				if (chrome.runtime?.lastError) resolve(false);
				else resolve(Boolean(result));
			});
		});
		return false;
	},
	/**
	* Identifies all broad permission patterns currently granted in the browser,
	* requests removal from the browser, and verifies that no broad grants remain.
	* Returns true only if all broad patterns were successfully removed.
	*/
	async removeAllBroadGrants() {
		if (typeof chrome === "undefined" || typeof chrome.permissions === "undefined" || typeof chrome.permissions.getAll === "undefined" || typeof chrome.permissions.remove === "undefined") return false;
		const broadOrigins = ((await chrome.permissions.getAll()).origins ?? []).filter((o) => isBroadGrant(o));
		if (broadOrigins.length === 0) return true;
		if (!await new Promise((resolve) => {
			chrome.permissions.remove({ origins: broadOrigins }, (result) => {
				resolve(Boolean(result));
			});
		})) return false;
		return ((await chrome.permissions.getAll()).origins ?? []).filter((o) => isBroadGrant(o)).length === 0;
	},
	/**
	* Revokes all optional host permissions granted to the extension.
	*/
	async removeAllOptionalPermissions() {
		if (typeof chrome === "undefined" || typeof chrome.permissions === "undefined") return false;
		const origins = (await chrome.permissions.getAll()).origins ?? [];
		if (origins.length === 0) return true;
		return new Promise((resolve) => {
			chrome.permissions.remove({ origins }, resolve);
		});
	}
};
/**
* Idempotently clears all captured state, pending receipts, badges, and session storage
* for a tab whose origin permission was revoked or reset.
*/
async function clearTabCapture(tabId, options) {
	const targetTabStates = options?.tabStates ?? tabStates;
	const targetSessionStorage = options?.sessionStorage ?? SessionStorage;
	const targetCaptureMap = options?.captureMap ?? captureMap;
	targetTabStates.delete(tabId);
	try {
		await targetSessionStorage.removeTabState(tabId);
	} catch {}
	for (const [requestId, partial] of targetCaptureMap.entries()) if (partial.tabId === tabId) targetCaptureMap.delete(requestId);
	options?.pendingServiceWorkerReports?.delete(tabId);
	options?.pendingMetaCspReports?.delete(tabId);
	if (options?.setBadge !== void 0) options.setBadge(tabId, "");
	else if (typeof chrome !== "undefined" && typeof chrome.action !== "undefined") chrome.action.setBadgeText({
		tabId,
		text: ""
	}).catch(() => void 0);
	if (options?.broadcast !== void 0) options.broadcast(tabId, {
		type: "STATE_RESPONSE",
		state: null
	});
}
/**
* Handles permission revocation when chrome.permissions.onRemoved fires.
* Identifies tabs whose origin permission was revoked and clears their capture.
* Preserves tabs whose origin remains permitted even after a broad grant is removed.
*/
async function reconcilePermissionsOnRemoved(_removedOrigins, options) {
	const clearedTabIds = [];
	const targetTabStates = options?.tabStates ?? tabStates;
	if (options?.isBroadGrantActive !== void 0 ? await options.isBroadGrantActive() : await PermissionsService.isBroadGrantPresent()) return clearedTabIds;
	const activeOrigins = options?.getActiveOrigins !== void 0 ? await options.getActiveOrigins() : await PermissionsService.getAllGrantedOrigins();
	const activeOriginSet = new Set(activeOrigins.map(normalizePermissionOrigin));
	for (const [tabId, state] of Array.from(targetTabStates.entries())) {
		const tabOrigin = normalizePermissionOrigin(state.origin);
		let tabOriginWithoutPort = "";
		try {
			const u = new URL(state.origin.endsWith("/") ? state.origin : `${state.origin}/`);
			tabOriginWithoutPort = `${u.protocol}//${u.hostname}`;
		} catch {}
		if (!(activeOriginSet.has(tabOrigin) || tabOriginWithoutPort.length > 0 && activeOriginSet.has(tabOriginWithoutPort))) {
			await clearTabCapture(tabId, options);
			clearedTabIds.push(tabId);
		}
	}
	return clearedTabIds;
}
/**
* Service worker startup reconciliation: inspects all hydrated tabs and evicts
* any tabs whose origin permission was revoked while the SW was inactive.
*/
async function reconcilePermissionsOnStartup(options) {
	const isBroadActive = options?.isBroadGrantActive !== void 0 ? await options.isBroadGrantActive() : await PermissionsService.isBroadGrantPresent();
	const activeOrigins = options?.getActiveOrigins !== void 0 ? await options.getActiveOrigins() : await PermissionsService.getAllGrantedOrigins();
	const activeOriginSet = new Set(activeOrigins.map(normalizePermissionOrigin));
	const targetTabStates = options?.tabStates ?? tabStates;
	const clearedTabIds = [];
	for (const [tabId, state] of Array.from(targetTabStates.entries())) {
		const tabOrigin = normalizePermissionOrigin(state.origin);
		let tabOriginWithoutPort = "";
		try {
			const u = new URL(state.origin.endsWith("/") ? state.origin : `${state.origin}/`);
			tabOriginWithoutPort = `${u.protocol}//${u.hostname}`;
		} catch {}
		if (!(isBroadActive || activeOriginSet.has(tabOrigin) || tabOriginWithoutPort.length > 0 && activeOriginSet.has(tabOriginWithoutPort))) {
			await clearTabCapture(tabId, options);
			clearedTabIds.push(tabId);
		}
	}
	return clearedTabIds;
}
//#endregion
//#region src/background/capture-policy.ts
/**
* capture-policy.ts
*
* Single authoritative fail-closed capture policy across navigation, API,
* and page-signal paths.
*/
var currentSnapshot = {
	ready: false,
	revision: 0,
	mode: "off",
	broadGrantActive: false,
	grantedOrigins: /* @__PURE__ */ new Set()
};
var currentRevision = 0;
var latestCompletedRevision = 0;
/**
* Pure synchronous evaluation of whether traffic for a URL qualifies for capture
* at the earliest listener boundary, using an immutable policy snapshot.
*/
function isCaptureAllowedAtBoundary(url, snapshot) {
	if (!snapshot.ready) return false;
	if (!url || isRestrictedUrl(url)) return false;
	if (snapshot.mode === "off") return false;
	if (snapshot.mode === "per-site") {
		if (snapshot.broadGrantActive) return false;
		const origin = originFromUrl(url);
		if (origin === null) return false;
		const normalized = normalizePermissionOrigin(origin);
		if (snapshot.grantedOrigins.has(normalized)) return true;
		try {
			const u = new URL(url);
			const withoutPort = `${u.protocol}//${u.hostname}`;
			if (snapshot.grantedOrigins.has(withoutPort)) return true;
		} catch {}
		return false;
	}
	if (snapshot.mode === "all-sites") return snapshot.broadGrantActive;
	return false;
}
/**
* Hydrates the snapshot from SettingsService + PermissionsService.
* Uses monotonic revision tracking so older async responses cannot overwrite newer state.
*/
async function refreshCapturePolicySnapshot() {
	const revision = ++currentRevision;
	try {
		const settings = await SettingsService.getSettings();
		const broadActive = await PermissionsService.isBroadGrantPresent();
		const hasAllSites = await PermissionsService.hasCompleteBroadGrant();
		const grantedOriginsList = await PermissionsService.getAllGrantedOrigins();
		if (revision >= latestCompletedRevision) {
			latestCompletedRevision = revision;
			const broadGrantActive = settings.monitoringMode === "all-sites" ? hasAllSites : settings.monitoringMode === "per-site" ? broadActive : false;
			currentSnapshot = {
				ready: true,
				revision,
				mode: settings.monitoringMode,
				broadGrantActive,
				grantedOrigins: new Set(grantedOriginsList.map(normalizePermissionOrigin))
			};
		}
	} catch {
		if (revision >= latestCompletedRevision) {
			latestCompletedRevision = revision;
			currentSnapshot = {
				ready: false,
				revision,
				mode: "off",
				broadGrantActive: false,
				grantedOrigins: /* @__PURE__ */ new Set()
			};
		}
	}
	return currentSnapshot;
}
SettingsService.onSettingsChanged(() => {
	refreshCapturePolicySnapshot();
});
if (typeof chrome !== "undefined" && typeof chrome.permissions !== "undefined") try {
	chrome.permissions.onAdded?.addListener?.(() => {
		refreshCapturePolicySnapshot();
	});
	chrome.permissions.onRemoved?.addListener?.(() => {
		refreshCapturePolicySnapshot();
	});
} catch {}
var CapturePolicy = {
	/**
	* Returns current synchronous snapshot.
	*/
	getSnapshot() {
		return currentSnapshot;
	},
	/**
	* Evaluates boundary allowance using current snapshot or passed snapshot.
	*/
	isCaptureAllowedAtBoundary(url, snapshot) {
		return isCaptureAllowedAtBoundary(url, snapshot ?? currentSnapshot);
	},
	/**
	* Sets snapshot for testing purposes.
	*/
	setSnapshotForTesting(snapshot) {
		currentSnapshot = snapshot;
	},
	/**
	* Resets snapshot to initial unhydrated state (for tests).
	*/
	resetSnapshotForTesting() {
		currentSnapshot = {
			ready: false,
			revision: 0,
			mode: "off",
			broadGrantActive: false,
			grantedOrigins: /* @__PURE__ */ new Set()
		};
		currentRevision = 0;
		latestCompletedRevision = 0;
	},
	/**
	* Triggers an idempotent snapshot refresh.
	*/
	async refreshSnapshot() {
		return refreshCapturePolicySnapshot();
	},
	/**
	* Returns truthful human-readable monitoring state.
	*/
	async getMonitoringState() {
		let settings;
		try {
			settings = await SettingsService.getSettings();
		} catch {
			return "Error loading settings";
		}
		if (settings.monitoringMode === "off") return "Off";
		if (settings.monitoringMode === "all-sites") {
			if (!await PermissionsService.hasCompleteBroadGrant()) return "Paused — All-sites permission missing";
			return "Active — All sites";
		}
		if (settings.monitoringMode === "per-site") {
			if (await PermissionsService.isBroadGrantPresent()) return "Paused — Broad access conflict";
			return "Active — Per-site";
		}
		return "Unknown";
	},
	/**
	* Authoritative fail-closed evaluation of whether capture is permitted for a URL.
	* Awaits settings hydration and evaluates mode, broad grants, and origin permissions.
	*/
	async evaluate(url) {
		if (url.length === 0 || isRestrictedUrl(url)) return {
			allowed: false,
			reason: "restricted-url"
		};
		const origin = originFromUrl(url);
		if (origin === null || origin.length === 0) return {
			allowed: false,
			reason: "invalid-url"
		};
		let settings;
		try {
			settings = await SettingsService.getSettings();
		} catch {
			return {
				allowed: false,
				reason: "settings-error"
			};
		}
		if (settings.monitoringMode === "off") return {
			allowed: false,
			reason: "off"
		};
		if (settings.monitoringMode === "all-sites") {
			if (!await PermissionsService.hasCompleteBroadGrant()) return {
				allowed: false,
				reason: "all-sites-missing-grant",
				monitoringState: "Paused — All-sites permission missing"
			};
			return { allowed: true };
		}
		if (settings.monitoringMode === "per-site") {
			if (await PermissionsService.isBroadGrantPresent()) return {
				allowed: false,
				reason: "broad-access-conflict"
			};
			if (!await PermissionsService.hasPermissionForOrigin(origin)) return {
				allowed: false,
				reason: "not-permitted"
			};
			return { allowed: true };
		}
		return { allowed: false };
	},
	/**
	* Helper returning boolean allowed status.
	*/
	async isAllowed(url) {
		return (await this.evaluate(url)).allowed;
	}
};
//#endregion
//#region src/background/capture.ts
/**
* capture.ts
*
* Registers chrome.webRequest listeners that intercept HTTP response headers
* at two distinct pipeline stages:
*
*   1. onHeadersReceived  — headers as the browser first sees them (may differ
*                           from final values if extensions modify them).
*   2. onResponseStarted  — final headers after all modifications.
*
* Comparing the two snapshots lets us detect header mutations by other
* extensions or intermediaries (headersDiffer flag on the Hop).
*
* Captures top-level (`main_frame`) navigations and in-page `xmlhttprequest` (XHR/fetch)
* API responses. Passive sub-resources (images, stylesheets, fonts, iframes) are excluded
* to avoid noise. All captures are strictly origin-gated and require user permission.
*/
var incognitoTabIds = /* @__PURE__ */ new Set();
/**
* Keyed by Chrome's `requestId`.  Entries are created on onHeadersReceived
* and deleted after onResponseStarted finishes processing.
*/
var captureMap = /* @__PURE__ */ new Map();
/**
* Keyed by Chrome's `requestId`. In-flight request metadata for XHR/Fetch.
*/
var inFlightRequests = /* @__PURE__ */ new Map();
/**
* Immediately clears all in-flight capture maps (used on transition to Off mode).
*/
function clearInFlightCaptures() {
	captureMap.clear();
	inFlightRequests.clear();
}
/**
* Detect the Non-Authoritative-Reason: HSTS header (case-insensitive name)
* which indicates the browser silently upgraded the request from HTTP→HTTPS.
*/
function detectHstsUpgrade(raw) {
	return raw.some((h) => h.name.toLowerCase() === "non-authoritative-reason" && h.value.toUpperCase() === "HSTS");
}
/**
* Convert a chrome.webRequest.HttpHeader array to the project's raw-header
* format, ensuring the value is always a string.
*/
function toRawHeaders(headers) {
	return headers.map((h) => ({
		name: h.name,
		value: redactHeaderValue(h.name, h.value ?? "")
	}));
}
/**
* Checks whether capture is currently active and permitted for this URL.
* Evaluates the synchronous fail-closed CapturePolicySnapshot at the listener boundary.
*/
function isCaptureActiveForUrl(url) {
	return isCaptureAllowedAtBoundary(url, CapturePolicy.getSnapshot());
}
/**
* Registers all WebRequest listeners needed to capture response hops.
*
* @param onHopComplete - Callback invoked for every captured response, including
*   intermediate redirect responses.
* @param onApiHopComplete - Optional callback invoked for each captured XHR/Fetch response.
*/
function registerCaptureListeners(onHopComplete, onApiHopComplete, onThirdPartyBlocked) {
	const filter = { urls: ["<all_urls>"] };
	const extraInfoSpec = ["responseHeaders", "extraHeaders"];
	try {
		chrome.webRequest.onBeforeSendHeaders.addListener((details) => {
			if (details.tabId < 0) return;
			const snapshot = CapturePolicy.getSnapshot();
			if (!isCaptureActiveForUrl(details.url)) {
				if (snapshot.ready && snapshot.mode === "per-site" && details.type !== "main_frame") {
					if (onThirdPartyBlocked) onThirdPartyBlocked(details.tabId, details.url);
				}
				return;
			}
			if (details.type !== "xmlhttprequest") return;
			const originHeader = details.requestHeaders?.find((h) => h.name.toLowerCase() === "origin")?.value;
			if (inFlightRequests.size > 100) {
				const oldestKey = inFlightRequests.keys().next().value;
				if (oldestKey !== void 0) inFlightRequests.delete(oldestKey);
			}
			inFlightRequests.set(details.requestId, {
				method: details.method,
				origin: originHeader,
				timestamp: details.timeStamp,
				generation: getTabGeneration(details.tabId)
			});
		}, filter, ["requestHeaders", "extraHeaders"]);
		chrome.webRequest.onErrorOccurred.addListener((details) => {
			inFlightRequests.delete(details.requestId);
			captureMap.delete(details.requestId);
		}, filter);
		chrome.webRequest.onCompleted.addListener((details) => {
			inFlightRequests.delete(details.requestId);
			captureMap.delete(details.requestId);
		}, filter);
	} catch {}
	chrome.webRequest.onHeadersReceived.addListener((details) => {
		if (details.type !== "main_frame" || details.tabId < 0) return;
		if (!isCaptureActiveForUrl(details.url)) return;
		const raw = details.responseHeaders ?? [];
		const isIncog = incognitoTabIds.has(details.tabId) ? true : void 0;
		const partial = {
			tabId: details.tabId,
			url: details.url,
			status: details.statusCode,
			headersReceived: normalizeHeaders(raw),
			rawHeadersReceived: toRawHeaders(raw),
			headersStarted: null,
			rawHeadersStarted: [],
			fromCache: false,
			wasRedirected: false,
			timestamp: details.timeStamp,
			redirectCount: 0,
			isIncognito: isIncog,
			generation: getTabGeneration(details.tabId)
		};
		captureMap.set(details.requestId, partial);
	}, filter, extraInfoSpec);
	chrome.webRequest.onResponseStarted.addListener((details) => {
		if (details.type === "xmlhttprequest" && details.tabId >= 0) {
			const reqMeta = inFlightRequests.get(details.requestId);
			inFlightRequests.delete(details.requestId);
			if (!isCaptureActiveForUrl(details.url)) return;
			if (onApiHopComplete === void 0) return;
			const raw = details.responseHeaders ?? [];
			const apiHeaders = normalizeHeaders(raw);
			const apiRawHeaders = toRawHeaders(raw);
			let normalizedPath;
			try {
				const u = new URL(details.url);
				normalizedPath = u.origin + redactUrlPath(u.pathname);
			} catch {
				normalizedPath = sanitizeUrlForStorage(details.url);
			}
			const sanitizedUrl = sanitizeUrlForStorage(details.url);
			const apiHop = {
				requestId: details.requestId,
				tabId: details.tabId,
				url: sanitizedUrl,
				normalizedPath,
				method: reqMeta?.method ?? "GET",
				requestOrigin: reqMeta?.origin,
				status: details.statusCode,
				headers: apiHeaders,
				rawHeaders: apiRawHeaders,
				timestamp: reqMeta?.timestamp ?? details.timeStamp,
				fromCache: details.fromCache ?? false,
				generation: reqMeta?.generation ?? getTabGeneration(details.tabId)
			};
			const isIncog = incognitoTabIds.has(details.tabId) ? true : void 0;
			try {
				const res = onApiHopComplete(apiHop, isIncog);
				if (res instanceof Promise) res.catch(() => {});
			} catch {}
			return;
		}
		if (details.type !== "main_frame" || details.tabId < 0) return;
		if (!isCaptureActiveForUrl(details.url)) {
			captureMap.delete(details.requestId);
			return;
		}
		const raw = details.responseHeaders ?? [];
		const normalised = normalizeHeaders(raw);
		const rawHeaders = toRawHeaders(raw);
		let partial = captureMap.get(details.requestId);
		if (!partial) {
			const isIncog = incognitoTabIds.has(details.tabId) ? true : void 0;
			partial = {
				tabId: details.tabId,
				url: sanitizeUrlForStorage(details.url),
				status: details.statusCode,
				headersReceived: null,
				rawHeadersReceived: [],
				headersStarted: null,
				rawHeadersStarted: [],
				fromCache: details.fromCache ?? false,
				wasRedirected: false,
				timestamp: details.timeStamp,
				redirectCount: 0,
				isIncognito: isIncog,
				generation: getTabGeneration(details.tabId)
			};
		}
		const sanitizedUrl = sanitizeUrlForStorage(details.url);
		partial.headersStarted = normalised;
		partial.rawHeadersStarted = rawHeaders;
		partial.fromCache = details.fromCache ?? false;
		partial.status = details.statusCode;
		partial.url = sanitizedUrl;
		const canonicalRaw = rawHeaders;
		const canonicalNormalised = normalised;
		const differ = partial.headersReceived !== null ? headersDiffer(partial.headersReceived, canonicalNormalised) : false;
		const hop = {
			requestId: details.requestId,
			url: sanitizedUrl,
			status: details.statusCode,
			headers: canonicalNormalised,
			rawHeaders: canonicalRaw,
			fromCache: partial.fromCache,
			isHstsUpgrade: detectHstsUpgrade(canonicalRaw),
			capturedAt: "onResponseStarted",
			headersDiffer: differ,
			timestamp: partial.timestamp,
			redirectCount: partial.redirectCount,
			generation: partial.generation ?? getTabGeneration(details.tabId)
		};
		captureMap.delete(details.requestId);
		try {
			const res = onHopComplete(details.tabId, hop, partial.isIncognito);
			if (res instanceof Promise) res.catch(() => {});
		} catch {}
	}, filter, extraInfoSpec);
	chrome.webRequest.onBeforeRedirect.addListener((details) => {
		if (details.type !== "main_frame" || details.tabId < 0) return;
		if (!isCaptureActiveForUrl(details.url)) {
			captureMap.delete(details.requestId);
			return;
		}
		const existing = captureMap.get(details.requestId);
		const raw = details.responseHeaders ?? existing?.rawHeadersReceived ?? [];
		const headers = normalizeHeaders(raw);
		const rawHeaders = toRawHeaders(raw);
		const beforeHeaders = existing?.headersReceived;
		const hop = {
			requestId: details.requestId,
			url: sanitizeUrlForStorage(details.url),
			status: details.statusCode,
			headers,
			rawHeaders,
			fromCache: false,
			isHstsUpgrade: detectHstsUpgrade(rawHeaders),
			capturedAt: "onResponseStarted",
			headersDiffer: beforeHeaders !== null && beforeHeaders !== void 0 ? headersDiffer(beforeHeaders, headers) : false,
			timestamp: existing?.timestamp ?? details.timeStamp,
			redirectCount: 0,
			generation: existing?.generation ?? getTabGeneration(details.tabId)
		};
		const isIncog = existing?.isIncognito ?? (incognitoTabIds.has(details.tabId) ? true : void 0);
		captureMap.delete(details.requestId);
		onHopComplete(details.tabId, hop, isIncog);
	}, filter, extraInfoSpec);
}
//#endregion
//#region src/background/lifecycle.ts
/**
* lifecycle.ts
*
* Manages periodic maintenance (via chrome.alarms) and restores
* in-memory tab state from chrome.storage.session after an SW revival.
*
* MV3 service workers are terminated after inactivity. Correctness relies
* entirely on persistent storage and session hydration—never keepalive alarms.
*/
/**
* Primary in-memory store for per-tab security analysis state.
* Keyed by Chrome tabId.  Persisted to chrome.storage.session so it
* survives SW restarts; re-hydrated via hydrateFromSession().
*/
var tabStates = /* @__PURE__ */ new Map();
/**
* In-memory cache for origin pre/post auth baselines.
* Persisted to chrome.storage.session so it survives SW restarts.
*/
var originAuthBaselines = /* @__PURE__ */ new Map();
/**
* Registers the periodic maintenance alarm and its listener.
*
* Runs periodic history pruning sweeps and cleans up expired data.
* Never uses keepalive alarms.
*/
function initLifecycle() {
	if (typeof chrome !== "undefined" && chrome.alarms !== void 0) {
		if (typeof chrome.alarms.get === "function") chrome.alarms.get(MAINTENANCE_ALARM, (existingAlarm) => {
			if (existingAlarm === void 0 || existingAlarm === null) chrome.alarms.create(MAINTENANCE_ALARM, { periodInMinutes: 30 });
		});
		else chrome.alarms.create(MAINTENANCE_ALARM, { periodInMinutes: 30 });
		if (chrome.alarms.onAlarm !== void 0 && typeof chrome.alarms.onAlarm.addListener === "function") chrome.alarms.onAlarm.addListener((alarm) => {
			if (alarm.name === "maintenance") LocalStorage.pruneAllHistory();
		});
	}
}
/**
* Loads all previously persisted TabState records from chrome.storage.session
* into the in-memory {@link tabStates} map.
*
* Must be awaited before registering WebRequest listeners so that any
* in-flight state from before the SW restart is available immediately.
*/
async function hydrateFromSession() {
	const all = await SessionStorage.getAllTabStates();
	for (const state of all) {
		const existing = tabStates.get(state.tabId);
		if (!existing || state.updatedAt > existing.updatedAt) tabStates.set(state.tabId, state);
		if (state.navigationGeneration !== void 0 && state.navigationGeneration > 0) setTabGeneration(state.tabId, state.navigationGeneration);
		if (state.isIncognito === true) incognitoTabIds.add(state.tabId);
	}
	const baselines = await SessionStorage.getAllAuthBaselines();
	for (const [key, baseline] of baselines) if (!originAuthBaselines.has(key)) originAuthBaselines.set(key, baseline);
	LocalStorage.pruneAllHistory();
}
//#endregion
export { tabGenerations as C, setTabGeneration as S, isModeCaptureAllowed as _, captureMap as a, getTabGeneration as b, incognitoTabIds as c, PermissionsService as d, hasAllSitesCoverage as f, reconcilePermissionsOnStartup as g, reconcilePermissionsOnRemoved as h, tabStates as i, registerCaptureListeners as l, patternFromOrigin as m, initLifecycle as n, clearInFlightCaptures as o, isBroadGrant as p, originAuthBaselines as r, inFlightRequests as s, hydrateFromSession as t, CapturePolicy as u, isRestrictedUrl as v, incrementTabGeneration as x, clearTabGenerations as y };

//# sourceMappingURL=lifecycle-CVNvjeon.js.map