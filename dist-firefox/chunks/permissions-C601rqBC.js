import { c as KEEPALIVE_PERIOD_MINUTES, s as KEEPALIVE_ALARM } from "./messaging-BCRf7spF.js";
import { n as SessionStorage } from "./storage-DkrZ3D78.js";
import { d as redactUrlQueryParams, i as headersDiffer, l as redactHeaderValue, o as normalizeHeaders, u as redactUrlPath } from "./utils-DgBLspgH.js";
//#region src/background/lifecycle.ts
/**
* lifecycle.ts
*
* Manages MV3 service-worker keepalive (via chrome.alarms) and restores
* in-memory tab state from chrome.storage.session after an SW revival.
*
* MV3 service workers are terminated after ~30 s of inactivity.  Firing a
* periodic alarm forces the browser to wake the worker so it can keep
* processing WebRequest events without dropping state.
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
* Registers the recurring keepalive alarm and its listener.
*
* Call once at SW startup (both fresh install and revival).
* chrome.alarms.create is idempotent for a given name — calling it again
* while the alarm already exists simply resets the period, which is fine.
*/
function initLifecycle() {
	chrome.alarms.create(KEEPALIVE_ALARM, { periodInMinutes: KEEPALIVE_PERIOD_MINUTES });
	chrome.alarms.onAlarm.addListener((alarm) => {
		if (alarm.name === "keepalive") {}
	});
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
	for (const state of all) tabStates.set(state.tabId, state);
	const baselines = await SessionStorage.getAllAuthBaselines();
	for (const [origin, baseline] of baselines) originAuthBaselines.set(origin, baseline);
}
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
/**
* Keyed by Chrome's `requestId`.  Entries are created on onHeadersReceived
* and deleted after onResponseStarted finishes processing.
*/
var captureMap = /* @__PURE__ */ new Map();
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
* Registers all WebRequest listeners needed to capture response hops.
*
* @param onHopComplete - Callback invoked for every captured response, including
*   intermediate redirect responses.
* @param onApiHopComplete - Optional callback invoked for each captured XHR/Fetch response.
*/
function registerCaptureListeners(onHopComplete, onApiHopComplete) {
	const filter = { urls: ["<all_urls>"] };
	const extraInfoSpec = ["responseHeaders", "extraHeaders"];
	const inFlightRequests = /* @__PURE__ */ new Map();
	try {
		chrome.webRequest.onBeforeSendHeaders.addListener((details) => {
			if (details.type !== "xmlhttprequest" || details.tabId < 0) return;
			const originHeader = details.requestHeaders?.find((h) => h.name.toLowerCase() === "origin")?.value;
			if (inFlightRequests.size > 100) {
				const oldestKey = inFlightRequests.keys().next().value;
				if (oldestKey !== void 0) inFlightRequests.delete(oldestKey);
			}
			inFlightRequests.set(details.requestId, {
				method: details.method,
				origin: originHeader,
				timestamp: details.timeStamp
			});
		}, filter, ["requestHeaders", "extraHeaders"]);
		chrome.webRequest.onErrorOccurred.addListener((details) => {
			inFlightRequests.delete(details.requestId);
		}, filter);
		chrome.webRequest.onCompleted.addListener((details) => {
			inFlightRequests.delete(details.requestId);
		}, filter);
	} catch {}
	chrome.webRequest.onHeadersReceived.addListener((details) => {
		if (details.type !== "main_frame" || details.tabId < 0) return;
		const raw = details.responseHeaders ?? [];
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
			redirectCount: 0
		};
		captureMap.set(details.requestId, partial);
	}, filter, extraInfoSpec);
	chrome.webRequest.onResponseStarted.addListener((details) => {
		if (details.type === "xmlhttprequest" && details.tabId >= 0) {
			if (onApiHopComplete !== void 0) {
				const reqMeta = inFlightRequests.get(details.requestId);
				inFlightRequests.delete(details.requestId);
				const raw = details.responseHeaders ?? [];
				const apiHeaders = normalizeHeaders(raw);
				const apiRawHeaders = toRawHeaders(raw);
				let normalizedPath;
				try {
					const u = new URL(details.url);
					normalizedPath = u.origin + redactUrlPath(u.pathname);
				} catch {
					normalizedPath = redactUrlQueryParams(details.url);
				}
				const sanitizedUrl = redactUrlQueryParams(details.url);
				onApiHopComplete({
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
					fromCache: details.fromCache ?? false
				});
			}
			return;
		}
		if (details.type !== "main_frame" || details.tabId < 0) return;
		const raw = details.responseHeaders ?? [];
		const normalised = normalizeHeaders(raw);
		const rawHeaders = toRawHeaders(raw);
		let partial = captureMap.get(details.requestId);
		if (!partial) partial = {
			tabId: details.tabId,
			url: redactUrlQueryParams(details.url),
			status: details.statusCode,
			headersReceived: null,
			rawHeadersReceived: [],
			headersStarted: null,
			rawHeadersStarted: [],
			fromCache: details.fromCache ?? false,
			wasRedirected: false,
			timestamp: details.timeStamp,
			redirectCount: 0
		};
		const sanitizedUrl = redactUrlQueryParams(details.url);
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
			redirectCount: partial.redirectCount
		};
		captureMap.delete(details.requestId);
		onHopComplete(details.tabId, hop);
	}, filter, extraInfoSpec);
	chrome.webRequest.onBeforeRedirect.addListener((details) => {
		if (details.type !== "main_frame" || details.tabId < 0) return;
		const existing = captureMap.get(details.requestId);
		const raw = details.responseHeaders ?? existing?.rawHeadersReceived ?? [];
		const headers = normalizeHeaders(raw);
		const rawHeaders = toRawHeaders(raw);
		const beforeHeaders = existing?.headersReceived;
		const hop = {
			requestId: details.requestId,
			url: redactUrlQueryParams(details.url),
			status: details.statusCode,
			headers,
			rawHeaders,
			fromCache: false,
			isHstsUpgrade: detectHstsUpgrade(rawHeaders),
			capturedAt: "onResponseStarted",
			headersDiffer: beforeHeaders !== null && beforeHeaders !== void 0 ? headersDiffer(beforeHeaders, headers) : false,
			timestamp: existing?.timestamp ?? details.timeStamp,
			redirectCount: 0
		};
		captureMap.delete(details.requestId);
		onHopComplete(details.tabId, hop);
	}, filter, extraInfoSpec);
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
var PermissionsService = {
	/**
	* Queries chrome.permissions.getAll() and returns true if any broad grant exists.
	*/
	async isBroadGrantPresent() {
		if (typeof chrome === "undefined" || typeof chrome.permissions === "undefined") return false;
		return ((await chrome.permissions.getAll()).origins ?? []).some((o) => isBroadGrant(o));
	},
	/**
	* Authoritative query: returns all explicitly granted origins (excluding broad patterns).
	* Normalizes patterns to canonical origins (e.g., https://example.com).
	*/
	async getAllGrantedOrigins() {
		if (typeof chrome === "undefined" || typeof chrome.permissions === "undefined") return [];
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
		const pattern = `${normalizePermissionOrigin(origin)}/*`;
		return new Promise((resolve) => {
			chrome.permissions.contains({ origins: [pattern] }, resolve);
		});
	},
	/**
	* Revokes host permission for a specific origin.
	*/
	async removeOriginPermission(origin) {
		if (!origin || typeof chrome === "undefined" || typeof chrome.permissions === "undefined") return false;
		const pattern = `${normalizePermissionOrigin(origin)}/*`;
		return new Promise((resolve) => {
			chrome.permissions.remove({ origins: [pattern] }, resolve);
		});
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
*/
async function reconcilePermissionsOnRemoved(removedOrigins, options) {
	const isBroadRemoved = removedOrigins.some((o) => isBroadGrant(o));
	const clearedTabIds = [];
	const targetTabStates = options?.tabStates ?? tabStates;
	const isBroadActive = options?.isBroadGrantActive !== void 0 ? await options.isBroadGrantActive() : await PermissionsService.isBroadGrantPresent();
	if (isBroadActive) return clearedTabIds;
	const activeOrigins = options?.getActiveOrigins !== void 0 ? await options.getActiveOrigins() : await PermissionsService.getAllGrantedOrigins();
	const activeOriginSet = new Set(activeOrigins.map(normalizePermissionOrigin));
	for (const [tabId, state] of Array.from(targetTabStates.entries())) {
		const tabOrigin = normalizePermissionOrigin(state.origin);
		if (!(isBroadActive || activeOriginSet.has(tabOrigin)) || isBroadRemoved) {
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
		if (!(isBroadActive || activeOriginSet.has(tabOrigin))) {
			await clearTabCapture(tabId, options);
			clearedTabIds.push(tabId);
		}
	}
	return clearedTabIds;
}
//#endregion
export { registerCaptureListeners as a, originAuthBaselines as c, captureMap as i, tabStates as l, reconcilePermissionsOnRemoved as n, hydrateFromSession as o, reconcilePermissionsOnStartup as r, initLifecycle as s, PermissionsService as t };

//# sourceMappingURL=permissions-C601rqBC.js.map