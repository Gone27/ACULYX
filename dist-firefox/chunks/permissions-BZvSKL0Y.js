import { D as STORAGE_KEYS, a as registrableDomain, d as normalizeHeaders, g as redactUrlQueryParams, h as redactUrlPath, l as headersDiffer, m as redactHeaderValue, x as MAINTENANCE_ALARM, y as DEFAULT_SETTINGS } from "./messaging-cpmoITPm.js";
//#region src/shared/settings.ts
/**
* settings.ts
*
* Single settings service and authoritative read/write path for extension settings.
* Enforces schema v2 validation, idempotent migration from legacy v1 shapes,
* in-memory caching with storage.onChanged invalidation, and change subscriptions.
*/
var VALID_MODES = /* @__PURE__ */ new Set([
	"per-site",
	"all-sites",
	"off"
]);
var VALID_SEVERITIES = /* @__PURE__ */ new Set([
	"critical",
	"high",
	"medium",
	"low",
	"info",
	"pass"
]);
/**
* Normalizes a list of cookie names: trims whitespace, lowercases, and deduplicates.
*/
function normalizeCookieList(names) {
	if (!Array.isArray(names)) return [];
	const set = /* @__PURE__ */ new Set();
	for (const item of names) if (typeof item === "string") {
		const trimmed = item.trim().toLowerCase();
		if (trimmed.length > 0) set.add(trimmed);
	}
	return Array.from(set);
}
/**
* Resolves overlaps between sensitive and ignored cookie lists.
* Invariant: if a cookie name is in both lists, "ignored" wins.
*/
function resolveCookieOverlaps(sensitive, ignored) {
	const ignoredSet = new Set(ignored);
	const overlaps = [];
	const filteredSensitive = [];
	for (const name of sensitive) if (ignoredSet.has(name)) overlaps.push(name);
	else filteredSensitive.push(name);
	return {
		sensitive: filteredSensitive,
		ignored,
		overlaps
	};
}
/**
* Clamps an integer value to [min, max]. Falls back to defaultValue if invalid.
*/
function clampNumber(val, min, max, defaultValue) {
	if (typeof val !== "number" || !Number.isFinite(val)) {
		if (typeof val === "string") {
			const parsed = parseInt(val, 10);
			if (Number.isFinite(parsed)) return Math.max(min, Math.min(max, parsed));
		}
		return defaultValue;
	}
	return Math.max(min, Math.min(max, Math.round(val)));
}
/**
* Sanitizes and validates a severity filter array.
*/
function sanitizeSeverityFilter(raw) {
	if (!Array.isArray(raw)) return [...DEFAULT_SETTINGS.severityFilter];
	const filtered = raw.filter((s) => typeof s === "string" && VALID_SEVERITIES.has(s));
	return filtered.length > 0 ? Array.from(new Set(filtered)) : [...DEFAULT_SETTINGS.severityFilter];
}
var UnsupportedSchemaError = class extends Error {
	version;
	constructor(version) {
		super(`Unsupported settings schema version: ${version}`);
		this.version = version;
		this.name = "UnsupportedSchemaError";
	}
};
/**
* Idempotently migrates any raw/legacy settings object to canonical SettingsV2.
* Preserves all valid existing v1 settings without dropping user preferences.
* Throws UnsupportedSchemaError if given a future schema version (> 2).
*/
function migrateSettings(raw) {
	if (raw == null || typeof raw !== "object") return { ...DEFAULT_SETTINGS };
	const obj = raw;
	if (typeof obj.schemaVersion === "number" && obj.schemaVersion > 2) throw new UnsupportedSchemaError(obj.schemaVersion);
	let monitoringMode = DEFAULT_SETTINGS.monitoringMode;
	if (typeof obj.monitoringMode === "string" && VALID_MODES.has(obj.monitoringMode)) monitoringMode = obj.monitoringMode;
	const severityFilter = sanitizeSeverityFilter(obj.severityFilter);
	const retainHistoryDays = clampNumber(obj.retainHistoryDays, 0, 365, DEFAULT_SETTINGS.retainHistoryDays);
	const maxHistoryPerOrigin = clampNumber(obj.maxHistoryPerOrigin, 1, 50, DEFAULT_SETTINGS.maxHistoryPerOrigin);
	const rawSensitive = obj.sensitiveCookieNames ?? obj.alwaysSensitiveCookies;
	const rawIgnored = obj.ignoredCookieNames ?? obj.alwaysIgnoreCookies;
	const { sensitive, ignored } = resolveCookieOverlaps(normalizeCookieList(rawSensitive), normalizeCookieList(rawIgnored));
	const evaluationMode = typeof obj.evaluationMode === "boolean" ? obj.evaluationMode : typeof obj.isPro === "boolean" ? obj.isPro : DEFAULT_SETTINGS.evaluationMode;
	let legacyAllowedOrigins;
	if (Array.isArray(obj.allowedOrigins) && obj.allowedOrigins.length > 0) legacyAllowedOrigins = obj.allowedOrigins.filter((o) => typeof o === "string" && o.trim().length > 0).map((o) => o.trim());
	else if (Array.isArray(obj.legacyAllowedOrigins) && obj.legacyAllowedOrigins.length > 0) legacyAllowedOrigins = obj.legacyAllowedOrigins.filter((o) => typeof o === "string" && o.trim().length > 0).map((o) => o.trim());
	const result = {
		schemaVersion: 2,
		monitoringMode,
		severityFilter,
		retainHistoryDays,
		maxHistoryPerOrigin,
		sensitiveCookieNames: sensitive,
		ignoredCookieNames: ignored,
		evaluationMode
	};
	if (legacyAllowedOrigins !== void 0 && legacyAllowedOrigins.length > 0) result.legacyAllowedOrigins = legacyAllowedOrigins;
	return result;
}
var cachedSettings = null;
var hydrationPromise = null;
var listeners = /* @__PURE__ */ new Set();
var storageListenerRegistered = false;
function ensureStorageListener() {
	if (storageListenerRegistered || typeof chrome === "undefined" || typeof chrome.storage === "undefined" || typeof chrome.storage.onChanged === "undefined") return;
	chrome.storage.onChanged.addListener((changes, areaName) => {
		const change = changes[STORAGE_KEYS.SETTINGS];
		if (areaName === "local" && change !== void 0) {
			const newRaw = change.newValue;
			try {
				cachedSettings = migrateSettings(newRaw);
			} catch {
				cachedSettings = {
					...DEFAULT_SETTINGS,
					monitoringMode: "off"
				};
			}
			for (const cb of listeners) try {
				cb(cachedSettings);
			} catch {}
		}
	});
	storageListenerRegistered = true;
}
var SettingsService = {
	/**
	* Reads settings from memory cache or chrome.storage.local.
	* Auto-migrates and writes back if legacy schema is detected.
	* Fails closed if storage read throws or future schema version is encountered.
	*/
	async getSettings() {
		ensureStorageListener();
		if (cachedSettings !== null) return { ...cachedSettings };
		if (hydrationPromise !== null) return hydrationPromise.then((s) => ({ ...s }));
		if (typeof chrome === "undefined" || typeof chrome.storage === "undefined" || typeof chrome.storage.local === "undefined") {
			cachedSettings = { ...DEFAULT_SETTINGS };
			return { ...cachedSettings };
		}
		hydrationPromise = (async () => {
			try {
				const raw = (await chrome.storage.local.get(STORAGE_KEYS.SETTINGS))[STORAGE_KEYS.SETTINGS];
				if (typeof raw === "object" && raw !== null && typeof raw["schemaVersion"] === "number" && raw["schemaVersion"] > 2) throw new UnsupportedSchemaError(raw["schemaVersion"]);
				const migrated = migrateSettings(raw);
				if (!(typeof raw === "object" && raw !== null && raw["schemaVersion"] === 2)) await chrome.storage.local.set({ [STORAGE_KEYS.SETTINGS]: migrated });
				cachedSettings = migrated;
				return { ...migrated };
			} catch (err) {
				cachedSettings = {
					...DEFAULT_SETTINGS,
					monitoringMode: "off"
				};
				throw err;
			} finally {
				hydrationPromise = null;
			}
		})();
		return hydrationPromise.then((s) => ({ ...s }));
	},
	/**
	* Returns a promise that resolves to valid hydrated settings, failing closed to Off mode.
	*/
	async whenReady() {
		if (cachedSettings !== null) return { ...cachedSettings };
		try {
			return await this.getSettings();
		} catch {
			return this.getCachedSettings();
		}
	},
	/**
	* Validates and applies a patch to current settings, writes to storage, and returns updated settings.
	*/
	async updateSettings(patch) {
		ensureStorageListener();
		if (typeof chrome !== "undefined" && typeof chrome.storage !== "undefined" && typeof chrome.storage.local !== "undefined") {
			const raw = (await chrome.storage.local.get(STORAGE_KEYS.SETTINGS))[STORAGE_KEYS.SETTINGS];
			if (typeof raw === "object" && raw !== null && typeof raw["schemaVersion"] === "number" && raw["schemaVersion"] > 2) throw new UnsupportedSchemaError(raw["schemaVersion"]);
		}
		const merged = migrateSettings({
			...await this.whenReady(),
			...patch,
			schemaVersion: 2
		});
		if (typeof chrome !== "undefined" && typeof chrome.storage !== "undefined" && typeof chrome.storage.local !== "undefined") await chrome.storage.local.set({ [STORAGE_KEYS.SETTINGS]: merged });
		cachedSettings = merged;
		for (const cb of listeners) try {
			cb(merged);
		} catch {}
		return { ...merged };
	},
	/**
	* Subscribes to settings updates. Returns an unsubscribe function.
	*/
	onSettingsChanged(cb) {
		ensureStorageListener();
		listeners.add(cb);
		return () => {
			listeners.delete(cb);
		};
	},
	/**
	* Returns in-memory cached settings synchronously, or fail-closed (mode off) if not yet loaded.
	*/
	getCachedSettings() {
		if (cachedSettings !== null) return { ...cachedSettings };
		if (typeof chrome === "undefined" || typeof chrome.storage === "undefined" || typeof chrome.storage.local === "undefined") return { ...DEFAULT_SETTINGS };
		return {
			...DEFAULT_SETTINGS,
			monitoringMode: "off"
		};
	},
	/**
	* Resets the in-memory cache (primarily for unit tests).
	*/
	clearCache() {
		cachedSettings = null;
		hydrationPromise = null;
	}
};
//#endregion
//#region src/shared/storage.ts
function serializeTabState(state) {
	const { apiEndpoints, ...rest } = state;
	if (apiEndpoints !== void 0) return {
		...rest,
		apiEndpoints: Array.from(apiEndpoints.entries())
	};
	return rest;
}
function deserializeTabState(raw) {
	const { apiEndpoints, ...rest } = raw;
	if (Array.isArray(apiEndpoints)) return {
		...rest,
		apiEndpoints: new Map(apiEndpoints)
	};
	return rest;
}
function hasUnredactedCookieValue(headerStr, isSetCookie = false) {
	if (!headerStr) return false;
	if (isSetCookie) {
		const lines = headerStr.split(/\r?\n/);
		for (const line of lines) {
			const semiIdx = line.indexOf(";");
			const firstPart = semiIdx !== -1 ? line.slice(0, semiIdx) : line;
			const eqIdx = firstPart.indexOf("=");
			if (eqIdx !== -1) {
				const val = firstPart.slice(eqIdx + 1).trim();
				if (val !== "" && val !== "[REDACTED]" && val !== "[redacted]") return true;
			}
		}
		return false;
	}
	const parts = headerStr.split(";");
	for (const part of parts) {
		const trimmed = part.trim();
		if (!trimmed) continue;
		const eqIdx = trimmed.indexOf("=");
		if (eqIdx !== -1) {
			const val = trimmed.slice(eqIdx + 1).trim();
			if (val !== "" && val !== "[REDACTED]" && val !== "[redacted]") return true;
		}
	}
	return false;
}
function assertNoSensitiveSecrets(state) {
	if (Array.isArray(state.cookies)) {
		for (const cookie of state.cookies) if ("value" in cookie) throw new Error(`[SecCheck] Cookie value detected on ${cookie.name} — storage aborted.`);
	}
	const checkHeaders = (headers, rawHeaders, context) => {
		if (headers) for (const [k, v] of Object.entries(headers)) {
			const lower = k.toLowerCase();
			if (lower === "set-cookie" || lower === "cookie") {
				if (hasUnredactedCookieValue(v, lower === "set-cookie")) throw new Error(`[SecCheck] Unredacted ${k} header detected in ${context} — storage aborted.`);
			} else if (lower === "authorization" || lower === "proxy-authorization") {
				if (v !== "[REDACTED]" && v !== "[redacted]") throw new Error(`[SecCheck] Unredacted ${k} header detected in ${context} — storage aborted.`);
			}
		}
		if (rawHeaders) for (const h of rawHeaders) {
			const lower = h.name.toLowerCase();
			if (lower === "set-cookie" || lower === "cookie") {
				if (hasUnredactedCookieValue(h.value, lower === "set-cookie")) throw new Error(`[SecCheck] Unredacted ${h.name} rawHeader detected in ${context} — storage aborted.`);
			} else if (lower === "authorization" || lower === "proxy-authorization") {
				if (h.value !== "[REDACTED]" && h.value !== "[redacted]") throw new Error(`[SecCheck] Unredacted ${h.name} rawHeader detected in ${context} — storage aborted.`);
			}
		}
	};
	if (Array.isArray(state.hops)) for (let i = 0; i < state.hops.length; i++) {
		const hop = state.hops[i];
		if (hop) checkHeaders(hop.headers, hop.rawHeaders, `hop[${i}]`);
	}
	if (state.apiEndpoints instanceof Map) for (const [path, endpoint] of state.apiEndpoints.entries()) checkHeaders(endpoint.lastHop.headers, endpoint.lastHop.rawHeaders, `apiEndpoint[${path}]`);
}
var SessionStorage = {
	async getTabState(tabId) {
		const key = `${STORAGE_KEYS.TAB_PREFIX}${tabId}`;
		const raw = (await chrome.storage.session.get(key))[key];
		if (raw === void 0) return null;
		return deserializeTabState(raw);
	},
	async setTabState(state) {
		assertNoSensitiveSecrets(state);
		const serialized = serializeTabState(state);
		const key = `${STORAGE_KEYS.TAB_PREFIX}${state.tabId}`;
		await chrome.storage.session.set({ [key]: serialized });
	},
	async removeTabState(tabId) {
		const key = `${STORAGE_KEYS.TAB_PREFIX}${tabId}`;
		await chrome.storage.session.remove(key);
	},
	async clearAllTabStates() {
		if (typeof chrome === "undefined" || typeof chrome.storage === "undefined" || typeof chrome.storage.session === "undefined") return;
		const all = await chrome.storage.session.get(null);
		const tabKeys = Object.keys(all).filter((k) => k.startsWith(STORAGE_KEYS.TAB_PREFIX));
		if (tabKeys.length > 0) await chrome.storage.session.remove(tabKeys);
	},
	async getAllTabStates() {
		const all = await chrome.storage.session.get(null);
		return Object.entries(all).filter(([k]) => k.startsWith(STORAGE_KEYS.TAB_PREFIX)).map(([, v]) => deserializeTabState(v));
	},
	async getAuthBaseline(origin) {
		if (!origin) return null;
		const key = `${STORAGE_KEYS.AUTH_BASELINE_PREFIX}${origin}`;
		return (await chrome.storage.session.get(key))[key] ?? null;
	},
	async setAuthBaseline(origin, baseline) {
		if (!origin) return;
		const key = `${STORAGE_KEYS.AUTH_BASELINE_PREFIX}${origin}`;
		await chrome.storage.session.set({ [key]: baseline });
	},
	async getAllAuthBaselines() {
		const all = await chrome.storage.session.get(null);
		const map = /* @__PURE__ */ new Map();
		for (const [k, v] of Object.entries(all)) if (k.startsWith(STORAGE_KEYS.AUTH_BASELINE_PREFIX)) {
			const origin = k.slice(STORAGE_KEYS.AUTH_BASELINE_PREFIX.length);
			map.set(origin, v);
		}
		return map;
	}
};
var DEFAULT_MAX_HISTORY_PER_ORIGIN = 10;
/**
* Pure function to prune origin history items according to age and count policies.
*
* Precedence (Contract Section 5.1):
* 1. Age pruning (retainHistoryDays): if > 0, prune items older than retainHistoryDays * 86,400,000 ms.
*    If 0, keep forever (age pruning disabled).
* 2. Count cap (maxHistoryPerOrigin): keep at most maxHistoryPerOrigin newest items (default 10, range 1..50).
*/
function pruneHistoryItems(items, now, retainHistoryDays, maxHistoryPerOrigin = DEFAULT_MAX_HISTORY_PER_ORIGIN) {
	let filtered = [...items];
	if (retainHistoryDays > 0) {
		const cutoff = now - retainHistoryDays * 24 * 60 * 60 * 1e3;
		filtered = filtered.filter((item) => item.timestamp >= cutoff);
	}
	const cap = Math.max(1, Math.min(50, Math.floor(typeof maxHistoryPerOrigin === "number" && !Number.isNaN(maxHistoryPerOrigin) ? maxHistoryPerOrigin : DEFAULT_MAX_HISTORY_PER_ORIGIN)));
	if (filtered.length > cap) filtered = filtered.slice(-cap);
	return filtered;
}
var LocalStorage = {
	async getSettings() {
		return await SettingsService.getSettings();
	},
	async setSettings(settings) {
		await SettingsService.updateSettings(settings);
	},
	async getOriginHistory(origin) {
		if (!origin) return [];
		const key = `${STORAGE_KEYS.HISTORY_PREFIX}${origin}`;
		return (await chrome.storage.local.get(key))[key] ?? [];
	},
	async recordOriginHistory(origin, item) {
		if (!origin) return;
		const history = await this.getOriginHistory(origin);
		const last = history[history.length - 1];
		if (last && last.score === item.score && last.grade === item.grade && item.timestamp - last.timestamp < 6e4) return;
		const settings = await this.getSettings();
		const updated = pruneHistoryItems([...history, item], item.timestamp, settings.retainHistoryDays, settings.maxHistoryPerOrigin);
		const key = `${STORAGE_KEYS.HISTORY_PREFIX}${origin}`;
		await chrome.storage.local.set({ [key]: updated });
	},
	async pruneAllHistory(now = Date.now(), settings) {
		if (typeof chrome === "undefined" || chrome.storage?.local === void 0) return;
		const currentSettings = settings ?? await this.getSettings();
		const all = await chrome.storage.local.get(null);
		const updates = {};
		const toRemove = [];
		for (const [key, value] of Object.entries(all)) if (key.startsWith(STORAGE_KEYS.HISTORY_PREFIX) || key.startsWith("history:")) {
			if (Array.isArray(value)) {
				const pruned = pruneHistoryItems(value, now, currentSettings.retainHistoryDays, currentSettings.maxHistoryPerOrigin);
				if (pruned.length === 0) toRemove.push(key);
				else updates[key] = pruned;
			}
		}
		if (Object.keys(updates).length > 0) await chrome.storage.local.set(updates);
		if (toRemove.length > 0) await chrome.storage.local.remove(toRemove);
	},
	async purgeOriginData(origin) {
		if (!origin || typeof chrome === "undefined" || chrome.storage?.local === void 0) return;
		const keysToRemove = [
			`${STORAGE_KEYS.HISTORY_PREFIX}${origin}`,
			`history:${origin}`,
			`${STORAGE_KEYS.AUTH_DIFF_PREFIX}${origin}`,
			`${STORAGE_KEYS.AUTH_BASELINE_PREFIX}${origin}`
		];
		let hostname = origin;
		try {
			hostname = new URL(origin).hostname;
		} catch {}
		const apex = registrableDomain(hostname) ?? hostname;
		if (apex) {
			if (hostname === apex) keysToRemove.push(`${STORAGE_KEYS.GRAPH_PREFIX}${apex}`);
			else {
				const graph = await this.getGraph(apex);
				if (graph) {
					graph.nodes = graph.nodes.filter((n) => n.hostname !== hostname);
					graph.edges = graph.edges.filter((e) => e.source !== hostname && e.target !== hostname);
					if (graph.nodes.length <= 1 && graph.nodes.every((n) => n.isApex)) keysToRemove.push(`${STORAGE_KEYS.GRAPH_PREFIX}${apex}`);
					else await this.saveGraph(graph);
				}
			}
		}
		if (hostname && hostname !== apex) keysToRemove.push(`${STORAGE_KEYS.GRAPH_PREFIX}${hostname}`);
		await chrome.storage.local.remove(keysToRemove);
		if (typeof chrome !== "undefined" && chrome.storage?.session !== void 0) await chrome.storage.session.remove(`${STORAGE_KEYS.AUTH_BASELINE_PREFIX}${origin}`).catch(() => {});
	},
	async getAuthDiffHistory(origin) {
		if (!origin) return [];
		const key = `${STORAGE_KEYS.AUTH_DIFF_PREFIX}${origin}`;
		return (await chrome.storage.local.get(key))[key] ?? [];
	},
	async getLatestAuthDiff(origin) {
		const list = await this.getAuthDiffHistory(origin);
		return list.length > 0 ? list[list.length - 1] ?? null : null;
	},
	async recordAuthDiff(origin, diff) {
		if (!origin) return;
		const updated = [...await this.getAuthDiffHistory(origin), diff].slice(-10);
		const key = `${STORAGE_KEYS.AUTH_DIFF_PREFIX}${origin}`;
		await chrome.storage.local.set({ [key]: updated });
	},
	async getGraph(apexDomain) {
		if (!apexDomain) return null;
		const key = `${STORAGE_KEYS.GRAPH_PREFIX}${apexDomain}`;
		return (await chrome.storage.local.get(key))[key] ?? null;
	},
	async saveGraph(graph) {
		if (!graph.apexDomain) return;
		const key = `${STORAGE_KEYS.GRAPH_PREFIX}${graph.apexDomain}`;
		await chrome.storage.local.set({ [key]: graph });
	},
	async isOnboardingDismissed() {
		const result = await chrome.storage.local.get(STORAGE_KEYS.ONBOARDING_DISMISSED);
		return Boolean(result[STORAGE_KEYS.ONBOARDING_DISMISSED]);
	},
	async setOnboardingDismissed(dismissed) {
		await chrome.storage.local.set({ [STORAGE_KEYS.ONBOARDING_DISMISSED]: dismissed });
	},
	async clearAll() {
		await chrome.storage.local.clear();
	}
};
//#endregion
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
* Registers the periodic maintenance alarm and its listener.
*
* Runs periodic history pruning sweeps and cleans up expired data.
*/
function initLifecycle() {
	chrome.alarms.create(MAINTENANCE_ALARM, { periodInMinutes: 1 });
	chrome.alarms.onAlarm.addListener((alarm) => {
		if (alarm.name === "maintenance" || alarm.name === "keepalive") LocalStorage.pruneAllHistory();
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
	LocalStorage.pruneAllHistory();
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
function isModeCaptureAllowed(url, settings, broadGrantPresent, options) {
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
	return {
		allowed: true,
		reason: "ok"
	};
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
* Returns false if mode is off, unhydrated, or URL is a restricted scheme.
*/
function isCaptureActiveForUrl(url) {
	if (!url || isRestrictedUrl(url)) return false;
	return SettingsService.getCachedSettings().monitoringMode !== "off";
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
	try {
		chrome.webRequest.onBeforeSendHeaders.addListener((details) => {
			if (details.type !== "xmlhttprequest" || details.tabId < 0) return;
			if (!isCaptureActiveForUrl(details.url)) return;
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
		if (typeof chrome === "undefined" || typeof chrome.permissions === "undefined" || typeof chrome.permissions.getAll === "undefined") return false;
		return ((await chrome.permissions.getAll()).origins ?? []).some((o) => isBroadGrant(o));
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
		if (!activeOriginSet.has(tabOrigin)) {
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
export { normalizeCookieList as _, captureMap as a, isModeCaptureAllowed as c, initLifecycle as d, originAuthBaselines as f, SettingsService as g, SessionStorage as h, reconcilePermissionsOnStartup as i, isRestrictedUrl as l, LocalStorage as m, isBroadGrant as n, clearInFlightCaptures as o, tabStates as p, reconcilePermissionsOnRemoved as r, registerCaptureListeners as s, PermissionsService as t, hydrateFromSession as u, resolveCookieOverlaps as v };

//# sourceMappingURL=permissions-BZvSKL0Y.js.map