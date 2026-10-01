import { a as DEFAULT_SETTINGS, m as STORAGE_KEYS } from "./messaging-BCRf7spF.js";
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
/**
* Idempotently migrates any raw/legacy settings object to canonical SettingsV2.
* Preserves all valid existing v1 settings without dropping user preferences.
*/
function migrateSettings(raw) {
	if (raw == null || typeof raw !== "object") return { ...DEFAULT_SETTINGS };
	const obj = raw;
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
var listeners = /* @__PURE__ */ new Set();
var storageListenerRegistered = false;
function ensureStorageListener() {
	if (storageListenerRegistered || typeof chrome === "undefined" || typeof chrome.storage === "undefined" || typeof chrome.storage.onChanged === "undefined") return;
	chrome.storage.onChanged.addListener((changes, areaName) => {
		const change = changes[STORAGE_KEYS.SETTINGS];
		if (areaName === "local" && change !== void 0) {
			const newRaw = change.newValue;
			cachedSettings = migrateSettings(newRaw);
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
	*/
	async getSettings() {
		ensureStorageListener();
		if (cachedSettings !== null) return { ...cachedSettings };
		if (typeof chrome === "undefined" || typeof chrome.storage === "undefined" || typeof chrome.storage.local === "undefined") {
			cachedSettings = { ...DEFAULT_SETTINGS };
			return { ...cachedSettings };
		}
		const raw = (await chrome.storage.local.get(STORAGE_KEYS.SETTINGS))[STORAGE_KEYS.SETTINGS];
		const migrated = migrateSettings(raw);
		if (!(typeof raw === "object" && raw !== null && raw["schemaVersion"] === 2)) await chrome.storage.local.set({ [STORAGE_KEYS.SETTINGS]: migrated });
		cachedSettings = migrated;
		return { ...migrated };
	},
	/**
	* Validates and applies a patch to current settings, writes to storage, and returns updated settings.
	*/
	async updateSettings(patch) {
		ensureStorageListener();
		const merged = migrateSettings({
			...await this.getSettings(),
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
	* Resets the in-memory cache (primarily for unit tests).
	*/
	clearCache() {
		cachedSettings = null;
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
		const updated = [...history, item].slice(-10);
		const key = `${STORAGE_KEYS.HISTORY_PREFIX}${origin}`;
		await chrome.storage.local.set({ [key]: updated });
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
export { resolveCookieOverlaps as a, normalizeCookieList as i, SessionStorage as n, SettingsService as r, LocalStorage as t };

//# sourceMappingURL=storage-DkrZ3D78.js.map