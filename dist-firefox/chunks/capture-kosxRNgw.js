import { D as STORAGE_KEYS, a as registrableDomain, d as normalizeHeaders, f as originFromUrl, g as redactUrlQueryParams, h as redactUrlPath, l as headersDiffer, m as redactHeaderValue, x as MAINTENANCE_ALARM, y as DEFAULT_SETTINGS } from "./messaging-BtJyJf3R.js";
//#region src/shared/settings.ts
/**
* settings.ts
*
* Single settings service and authoritative read/write path for extension settings.
* Enforces schema v2 validation, idempotent migration from legacy v1 shapes,
* in-memory caching with storage.onChanged invalidation, and change subscriptions.
*
* WS1: Implements atomic settings transitions via SettingsTransitionPipeline with
* lastAppliedSettings snapshot and delta detection for cookie list changes and mode transitions.
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
* Detects whether cookie lists (sensitive or ignored) have changed between two settings versions.
*/
function haveCookieListsChanged(prev, next) {
	const prevSens = prev.sensitiveCookieNames ?? prev.alwaysSensitiveCookies ?? [];
	const nextSens = next.sensitiveCookieNames ?? next.alwaysSensitiveCookies ?? [];
	const prevIgn = prev.ignoredCookieNames ?? prev.alwaysIgnoreCookies ?? [];
	const nextIgn = next.ignoredCookieNames ?? next.alwaysIgnoreCookies ?? [];
	if (prevSens.length !== nextSens.length || prevIgn.length !== nextIgn.length) return true;
	const prevSensSet = new Set(prevSens);
	if (nextSens.some((s) => !prevSensSet.has(s))) return true;
	const prevIgnSet = new Set(prevIgn);
	if (nextIgn.some((s) => !prevIgnSet.has(s))) return true;
	return false;
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
var SettingsTransitionPipeline = class {
	lastAppliedSettings = null;
	hooks = {};
	registerHooks(hooks) {
		this.hooks = {
			...this.hooks,
			...hooks
		};
	}
	getLastAppliedSettings() {
		return this.lastAppliedSettings !== null ? { ...this.lastAppliedSettings } : null;
	}
	setLastAppliedSettings(settings) {
		this.lastAppliedSettings = settings !== null ? { ...settings } : null;
	}
	areEqual(a, b) {
		if (a.schemaVersion !== b.schemaVersion) return false;
		if (a.monitoringMode !== b.monitoringMode) return false;
		if (a.evaluationMode !== b.evaluationMode) return false;
		if (a.retainHistoryDays !== b.retainHistoryDays) return false;
		if (a.maxHistoryPerOrigin !== b.maxHistoryPerOrigin) return false;
		if (a.severityFilter.length !== b.severityFilter.length) return false;
		const aSev = new Set(a.severityFilter);
		if (b.severityFilter.some((s) => !aSev.has(s))) return false;
		if (a.sensitiveCookieNames.length !== b.sensitiveCookieNames.length) return false;
		if (a.sensitiveCookieNames.some((v, i) => v !== b.sensitiveCookieNames[i])) return false;
		if (a.ignoredCookieNames.length !== b.ignoredCookieNames.length) return false;
		if (a.ignoredCookieNames.some((v, i) => v !== b.ignoredCookieNames[i])) return false;
		return true;
	}
	async transition(incoming, _source = "storage") {
		if (typeof incoming === "object" && incoming !== null && typeof incoming.schemaVersion === "number" && incoming.schemaVersion > 2) throw new UnsupportedSchemaError(incoming.schemaVersion);
		const validated = migrateSettings(incoming);
		if (this.lastAppliedSettings !== null && this.areEqual(this.lastAppliedSettings, validated)) return { ...this.lastAppliedSettings };
		const previous = this.lastAppliedSettings ?? {
			...DEFAULT_SETTINGS,
			monitoringMode: "off"
		};
		const cookieListsChanged = haveCookieListsChanged(previous, validated);
		const modeChanged = previous.monitoringMode !== validated.monitoringMode;
		this.lastAppliedSettings = { ...validated };
		cachedSettings = { ...validated };
		if (modeChanged && this.hooks.onModeChange) await this.hooks.onModeChange(previous.monitoringMode, validated.monitoringMode);
		if (cookieListsChanged && this.hooks.onRescoreTabs) await this.hooks.onRescoreTabs(previous, validated);
		if (this.hooks.onSettingsApplied) await this.hooks.onSettingsApplied(validated);
		for (const cb of listeners) try {
			cb(validated);
		} catch {}
		return { ...validated };
	}
};
var settingsTransitionPipeline = new SettingsTransitionPipeline();
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
			settingsTransitionPipeline.transition(newRaw, "storage").catch(() => {
				cachedSettings = {
					...DEFAULT_SETTINGS,
					monitoringMode: "off"
				};
			});
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
			settingsTransitionPipeline.setLastAppliedSettings(cachedSettings);
			return { ...cachedSettings };
		}
		hydrationPromise = (async () => {
			try {
				const raw = (await chrome.storage.local.get(STORAGE_KEYS.SETTINGS))[STORAGE_KEYS.SETTINGS];
				if (typeof raw === "object" && raw !== null && typeof raw["schemaVersion"] === "number" && raw["schemaVersion"] > 2) throw new UnsupportedSchemaError(raw["schemaVersion"]);
				const migrated = migrateSettings(raw);
				if (!(typeof raw === "object" && raw !== null && raw["schemaVersion"] === 2)) await chrome.storage.local.set({ [STORAGE_KEYS.SETTINGS]: migrated });
				cachedSettings = migrated;
				settingsTransitionPipeline.setLastAppliedSettings(migrated);
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
	* Checks whether settings have finished initial storage hydration.
	*/
	isReady() {
		if (cachedSettings !== null) return true;
		if (typeof chrome === "undefined" || typeof chrome.storage === "undefined" || typeof chrome.storage.local === "undefined") return true;
		return false;
	},
	/**
	* Routes an incoming settings update through the single atomic transition pipeline.
	*/
	async transition(incoming, source = "storage") {
		ensureStorageListener();
		return settingsTransitionPipeline.transition(incoming, source);
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
		return await settingsTransitionPipeline.transition(merged, "storage");
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
	* Resets the in-memory cache and pipeline (primarily for unit tests).
	*/
	clearCache() {
		cachedSettings = null;
		hydrationPromise = null;
		settingsTransitionPipeline.setLastAppliedSettings(null);
	}
};
//#endregion
//#region src/shared/storage.ts
var KeyedAsyncMutex = class {
	locks = /* @__PURE__ */ new Map();
	async runExclusive(key, fn) {
		const currentLock = this.locks.get(key) ?? Promise.resolve();
		let release;
		const nextLock = new Promise((resolve) => {
			release = resolve;
		});
		const tail = currentLock.then(() => nextLock, () => nextLock);
		this.locks.set(key, tail);
		try {
			await currentLock;
			return await fn();
		} finally {
			release();
			if (this.locks.get(key) === tail) this.locks.delete(key);
		}
	}
	isLocked(key) {
		return this.locks.has(key);
	}
};
var storageMutex = new KeyedAsyncMutex();
var storageHealth = {
	isDegraded: false,
	lastError: null,
	lastErrorTimestamp: null
};
function recordStorageFailure(error) {
	storageHealth.isDegraded = true;
	storageHealth.lastError = error instanceof Error ? error.message : String(error);
	storageHealth.lastErrorTimestamp = Date.now();
}
function serializeTabState(state) {
	const { apiEndpoints, ...rest } = state;
	if (apiEndpoints !== void 0) return {
		...rest,
		apiEndpoints: Array.from(apiEndpoints.entries())
	};
	return rest;
}
function deserializeTabState(raw) {
	if (typeof raw !== "object" || raw === null) throw new Error("Invalid serialized TabState: not an object");
	const candidate = raw;
	if (typeof candidate.tabId !== "number" || typeof candidate.origin !== "string") throw new Error("Invalid serialized TabState: missing required tabId or origin");
	const { apiEndpoints, ...rest } = candidate;
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
		return storageMutex.runExclusive(`tab:${state.tabId}`, async () => {
			const serialized = serializeTabState(state);
			const key = `${STORAGE_KEYS.TAB_PREFIX}${state.tabId}`;
			try {
				await chrome.storage.session.set({ [key]: serialized });
			} catch (err) {
				recordStorageFailure(err);
				throw err;
			}
		});
	},
	async removeTabState(tabId) {
		return storageMutex.runExclusive(`tab:${tabId}`, async () => {
			const key = `${STORAGE_KEYS.TAB_PREFIX}${tabId}`;
			try {
				await chrome.storage.session.remove(key);
			} catch (err) {
				recordStorageFailure(err);
				throw err;
			}
		});
	},
	async clearAllTabStates() {
		if (typeof chrome === "undefined" || typeof chrome.storage === "undefined" || typeof chrome.storage.session === "undefined") return;
		try {
			const all = await chrome.storage.session.get(null);
			const tabKeys = Object.keys(all).filter((k) => k.startsWith(STORAGE_KEYS.TAB_PREFIX));
			if (tabKeys.length > 0) await chrome.storage.session.remove(tabKeys);
		} catch (err) {
			recordStorageFailure(err);
			throw err;
		}
	},
	async getAllTabStates() {
		const all = await chrome.storage.session.get(null);
		const results = [];
		for (const [k, v] of Object.entries(all)) if (k.startsWith(STORAGE_KEYS.TAB_PREFIX)) try {
			results.push(deserializeTabState(v));
		} catch {}
		return results;
	},
	async getAuthBaseline(origin) {
		if (!origin) return null;
		const key = `${STORAGE_KEYS.AUTH_BASELINE_PREFIX}${origin}`;
		return (await chrome.storage.session.get(key))[key] ?? null;
	},
	async setAuthBaseline(origin, baseline) {
		if (!origin) return;
		return storageMutex.runExclusive(`auth_baseline:${origin}`, async () => {
			const key = `${STORAGE_KEYS.AUTH_BASELINE_PREFIX}${origin}`;
			try {
				await chrome.storage.session.set({ [key]: baseline });
			} catch (err) {
				recordStorageFailure(err);
				throw err;
			}
		});
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
		return storageMutex.runExclusive(`origin:${origin}`, async () => {
			try {
				const history = await this.getOriginHistory(origin);
				const last = history[history.length - 1];
				if (last && last.score === item.score && last.grade === item.grade && item.timestamp - last.timestamp < 6e4) return;
				const settings = await this.getSettings();
				const updated = pruneHistoryItems([...history, item], item.timestamp, settings.retainHistoryDays, settings.maxHistoryPerOrigin);
				const key = `${STORAGE_KEYS.HISTORY_PREFIX}${origin}`;
				await chrome.storage.local.set({ [key]: updated });
			} catch (err) {
				recordStorageFailure(err);
				throw err;
			}
		});
	},
	async pruneAllHistory(now = Date.now(), settings) {
		if (typeof chrome === "undefined" || chrome.storage?.local === void 0) return;
		try {
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
		} catch (err) {
			recordStorageFailure(err);
			throw err;
		}
	},
	async purgeOriginData(origin) {
		if (!origin || typeof chrome === "undefined" || chrome.storage?.local === void 0) return;
		return storageMutex.runExclusive(`origin:${origin}`, async () => {
			try {
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
			} catch (err) {
				recordStorageFailure(err);
				throw err;
			}
		});
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
		return storageMutex.runExclusive(`auth_diff:${origin}`, async () => {
			try {
				const updated = [...await this.getAuthDiffHistory(origin), diff].slice(-10);
				const key = `${STORAGE_KEYS.AUTH_DIFF_PREFIX}${origin}`;
				await chrome.storage.local.set({ [key]: updated });
			} catch (err) {
				recordStorageFailure(err);
				throw err;
			}
		});
	},
	async getGraph(apexDomain) {
		if (!apexDomain) return null;
		const key = `${STORAGE_KEYS.GRAPH_PREFIX}${apexDomain}`;
		return (await chrome.storage.local.get(key))[key] ?? null;
	},
	async saveGraph(graph) {
		if (!graph.apexDomain) return;
		return storageMutex.runExclusive(`graph:${graph.apexDomain}`, async () => {
			try {
				const now = Date.now();
				const maxLastSeen = Math.max(0, ...graph.nodes.map((n) => n.lastSeen || 0));
				const refTime = maxLastSeen > 0 ? maxLastSeen : now;
				let nodes = graph.nodes.filter((n) => n.isApex || !n.lastSeen || Math.abs(refTime - n.lastSeen) <= 2592e6);
				if (nodes.length > 100) {
					const apex = nodes.find((n) => n.isApex);
					const nonApex = nodes.filter((n) => !n.isApex).sort((a, b) => b.lastSeen - a.lastSeen);
					nodes = apex ? [apex, ...nonApex.slice(0, 99)] : nonApex.slice(0, 100);
				}
				const validHosts = new Set(nodes.map((n) => n.hostname));
				let edges = graph.edges.filter((e) => validHosts.has(e.source) && validHosts.has(e.target));
				if (edges.length > 150) edges = edges.slice(0, 150);
				const boundedGraph = {
					...graph,
					nodes,
					edges,
					lastUpdated: now
				};
				const key = `${STORAGE_KEYS.GRAPH_PREFIX}${graph.apexDomain}`;
				await chrome.storage.local.set({ [key]: boundedGraph });
			} catch (err) {
				recordStorageFailure(err);
				throw err;
			}
		});
	},
	/**
	* Atomically mutates the attack surface graph for an apex domain within a mutex.
	* Guarantees read-modify-write safety without lost updates.
	*/
	async mutateGraph(apexDomain, mutator) {
		if (!apexDomain) return null;
		return storageMutex.runExclusive(`graph:${apexDomain}`, async () => {
			try {
				const updated = mutator(await this.getGraph(apexDomain));
				const now = Date.now();
				const maxLastSeen = Math.max(0, ...updated.nodes.map((n) => n.lastSeen || 0));
				const refTime = maxLastSeen > 0 ? maxLastSeen : now;
				let nodes = updated.nodes.filter((n) => n.isApex || !n.lastSeen || Math.abs(refTime - n.lastSeen) <= 2592e6);
				if (nodes.length > 100) {
					const apex = nodes.find((n) => n.isApex);
					const nonApex = nodes.filter((n) => !n.isApex).sort((a, b) => b.lastSeen - a.lastSeen);
					nodes = apex ? [apex, ...nonApex.slice(0, 99)] : nonApex.slice(0, 100);
				}
				const validHosts = new Set(nodes.map((n) => n.hostname));
				let edges = updated.edges.filter((e) => validHosts.has(e.source) && validHosts.has(e.target));
				if (edges.length > 150) edges = edges.slice(0, 150);
				const boundedGraph = {
					...updated,
					nodes,
					edges,
					lastUpdated: now
				};
				const key = `${STORAGE_KEYS.GRAPH_PREFIX}${apexDomain}`;
				await chrome.storage.local.set({ [key]: boundedGraph });
				return boundedGraph;
			} catch (err) {
				recordStorageFailure(err);
				throw err;
			}
		});
	},
	async isOnboardingDismissed() {
		const result = await chrome.storage.local.get(STORAGE_KEYS.ONBOARDING_DISMISSED);
		return Boolean(result[STORAGE_KEYS.ONBOARDING_DISMISSED]);
	},
	async setOnboardingDismissed(dismissed) {
		await chrome.storage.local.set({ [STORAGE_KEYS.ONBOARDING_DISMISSED]: dismissed });
	},
	async deleteOriginData(origin) {
		await this.purgeOriginData(origin);
	},
	async deleteAllHistory() {
		try {
			const all = await chrome.storage.local.get(null);
			const histKeys = Object.keys(all).filter((k) => k.startsWith(STORAGE_KEYS.HISTORY_PREFIX));
			if (histKeys.length > 0) await chrome.storage.local.remove(histKeys);
		} catch (err) {
			recordStorageFailure(err);
			throw err;
		}
	},
	async deletePrivateRecords() {
		try {
			const all = await chrome.storage.session.get(null);
			const toRemove = Object.entries(all).filter(([k, v]) => k.startsWith(STORAGE_KEYS.TAB_PREFIX) && typeof v === "object" && v !== null && v.isIncognito === true).map(([k]) => k);
			if (toRemove.length > 0) await chrome.storage.session.remove(toRemove);
		} catch {}
	},
	async clearAll() {
		try {
			await chrome.storage.local.clear();
		} catch (err) {
			recordStorageFailure(err);
			throw err;
		}
	}
};
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
	chrome.alarms.create(MAINTENANCE_ALARM, { periodInMinutes: 1 });
	chrome.alarms.onAlarm.addListener((alarm) => {
		if (alarm.name === "maintenance") LocalStorage.pruneAllHistory();
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
	for (const state of all) {
		const existing = tabStates.get(state.tabId);
		if (!existing || state.updatedAt > existing.updatedAt) tabStates.set(state.tabId, state);
	}
	const baselines = await SessionStorage.getAllAuthBaselines();
	for (const [origin, baseline] of baselines) if (!originAuthBaselines.has(origin)) originAuthBaselines.set(origin, baseline);
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
		const isIncog = incognitoTabIds.has(details.tabId);
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
			isIncognito: isIncog
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
			}, incognitoTabIds.has(details.tabId));
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
			const isIncog = incognitoTabIds.has(details.tabId);
			partial = {
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
				redirectCount: 0,
				isIncognito: isIncog
			};
		}
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
		onHopComplete(details.tabId, hop, partial.isIncognito ?? false);
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
		const isIncog = existing?.isIncognito ?? incognitoTabIds.has(details.tabId);
		captureMap.delete(details.requestId);
		onHopComplete(details.tabId, hop, isIncog);
	}, filter, extraInfoSpec);
}
//#endregion
export { settingsTransitionPipeline as C, resolveCookieOverlaps as S, tabStates as _, registerCaptureListeners as a, SettingsService as b, isBroadGrant as c, reconcilePermissionsOnStartup as d, isModeCaptureAllowed as f, originAuthBaselines as g, initLifecycle as h, incognitoTabIds as i, patternFromOrigin as l, hydrateFromSession as m, clearInFlightCaptures as n, CapturePolicy as o, isRestrictedUrl as p, inFlightRequests as r, PermissionsService as s, captureMap as t, reconcilePermissionsOnRemoved as u, LocalStorage as v, normalizeCookieList as x, SessionStorage as y };

//# sourceMappingURL=capture-kosxRNgw.js.map