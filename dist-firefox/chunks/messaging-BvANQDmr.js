//#region src/shared/constants.ts
/** Bump when either score model changes so persisted history remains comparable. */
var SCORE_VERSION = "1.7.0";
/** URL schemes the extension cannot inspect. Show explicit "restricted" state. */
var RESTRICTED_SCHEMES = [
	"chrome://",
	"chrome-extension://",
	"devtools://",
	"about:",
	"data:",
	"blob:"
];
var BADGE_COLORS = {
	A: "#27ae60",
	B: "#2980b9",
	C: "#f39c12",
	D: "#e67e22",
	F: "#c0392b",
	"?": "#7f8c8d"
};
var SEVERITY_ORDER = [
	"critical",
	"high",
	"medium",
	"low",
	"info",
	"pass"
];
var GRADE_THRESHOLDS = [
	{
		min: 90,
		grade: "A"
	},
	{
		min: 70,
		grade: "B"
	},
	{
		min: 50,
		grade: "C"
	},
	{
		min: 30,
		grade: "D"
	},
	{
		min: 0,
		grade: "F"
	}
];
var STORAGE_KEYS = {
	SETTINGS: "settings",
	TAB_PREFIX: "tab:",
	HISTORY_PREFIX: "hist:",
	AUTH_DIFF_PREFIX: "authdiff:",
	AUTH_BASELINE_PREFIX: "authbase:",
	GRAPH_PREFIX: "graph:",
	ONBOARDING_DISMISSED: "onboarding_dismissed",
	HISTORY_INDEX: "hist_index"
};
/** Runtime port name for popup ↔ service worker connection. */
var POPUP_PORT_NAME = "popup";
/**
* Runtime port name for side panel ↔ service worker connection.
* Channel is registered now; the panel UI ships in Phase 3.
*/
var SIDEPANEL_PORT_NAME = "sidepanel";
var MAINTENANCE_ALARM = "maintenance";
var DEFAULT_SETTINGS = {
	schemaVersion: 2,
	monitoringMode: "per-site",
	severityFilter: [
		"critical",
		"high",
		"medium",
		"low",
		"info"
	],
	retainHistoryDays: 7,
	maxHistoryPerOrigin: 10,
	sensitiveCookieNames: [],
	ignoredCookieNames: [],
	evaluationMode: false,
	theme: "system",
	density: "comfortable",
	reducedMotion: "system"
};
//#endregion
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
	const VALID_THEMES = /* @__PURE__ */ new Set([
		"system",
		"dark",
		"light"
	]);
	const VALID_DENSITIES = /* @__PURE__ */ new Set(["comfortable", "compact"]);
	const VALID_MOTIONS = /* @__PURE__ */ new Set([
		"system",
		"always",
		"never"
	]);
	const theme = typeof obj.theme === "string" && VALID_THEMES.has(obj.theme) ? obj.theme : "system";
	const density = typeof obj.density === "string" && VALID_DENSITIES.has(obj.density) ? obj.density : "comfortable";
	const reducedMotion = typeof obj.reducedMotion === "string" && VALID_MOTIONS.has(obj.reducedMotion) ? obj.reducedMotion : "system";
	const result = {
		schemaVersion: 2,
		monitoringMode,
		severityFilter,
		retainHistoryDays,
		maxHistoryPerOrigin,
		sensitiveCookieNames: sensitive,
		ignoredCookieNames: ignored,
		evaluationMode,
		theme,
		density,
		reducedMotion
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
		const aSens = new Set(a.sensitiveCookieNames);
		if (b.sensitiveCookieNames.some((s) => !aSens.has(s))) return false;
		if (a.ignoredCookieNames.length !== b.ignoredCookieNames.length) return false;
		const aIgn = new Set(a.ignoredCookieNames);
		if (b.ignoredCookieNames.some((s) => !aIgn.has(s))) return false;
		if (a.theme !== b.theme) return false;
		if (a.density !== b.density) return false;
		if (a.reducedMotion !== b.reducedMotion) return false;
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
//#region src/rules/utils.ts
var CONTROL_CHAR_RE = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;
var BIDI_OVERRIDE_RE = /[\u200B-\u200D\u202A-\u202E\u2066-\u2069\uFEFF]/g;
/**
* Sanitise an evidence string for safe storage and display.
* Uses only textContent-safe characters — no HTML escaping needed,
* but we still escape the dangerous control/BiDi chars.
*/
function sanitizeEvidence(raw) {
	let s = raw.slice(0, 500).replace(CONTROL_CHAR_RE, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, "0")}`).replace(BIDI_OVERRIDE_RE, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
	if (raw.length > 500) s += ` … [${raw.length - 500} chars truncated]`;
	return s;
}
/** Find conflicting repeated values among security-sensitive response headers. */
function checkDuplicateHeaders(hop) {
	const names = [
		"strict-transport-security",
		"x-frame-options",
		"referrer-policy",
		"x-content-type-options",
		"x-xss-protection"
	];
	const findings = [];
	for (const name of names) {
		const values = hop.rawHeaders.filter((header) => header.name.toLowerCase() === name).map((header) => header.value.trim());
		if (values.length < 2 || new Set(values).size < 2) continue;
		findings.push({
			ruleId: "DUP-001",
			category: "header",
			severity: "info",
			title: `Conflicting duplicate ${name} headers`,
			impact: "Browsers and intermediaries may interpret conflicting repeated policy values differently.",
			evidence: sanitizeEvidence(`${name}: ${values.join(" | ")}`),
			recommendation: "Configure the server or proxy to emit one authoritative value for this header.",
			reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"
		});
	}
	return findings;
}
/**
* Redact the secret cookie value from a Set-Cookie header string,
* preserving the cookie name and all attributes (Path, Domain, SameSite, Secure, HttpOnly, etc.).
* e.g. "session=V2_CANARY; Path=/; Secure; HttpOnly" -> "session=[REDACTED]; Path=/; Secure; HttpOnly"
*/
function redactSetCookieHeader(headerValue) {
	if (!headerValue) return headerValue;
	const eqIdx = headerValue.indexOf("=");
	const semiIdx = headerValue.indexOf(";");
	if (eqIdx !== -1 && (semiIdx === -1 || eqIdx < semiIdx)) return `${headerValue.slice(0, eqIdx).trim()}=[REDACTED]${semiIdx !== -1 ? headerValue.slice(semiIdx) : ""}`;
	if (semiIdx !== -1) return `${headerValue.slice(0, semiIdx).trim()}=[REDACTED]${headerValue.slice(semiIdx)}`;
	return `${headerValue.trim()}=[REDACTED]`;
}
/**
* Redact secret cookie values from a Cookie request header string.
* e.g. "a=secret1; b=secret2" -> "a=[REDACTED]; b=[REDACTED]"
*/
function redactCookieHeader(headerValue) {
	if (!headerValue) return headerValue;
	return headerValue.split(";").map((part) => {
		const trimmed = part.trim();
		const eqIdx = trimmed.indexOf("=");
		if (eqIdx !== -1) return `${trimmed.slice(0, eqIdx).trim()}=[REDACTED]`;
		return trimmed ? `${trimmed}=[REDACTED]` : "";
	}).filter((s) => s.length > 0).join("; ");
}
/**
* Redact sensitive header values (Set-Cookie, Cookie, Authorization, Proxy-Authorization).
*/
function redactHeaderValue(name, value) {
	const lower = name.toLowerCase();
	if (lower === "set-cookie") return redactSetCookieHeader(value);
	if (lower === "cookie") return redactCookieHeader(value);
	if (lower === "authorization" || lower === "proxy-authorization") return "[REDACTED]";
	return value;
}
/**
* Build a lowercase-keyed header map from the raw WebRequest header array.
* Sensitive values (Set-Cookie, Cookie, Authorization) are automatically redacted.
* For most headers last-value-wins.
*/
function normalizeHeaders(raw) {
	const map = {};
	for (const { name, value } of raw) if (value != null) map[name.toLowerCase()] = redactHeaderValue(name, value);
	return map;
}
/**
* Collect every Set-Cookie header value as a raw string array with values redacted.
* The webRequest API may present them as a single joined header or
* as multiple entries depending on Chrome version.
*/
function extractSetCookieHeaders(raw) {
	return raw.filter((h) => h.name.toLowerCase() === "set-cookie" && h.value != null).map((h) => redactSetCookieHeader(h.value));
}
/**
* Compare two header maps and return true if they differ in any key or value.
* Used to detect modifications made by other extensions between
* onHeadersReceived and onResponseStarted.
*/
function headersDiffer(a, b) {
	const keysA = Object.keys(a).sort();
	const keysB = Object.keys(b).sort();
	if (keysA.length !== keysB.length) return true;
	for (let i = 0; i < keysA.length; i++) {
		const k = keysA[i];
		if (k !== keysB[i]) return true;
		if (a[k] !== b[k]) return true;
	}
	return false;
}
/**
* Parse a raw CSP string into a directive map.
* Keys are directive names (lowercase), values are the raw source-list string.
* This is a best-effort linear-time parser — not a full evaluator.
* For thorough analysis, use csp-evaluator on top of this.
*/
function parseCspDirectives(csp) {
	const directives = /* @__PURE__ */ new Map();
	for (const part of csp.split(";")) {
		const trimmed = part.trim();
		if (trimmed.length === 0) continue;
		const spaceIdx = trimmed.indexOf(" ");
		if (spaceIdx === -1) directives.set(trimmed.toLowerCase(), "");
		else {
			const name = trimmed.slice(0, spaceIdx).toLowerCase();
			const value = trimmed.slice(spaceIdx + 1).trim();
			directives.set(name, value);
		}
	}
	return directives;
}
/** Extract the scheme+host+port origin from a URL string, or null on failure. */
function originFromUrl(url) {
	try {
		const u = new URL(url);
		return u.origin === "null" ? null : u.origin;
	} catch {
		return null;
	}
}
var SENSITIVE_COOKIE_RE = /(^|[-_])(session|sess|auth|token|jwt|sid|login|sso|connect\.sid|phpsessid|jsessionid|asp\.net_sessionid|credential|secret|password|access[-_]?token|id[-_]?token)([-_]|$)/i;
var NON_SENSITIVE_COOKIE_RE = /(^|[-_])(ga|gid|gat|gcl|fbp|fbc|theme|dark|light|lang|locale|country|currency|timezone|tz|sidebar|banner|notice|consent|cookie_consent|optout|optimizely|amplitude|intercom|csrf|xsrf|csrftoken)([-_]|$)/i;
/**
* Returns true when a cookie's name indicates it is likely an authentication,
* session, or authorization token that requires strict security flags (HttpOnly, Secure).
*
* Harmless client-side cookies (analytics, UI preferences, language, CSRF tokens that
* need JS reading in double-submit patterns) return false.
*/
function isSensitiveCookie(name, alwaysSensitive = [], alwaysIgnore = []) {
	if (alwaysIgnore.includes(name)) return {
		isSensitive: false,
		reason: "override"
	};
	if (alwaysSensitive.includes(name)) return {
		isSensitive: true,
		reason: "override"
	};
	if (name.startsWith("__Host-") || name.startsWith("__Secure-")) return {
		isSensitive: true,
		reason: "prefix"
	};
	if (NON_SENSITIVE_COOKIE_RE.test(name)) return {
		isSensitive: false,
		reason: "regex"
	};
	return {
		isSensitive: SENSITIVE_COOKIE_RE.test(name),
		reason: "regex"
	};
}
var NONCE_RE = /'nonce-[A-Za-z0-9+/=_-]+'/i;
var HASH_RE = /'sha(256|384|512)-[A-Za-z0-9+/=_-]+'/i;
/**
* Checks whether a script-src source-list employs modern CSP Level 3 safeguards
* (nonces, hashes, or 'strict-dynamic').
*
* In CSP Level 3:
*  - If 'nonce-...' or 'sha...' is present, browsers ignore 'unsafe-inline'.
*  - If 'strict-dynamic' is present, browsers ignore 'unsafe-inline' and host sources (e.g. https:).
*/
function hasCspBypassProtection(sourceList) {
	const hasNonce = NONCE_RE.test(sourceList);
	const hasHash = HASH_RE.test(sourceList);
	const hasStrictDynamic = sourceList.includes("'strict-dynamic'");
	return {
		hasNonce,
		hasHash,
		hasStrictDynamic,
		isModernStrict: hasNonce || hasHash || hasStrictDynamic
	};
}
var SENSITIVE_PATH_KEYWORDS = /* @__PURE__ */ new Set([
	"reset",
	"token",
	"tokens",
	"auth",
	"password",
	"passwords",
	"passwd",
	"pwd",
	"invite",
	"invites",
	"invitation",
	"verify",
	"verification",
	"confirm",
	"confirmation",
	"session",
	"sessions",
	"secret",
	"secrets",
	"key",
	"keys",
	"apikey",
	"otp",
	"code",
	"codes",
	"recovery",
	"credential",
	"credentials"
]);
var COMMON_SAFE_SUBPATHS = /* @__PURE__ */ new Set([
	"login",
	"logout",
	"signin",
	"signout",
	"signup",
	"register",
	"status",
	"check",
	"user",
	"users",
	"me",
	"profile",
	"settings",
	"account",
	"callback",
	"refresh",
	"new",
	"edit",
	"delete",
	"update",
	"create",
	"view",
	"list"
]);
var UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
var UUID_SUBSTRING_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
var JWT_RE = /^eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/;
var HEX_TOKEN_RE = /^[0-9a-f]{16,}$/i;
var LONG_OPAQUE_RE = /^[a-zA-Z0-9_.-]{20,}$/;
/**
* Redacts sensitive path segments (tokens, UUIDs, JWTs, opaque hashes, and parameters following
* keywords like /reset/ or /token/) from URL paths to prevent credential persistence in storage/UI.
*/
function redactUrlPath(pathname) {
	const segments = pathname.split("/");
	for (let i = 0; i < segments.length; i++) {
		const seg = segments[i];
		if (seg === void 0 || seg.length === 0) continue;
		if (seg === "[id]" || seg === "[token]" || seg === "[redacted]") continue;
		const stem = seg.replace(/\.[a-zA-Z0-9]+$/, "");
		if (UUID_RE.test(seg) || UUID_RE.test(stem) || UUID_SUBSTRING_RE.test(seg)) {
			segments[i] = "[id]";
			continue;
		}
		if (JWT_RE.test(seg) || JWT_RE.test(stem) || /^eyJ/.test(seg)) {
			segments[i] = "[token]";
			continue;
		}
		const prev = i > 0 ? segments[i - 1]?.toLowerCase() : void 0;
		if (prev !== void 0 && SENSITIVE_PATH_KEYWORDS.has(prev)) {
			if (!COMMON_SAFE_SUBPATHS.has(seg.toLowerCase()) && !COMMON_SAFE_SUBPATHS.has(stem.toLowerCase())) {
				segments[i] = "[token]";
				continue;
			}
		}
		if (HEX_TOKEN_RE.test(seg) || HEX_TOKEN_RE.test(stem) || LONG_OPAQUE_RE.test(seg) || LONG_OPAQUE_RE.test(stem)) {
			segments[i] = "[token]";
			continue;
		}
	}
	return segments.join("/");
}
/**
* Sanitizes a URL for safe storage: strips query strings, fragments, and credentials,
* and redacts sensitive tokens/UUIDs in path segments.
*/
function sanitizeUrlForStorage(rawUrl) {
	if (rawUrl === null || rawUrl === void 0 || rawUrl === "") return "";
	const cleaned = ((rawUrl.split("#")[0] ?? "").split("?")[0] ?? "").trim();
	if (cleaned.length === 0) return "";
	try {
		const parsed = new URL(cleaned);
		const proto = parsed.protocol.toLowerCase();
		if (proto === "http:" || proto === "https:" || proto === "ws:" || proto === "wss:") return `${`${parsed.protocol}//${parsed.host}`}${redactUrlPath(parsed.pathname)}`;
	} catch {}
	return redactUrlPath(cleaned.replace(/^[a-zA-Z0-9+.-]+:\/\/[^@/]+@/, "").replace(/^[^@/]+@/, ""));
}
/**
* Sanitizes a CSP policy string for storage by parsing directives and sanitizing
* reporting URLs in report-uri and report-to directives.
*/
function sanitizeCspPolicyForStorage(policy) {
	if (!policy || typeof policy !== "string") return "";
	const directives = policy.split(";").map((p) => p.trim()).filter(Boolean);
	const sanitizedDirectives = [];
	for (const directive of directives) {
		const spaceIdx = directive.indexOf(" ");
		if (spaceIdx === -1) {
			sanitizedDirectives.push(directive);
			continue;
		}
		const name = directive.slice(0, spaceIdx).trim();
		const value = directive.slice(spaceIdx + 1).trim();
		const lowerName = name.toLowerCase();
		if (lowerName === "report-uri" || lowerName === "report-to") {
			const sanitizedTokens = value.split(/\s+/).filter(Boolean).map((token) => sanitizeUrlForStorage(token));
			sanitizedDirectives.push(`${name} ${sanitizedTokens.join(" ")}`);
		} else sanitizedDirectives.push(`${name} ${value}`);
	}
	return sanitizedDirectives.join("; ");
}
//#endregion
//#region src/rules/headers/subdomain-trust.ts
var REF_SUBDOMAIN = "https://portswigger.net/web-security/host-header/exploiting#password-reset-poisoning-via-dangling-markup";
var REF_CORS = "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS";
var REF_COOKIE = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#domaindomain-value";
var REF_COOKIE_TOSS = "https://datatracker.ietf.org/doc/html/rfc6265#section-8.6";
var REF_CSP = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy";
var REF_COOP = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy";
var REF_OAC = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin-Agent-Cluster";
var TWO_PART_TLDS = /* @__PURE__ */ new Set([
	"co.uk",
	"org.uk",
	"gov.uk",
	"ac.uk",
	"net.uk",
	"me.uk",
	"ltd.uk",
	"plc.uk",
	"com.au",
	"net.au",
	"org.au",
	"edu.au",
	"gov.au",
	"asn.au",
	"id.au",
	"co.nz",
	"net.nz",
	"org.nz",
	"govt.nz",
	"ac.nz",
	"geek.nz",
	"school.nz",
	"co.jp",
	"ne.jp",
	"or.jp",
	"go.jp",
	"ac.jp",
	"ed.jp",
	"lg.jp",
	"co.in",
	"net.in",
	"org.in",
	"gen.in",
	"firm.in",
	"ind.in",
	"nic.in",
	"ac.in",
	"edu.in",
	"gov.in",
	"com.br",
	"net.br",
	"org.br",
	"gov.br",
	"edu.br",
	"ind.br",
	"com.sg",
	"edu.sg",
	"gov.sg",
	"net.sg",
	"org.sg",
	"com.mx",
	"edu.mx",
	"gob.mx",
	"org.mx",
	"net.mx",
	"co.za",
	"org.za",
	"gov.za",
	"net.za",
	"ac.za",
	"com.tr",
	"net.tr",
	"org.tr",
	"gov.tr",
	"edu.tr",
	"com.tw",
	"org.tw",
	"gov.tw",
	"edu.tw",
	"net.tw",
	"com.hk",
	"org.hk",
	"gov.hk",
	"edu.hk",
	"net.hk",
	"com.cn",
	"net.cn",
	"org.cn",
	"gov.cn",
	"edu.cn"
]);
/**
* Derive the eTLD+1 (registrable domain) from a hostname.
* Handles both standard TLDs (example.com) and two-part eTLDs (example.co.uk).
* Returns null for IP addresses and localhost.
*/
function registrableDomain(hostname) {
	if (!hostname || /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname === "localhost") return null;
	const parts = hostname.toLowerCase().split(".");
	if (parts.length < 2) return null;
	if (parts.length >= 3) {
		const lastTwo = parts.slice(-2).join(".");
		if (TWO_PART_TLDS.has(lastTwo) || /^[a-z0-9\-]+\.(co|com|net|org|gov|edu|ac|gob)\.[a-z]{2}$/.test(parts.slice(-3).join("."))) return parts.slice(-3).join(".");
	}
	return parts.slice(-2).join(".");
}
/**
* Returns true when `hostname` is a true subdomain of its registrable domain
* (ignoring the standard 'www' prefix which acts as the apex site).
*/
function isSubdomain(hostname) {
	const reg = registrableDomain(hostname);
	if (reg == null || hostname === reg) return false;
	if (hostname === `www.${reg}`) return false;
	return hostname.length > reg.length + 1 && hostname.endsWith(`.${reg}`);
}
/**
* Split a CSP source-list on whitespace, return tokens.
*/
function cspTokens(src) {
	return src.split(/\s+/).filter((t) => t.length > 0);
}
/**
* Returns true when a CSP source-list token allows script execution from
* an arbitrary subdomain of `registrable` (eTLD+1).
*/
function cspAllowsSubdomain(sourceList, registrable) {
	for (const token of cspTokens(sourceList)) {
		const bare = token.replace(/^https?:\/\//, "");
		if (bare === `*.${registrable}` || bare === registrable) return true;
		if (bare.endsWith(`.${registrable}`) && !bare.startsWith("*")) return true;
	}
	return false;
}
/**
* Resolve effective source-list for `directive`, falling back to default-src.
*/
function resolveEffective(directives, directive) {
	return directives.get(directive) ?? directives.get("default-src");
}
/**
* Analyse the final hop's headers + cookies for subdomain→main-domain
* escalation paths.
*
* @param finalHop - The authoritative response hop.
* @param cookies  - Cookie metadata for the page.
*/
function checkSubdomainTrust(finalHop, cookies, alwaysSensitive = [], alwaysIgnore = []) {
	const findings = [];
	const vectors = [];
	let hostname = "";
	try {
		hostname = new URL(finalHop.url).hostname;
	} catch {
		return {
			findings,
			hasEscalationPath: false,
			vectors
		};
	}
	const regDomain = registrableDomain(hostname);
	if (regDomain == null) return {
		findings,
		hasEscalationPath: false,
		vectors
	};
	const pageIsSubdomain = isSubdomain(hostname);
	const cspValue = finalHop.headers["content-security-policy"] ?? "";
	const corsOrigin = finalHop.headers["access-control-allow-origin"] ?? "";
	const corsCredsRaw = finalHop.headers["access-control-allow-credentials"] ?? "";
	const varyHeader = finalHop.headers["vary"] ?? "";
	const coopHeader = finalHop.headers["cross-origin-opener-policy"] ?? "";
	const oacHeader = finalHop.headers["origin-agent-cluster"] ?? "";
	const xfo = finalHop.headers["x-frame-options"] ?? "";
	const directives = cspValue.length > 0 ? parseCspDirectives(cspValue) : /* @__PURE__ */ new Map();
	const effectiveScriptSrc = resolveEffective(directives, "script-src");
	const frameAncestors = directives.get("frame-ancestors") ?? "";
	let hasEscalationPath = false;
	const broadCookies = [];
	for (const cookie of cookies) {
		const d = cookie.domain;
		if ((d.startsWith(".") ? d.slice(1) : d) === regDomain || d === `.${regDomain}`) {
			if (isSensitiveCookie(cookie.name, alwaysSensitive, alwaysIgnore).isSensitive || cookie.httpOnly && cookie.session) broadCookies.push(cookie.name);
		}
	}
	const cookieTrustPresent = broadCookies.length > 0;
	if (cookieTrustPresent) hasEscalationPath = true;
	vectors.push({
		id: "SUB-001",
		label: "Cookie scope spans all subdomains",
		detail: cookieTrustPresent ? `${broadCookies.length} sensitive cookie(s) scoped to .${regDomain}: ${broadCookies.slice(0, 3).map((n) => `"${n}"`).join(", ")}${broadCookies.length > 3 ? " …" : ""}` : `No domain-wide sensitive cookies detected (all session cookies host-only or isolated)`,
		risk: "critical",
		present: cookieTrustPresent
	});
	if (cookieTrustPresent) findings.push({
		ruleId: "SUB-001",
		category: "cookie",
		severity: "critical",
		title: `Sensitive cookie(s) scoped to .${regDomain} — subdomain compromise exposes main-domain session`,
		impact: `An attacker who compromises any subdomain on ${regDomain} can access these session cookies and impersonate users on the apex domain.`,
		evidence: sanitizeEvidence(`Domain-wide sensitive cookies: ${broadCookies.slice(0, 5).join(", ")}`),
		recommendation: "Set authentication and session cookies without the Domain attribute (host-only) or restrict to Domain=<specific-subdomain>. Avoid Domain=.example.com for session/auth cookies.",
		reference: REF_COOKIE
	});
	const unshieldedSensitiveCookies = [];
	for (const cookie of cookies) if (isSensitiveCookie(cookie.name, alwaysSensitive, alwaysIgnore).isSensitive && !cookie.name.startsWith("__Host-")) unshieldedSensitiveCookies.push(cookie.name);
	const cookieTossingRisk = unshieldedSensitiveCookies.length > 0;
	if (cookieTossingRisk) hasEscalationPath = true;
	vectors.push({
		id: "SUB-005",
		label: "Cookie Tossing / Shadowing Risk (Missing __Host- prefix)",
		detail: cookieTossingRisk ? `Sensitive cookie(s) lack __Host- prefix: ${unshieldedSensitiveCookies.slice(0, 3).join(", ")}. A compromised subdomain can inject Domain=.${regDomain} cookies to hijack sessions.` : "All sensitive cookies use __Host- prefix or none detected",
		risk: "medium",
		present: cookieTossingRisk
	});
	if (cookieTossingRisk) findings.push({
		ruleId: "SUB-005",
		category: "cookie",
		severity: "medium",
		title: `Sensitive session cookie(s) lack __Host- prefix — vulnerable to Cookie Tossing from subdomains`,
		impact: `An attacker controlling any subdomain can overwrite or shadow main-domain session cookies by setting Domain=.${regDomain} cookies (Cookie Tossing).`,
		evidence: sanitizeEvidence(`Unprefixed sensitive cookies: ${unshieldedSensitiveCookies.slice(0, 5).join(", ")}`),
		recommendation: "Prefix sensitive session cookies with __Host- (e.g. __Host-session=...) so browsers reject subdomains attempting to shadow or overwrite cookies for the main domain (RFC 6265bis §4.1.3).",
		reference: REF_COOKIE_TOSS
	});
	let cspSubdomainTrust = false;
	let cspEvidence = "";
	if (effectiveScriptSrc !== void 0) {
		const { isModernStrict } = hasCspBypassProtection(effectiveScriptSrc);
		if (!isModernStrict) {
			const dangerous = cspTokens(effectiveScriptSrc).filter((t) => {
				const bare = t.replace(/^https?:\/\//, "");
				return bare === `*.${regDomain}` || bare === regDomain;
			});
			if (dangerous.length > 0) {
				cspSubdomainTrust = true;
				hasEscalationPath = true;
				cspEvidence = dangerous.join(" ");
			}
		}
	}
	const subdomainTrustDetail = effectiveScriptSrc != null ? `script-src is scoped to explicit hosts (no wildcard subdomain trust for ${regDomain})` : cspValue.length > 0 ? "CSP present but script-src not found" : "No CSP response header; explicit subdomain script trust is not evaluated here";
	vectors.push({
		id: "SUB-002",
		label: "CSP trusts scripts from subdomains",
		detail: cspSubdomainTrust ? `Subdomain script source(s): ${cspEvidence}` : subdomainTrustDetail,
		risk: "critical",
		present: cspSubdomainTrust
	});
	if (cspSubdomainTrust && cspEvidence) findings.push({
		ruleId: "SUB-002",
		category: "header",
		severity: "critical",
		title: `CSP script-src trusts wildcard *.${regDomain} — allows XSS pivot from any ${regDomain} subdomain`,
		impact: `An attacker who finds an XSS bug or hosts files on any ${regDomain} subdomain can execute scripts with full permissions on the main domain.`,
		evidence: sanitizeEvidence(cspEvidence),
		recommendation: `Replace wildcard subdomain source (*.${regDomain}) with explicit allowlisted hostnames or nonces/hashes.`,
		reference: REF_CSP
	});
	let corsTrustPresent = false;
	let corsDetail = "";
	const corsWithCreds = corsCredsRaw?.toLowerCase().trim() === "true";
	if (corsOrigin.length > 0) {
		if (corsOrigin === "*") {
			corsTrustPresent = true;
			corsDetail = "Access-Control-Allow-Origin: *";
			if (corsWithCreds) corsDetail += " + Credentials: true (critical misconfiguration)";
		} else try {
			const allowedHostname = new URL(corsOrigin).hostname;
			if (registrableDomain(allowedHostname) === regDomain && allowedHostname !== hostname) {
				corsTrustPresent = true;
				corsDetail = `Access-Control-Allow-Origin: ${corsOrigin} (trusts subdomain of same root)`;
				if (corsWithCreds) corsDetail += "; Access-Control-Allow-Credentials: true";
			}
		} catch {}
	} else if (varyHeader.toLowerCase().includes("origin")) {
		corsTrustPresent = true;
		corsDetail = "Vary: Origin present with no Access-Control-Allow-Origin header — possible dynamic reflection (heuristic)";
	}
	if (corsTrustPresent) hasEscalationPath = true;
	const varyOnlyHeuristic = corsTrustPresent && corsOrigin.length === 0;
	vectors.push({
		id: varyOnlyHeuristic ? "SUB-003H" : "SUB-003",
		label: varyOnlyHeuristic ? "CORS Vary: Origin heuristic" : "CORS allows subdomain / wildcard origins",
		detail: corsTrustPresent ? corsDetail : corsOrigin.length > 0 ? `Access-Control-Allow-Origin: ${corsOrigin.slice(0, 80)} (no cross-subdomain trust detected)` : "No CORS header present",
		risk: varyOnlyHeuristic ? "medium" : "high",
		present: corsTrustPresent
	});
	if (corsTrustPresent) findings.push({
		ruleId: varyOnlyHeuristic ? "SUB-003H" : "SUB-003",
		category: "cors",
		severity: varyOnlyHeuristic ? "medium" : "high",
		confidence: varyOnlyHeuristic ? "heuristic" : "deterministic",
		title: varyOnlyHeuristic ? "Vary: Origin with no explicit CORS policy — possible dynamic origin reflection (heuristic)" : "CORS policy trusts subdomain origin — cross-subdomain API data exposure possible",
		impact: "Compromised or attacker-controlled subdomains can send authenticated AJAX requests to your private APIs and read sensitive user data across origins.",
		evidence: sanitizeEvidence(corsDetail),
		recommendation: "Set Access-Control-Allow-Origin to an explicit allowlist of known origins. Never reflect the Origin request header without strict validation.",
		reference: REF_CORS
	});
	let postMsgTrustPresent = false;
	let postMsgDetail = "";
	if (xfo.length === 0 && frameAncestors.length > 0 && (frameAncestors.includes("*") || cspAllowsSubdomain(frameAncestors, regDomain))) {
		postMsgTrustPresent = true;
		postMsgDetail = `Explicit subdomain framing trust: ${frameAncestors.slice(0, 80)}`;
		hasEscalationPath = true;
	}
	vectors.push({
		id: "SUB-004",
		label: "postMessage / framing trust open to subdomains",
		detail: postMsgTrustPresent ? postMsgDetail : frameAncestors.length > 0 || xfo.length > 0 ? `Framing is restricted (${frameAncestors.length > 0 ? "frame-ancestors" : "X-Frame-Options"} present)` : "No framing policy detected; covered by CSP-005 and XFO-001",
		risk: "high",
		present: postMsgTrustPresent
	});
	if (postMsgTrustPresent) findings.push({
		ruleId: "SUB-004",
		category: "header",
		severity: "high",
		title: "Page can be framed by subdomains — postMessage confusion / clickjacking pivot possible",
		impact: "Subdomains can embed this page in an iframe to sniff postMessage data or perform clickjacking attacks on authenticated actions.",
		evidence: sanitizeEvidence(postMsgDetail),
		recommendation: "Add \"Content-Security-Policy: frame-ancestors 'self'\" or \"X-Frame-Options: SAMEORIGIN\" to prevent untrusted subdomains from embedding this page.",
		reference: REF_CSP
	});
	const coopMissing = coopHeader.length === 0 || !coopHeader.toLowerCase().includes("same-origin");
	if (coopMissing) hasEscalationPath = true;
	vectors.push({
		id: "SUB-006",
		label: "Cross-Origin-Opener-Policy (COOP) missing",
		detail: coopMissing ? coopHeader.length > 0 ? `COOP: ${coopHeader} (not same-origin)` : "COOP header absent — subdomains can manipulate window.opener" : `COOP is strict (${coopHeader})`,
		risk: "medium",
		present: coopMissing
	});
	if (coopMissing) findings.push({
		ruleId: "SUB-006",
		category: "header",
		severity: "medium",
		title: "Missing Cross-Origin-Opener-Policy (COOP) — subdomains can access window.opener",
		impact: "Untrusted subdomains opened in new tabs or windows can access window.opener and silently redirect the parent tab to a phishing clone (Reverse Tabnabbing).",
		evidence: sanitizeEvidence(coopHeader.length > 0 ? coopHeader : "(header absent)"),
		recommendation: "Set \"Cross-Origin-Opener-Policy: same-origin\" to isolate the top-level browsing context and prevent malicious subdomains from manipulating window.opener.",
		reference: REF_COOP
	});
	const oacMissing = oacHeader.length === 0 || !oacHeader.includes("?1");
	vectors.push({
		id: "SUB-007",
		label: "Origin-Agent-Cluster missing (document.domain relaxation risk)",
		detail: oacMissing ? "Origin-Agent-Cluster: ?1 missing — legacy document.domain relaxation can bridge subdomains" : "Origin-Agent-Cluster: ?1 is active",
		risk: "low",
		present: oacMissing
	});
	if (oacMissing) findings.push({
		ruleId: "SUB-007",
		category: "header",
		severity: "low",
		title: "Missing Origin-Agent-Cluster header — document.domain relaxation possible",
		impact: "Subdomains can alter document.domain to match the main domain, breaking Same-Origin-Policy boundaries and reading DOM content directly.",
		evidence: sanitizeEvidence(oacHeader.length > 0 ? oacHeader : "(header absent)"),
		recommendation: "Add \"Origin-Agent-Cluster: ?1\" to prevent document.domain relaxation and enforce origin isolation.",
		reference: REF_OAC
	});
	if (pageIsSubdomain && !hasEscalationPath) {
		vectors.push({
			id: "SUB-008",
			label: "Subdomain Isolated (No Escalation Path to Main Domain)",
			detail: `This page (${hostname}) is a subdomain, but no cookie scope, CSP wildcard, CORS, framing, or opener trust bridges to ${regDomain} were found.`,
			risk: "info",
			present: false
		});
		findings.push({
			ruleId: "SUB-008",
			category: "header",
			severity: "info",
			title: `Subdomain Isolated — no trust bridge to main domain detected`,
			impact: "This subdomain has no cookie, CSP, CORS, or framing trust bridges to the main domain; any security flaw found here remains strictly contained.",
			evidence: sanitizeEvidence(`${hostname} is isolated from ${regDomain}`),
			recommendation: "No action required. Vulnerabilities on this subdomain remain isolated and cannot jump to the main domain based on current security controls.",
			reference: REF_SUBDOMAIN
		});
	}
	return {
		findings,
		hasEscalationPath,
		vectors
	};
}
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
var StorageWriteBarrier = class {
	activeWrites = /* @__PURE__ */ new Set();
	barrierPromise = null;
	releaseBarrier = null;
	async enter() {
		if (this.barrierPromise !== null) await this.barrierPromise;
	}
	track(promise) {
		this.activeWrites.add(promise);
		const cleanup = () => {
			this.activeWrites.delete(promise);
		};
		promise.then(cleanup, cleanup);
		return promise;
	}
	async closeBarrierAndDrain() {
		if (this.barrierPromise === null) {
			let release;
			this.barrierPromise = new Promise((resolve) => {
				release = resolve;
			});
			this.releaseBarrier = release;
		}
		while (this.activeWrites.size > 0) await Promise.allSettled(Array.from(this.activeWrites));
	}
	openBarrier() {
		if (this.releaseBarrier !== null) {
			const release = this.releaseBarrier;
			this.releaseBarrier = null;
			this.barrierPromise = null;
			release();
		}
	}
	isClosed() {
		return this.barrierPromise !== null;
	}
	getActiveCount() {
		return this.activeWrites.size;
	}
};
var storageWriteBarrier = new StorageWriteBarrier();
var storageResetEpoch = 0;
function getStorageResetEpoch() {
	return storageResetEpoch;
}
function setStorageResetEpoch(epoch) {
	storageResetEpoch = epoch;
}
function incrementStorageResetEpoch() {
	storageResetEpoch++;
	return storageResetEpoch;
}
function isStorageEpochStale(epoch) {
	if (epoch === void 0) return false;
	return epoch !== storageResetEpoch;
}
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
var GRAPH_NODE_TTL_MS = 2592e6;
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
	const checkUrlStr = (urlStr, context) => {
		if (urlStr === null || urlStr === void 0 || urlStr === "") return;
		if (urlStr.includes("?")) throw new Error(`[SecCheck] Unredacted query string detected in ${context} — storage aborted.`);
		if (urlStr.match(/:\/\/[^@/]+@/) !== null) throw new Error(`[SecCheck] Unredacted credentials detected in ${context} — storage aborted.`);
		const checkSegments = (segments) => {
			for (const seg of segments) {
				if (!seg || seg === "[id]" || seg === "[token]" || seg === "[redacted]") continue;
				const stem = seg.replace(/\.[a-zA-Z0-9]+$/, "");
				if (stem === "[id]" || stem === "[token]" || stem === "[redacted]") continue;
				const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg) || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(stem) || /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i.test(seg);
				const isJwt = /^eyJ/.test(seg) || /^eyJ/.test(stem);
				const isLongOpaque = seg.length >= 20 || stem.length >= 20 || /^[0-9a-f]{16,}$/i.test(stem);
				const isEmail = /@/.test(seg);
				if (isUuid || isJwt || isLongOpaque || isEmail) throw new Error(`[SecCheck] Unredacted sensitive token/path detected in ${context} — storage aborted.`);
			}
		};
		if (urlStr.includes("#")) throw new Error(`[SecCheck] Unredacted URL fragment detected in ${context} — storage aborted.`);
		const tokens = urlStr.split(/[\s;]+/).filter(Boolean);
		for (const token of tokens) if (token.includes("/")) try {
			checkSegments(new URL(token).pathname.split("/"));
		} catch {
			checkSegments(token.replace(/^[a-zA-Z0-9+.-]+:\/\/[^/]+/, "").split("/"));
		}
		else if (context === "serviceWorkerUrl") checkSegments([token]);
	};
	checkUrlStr(state.url, "state.url");
	if (state.coverage !== void 0 && state.coverage !== null) {
		checkUrlStr(state.coverage.serviceWorkerUrl, "serviceWorkerUrl");
		if (Array.isArray(state.coverage.metaCspPolicies)) for (const policy of state.coverage.metaCspPolicies) checkUrlStr(policy, "metaCspPolicies");
		if (Array.isArray(state.coverage.ledger)) for (const entry of state.coverage.ledger) checkUrlStr(entry.url, `ledger.url (${entry.type})`);
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
		if (hop) {
			checkUrlStr(hop.url, `hop[${i}].url`);
			checkHeaders(hop.headers, hop.rawHeaders, `hop[${i}]`);
		}
	}
	if (state.apiEndpoints instanceof Map) for (const [path, endpoint] of state.apiEndpoints.entries()) {
		checkUrlStr(path, `apiEndpoint[${path}].path`);
		checkUrlStr(endpoint.normalizedPath, `apiEndpoint[${path}].normalizedPath`);
		checkUrlStr(endpoint.lastHop.url, `apiEndpoint[${path}].lastHop.url`);
		checkHeaders(endpoint.lastHop.headers, endpoint.lastHop.rawHeaders, `apiEndpoint[${path}]`);
	}
	if (Array.isArray(state.findings)) {
		for (const f of state.findings) if (f.sourceUrl !== void 0 && f.sourceUrl !== "") checkUrlStr(f.sourceUrl, `finding.sourceUrl (${f.ruleId})`);
	}
}
var SessionStorage = {
	async getTabState(tabId) {
		const key = `${STORAGE_KEYS.TAB_PREFIX}${tabId}`;
		const raw = (await chrome.storage.session.get(key))[key];
		if (raw === void 0) return null;
		return deserializeTabState(raw);
	},
	async setTabState(state, epoch) {
		assertNoSensitiveSecrets(state);
		const opEpoch = epoch ?? getStorageResetEpoch();
		if (isStorageEpochStale(opEpoch)) return;
		await storageWriteBarrier.enter();
		if (isStorageEpochStale(opEpoch)) return;
		const opPromise = storageMutex.runExclusive(`tab:${state.tabId}`, async () => {
			if (isStorageEpochStale(opEpoch)) return;
			const serialized = serializeTabState(state);
			const key = `${STORAGE_KEYS.TAB_PREFIX}${state.tabId}`;
			try {
				if (isStorageEpochStale(opEpoch)) return;
				const writePromise = chrome.storage.session.set({ [key]: serialized });
				await storageWriteBarrier.track(writePromise);
			} catch (err) {
				recordStorageFailure(err);
				throw err;
			}
		});
		return storageWriteBarrier.track(opPromise);
	},
	async removeTabState(tabId, epoch) {
		const opEpoch = epoch ?? getStorageResetEpoch();
		if (isStorageEpochStale(opEpoch)) return;
		await storageWriteBarrier.enter();
		if (isStorageEpochStale(opEpoch)) return;
		const opPromise = storageMutex.runExclusive(`tab:${tabId}`, async () => {
			if (isStorageEpochStale(opEpoch)) return;
			const key = `${STORAGE_KEYS.TAB_PREFIX}${tabId}`;
			try {
				if (isStorageEpochStale(opEpoch)) return;
				const removePromise = chrome.storage.session.remove(key);
				await storageWriteBarrier.track(removePromise);
			} catch (err) {
				recordStorageFailure(err);
				throw err;
			}
		});
		return storageWriteBarrier.track(opPromise);
	},
	async clearAllTabStates() {
		if (typeof chrome === "undefined" || typeof chrome.storage === "undefined" || typeof chrome.storage.session === "undefined") return;
		await storageWriteBarrier.enter();
		try {
			const all = await chrome.storage.session.get(null);
			const tabKeys = Object.keys(all).filter((k) => k.startsWith(STORAGE_KEYS.TAB_PREFIX));
			if (tabKeys.length > 0) {
				const removePromise = chrome.storage.session.remove(tabKeys);
				await storageWriteBarrier.track(removePromise);
			}
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
	getAuthBaselineKey(origin, tabId) {
		if (typeof tabId === "number" && Number.isInteger(tabId) && tabId >= 0) return `${origin}#tab:${tabId}`;
		return origin;
	},
	async getAuthBaseline(origin, tabId) {
		if (!origin) return null;
		const baselineKey = this.getAuthBaselineKey(origin, tabId);
		const key = `${STORAGE_KEYS.AUTH_BASELINE_PREFIX}${baselineKey}`;
		return (await chrome.storage.session.get(key))[key] ?? null;
	},
	async setAuthBaseline(origin, baseline, tabId, epoch) {
		if (!origin) return;
		const opEpoch = epoch ?? getStorageResetEpoch();
		if (isStorageEpochStale(opEpoch)) return;
		await storageWriteBarrier.enter();
		if (isStorageEpochStale(opEpoch)) return;
		const resolvedTabId = tabId ?? baseline.tabId;
		const baselineKey = this.getAuthBaselineKey(origin, resolvedTabId);
		const opPromise = storageMutex.runExclusive(`auth_baseline:${baselineKey}`, async () => {
			if (isStorageEpochStale(opEpoch)) return;
			const key = `${STORAGE_KEYS.AUTH_BASELINE_PREFIX}${baselineKey}`;
			try {
				if (isStorageEpochStale(opEpoch)) return;
				const writePromise = chrome.storage.session.set({ [key]: baseline });
				await storageWriteBarrier.track(writePromise);
			} catch (err) {
				recordStorageFailure(err);
				throw err;
			}
		});
		return storageWriteBarrier.track(opPromise);
	},
	async removeAuthBaseline(origin, tabId, epoch) {
		if (!origin) return;
		const opEpoch = epoch ?? getStorageResetEpoch();
		if (isStorageEpochStale(opEpoch)) return;
		await storageWriteBarrier.enter();
		if (isStorageEpochStale(opEpoch)) return;
		const baselineKey = this.getAuthBaselineKey(origin, tabId);
		const key = `${STORAGE_KEYS.AUTH_BASELINE_PREFIX}${baselineKey}`;
		try {
			if (isStorageEpochStale(opEpoch)) return;
			const removePromise = chrome.storage.session.remove(key);
			await storageWriteBarrier.track(removePromise);
		} catch (err) {
			recordStorageFailure(err);
			throw err;
		}
	},
	async getAllAuthBaselines() {
		const all = await chrome.storage.session.get(null);
		const map = /* @__PURE__ */ new Map();
		for (const [k, v] of Object.entries(all)) if (k.startsWith(STORAGE_KEYS.AUTH_BASELINE_PREFIX)) {
			const baselineKey = k.slice(STORAGE_KEYS.AUTH_BASELINE_PREFIX.length);
			map.set(baselineKey, v);
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
/**
* Pure function to prune auth diff items according to age and count policies.
*/
function pruneAuthDiffItems(items, now, retainHistoryDays, maxHistoryPerOrigin = DEFAULT_MAX_HISTORY_PER_ORIGIN) {
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
	async recordOriginHistory(origin, item, epoch) {
		if (!origin) return;
		const opEpoch = epoch ?? getStorageResetEpoch();
		if (isStorageEpochStale(opEpoch)) return;
		await storageWriteBarrier.enter();
		if (isStorageEpochStale(opEpoch)) return;
		const opPromise = storageMutex.runExclusive(`origin:${origin}`, async () => {
			try {
				if (isStorageEpochStale(opEpoch)) return;
				const history = await this.getOriginHistory(origin);
				if (isStorageEpochStale(opEpoch)) return;
				const last = history[history.length - 1];
				if (last && last.score === item.score && last.grade === item.grade && item.timestamp - last.timestamp < 6e4) return;
				const settings = await this.getSettings();
				if (isStorageEpochStale(opEpoch)) return;
				const updated = pruneHistoryItems([...history, item], item.timestamp, settings.retainHistoryDays, settings.maxHistoryPerOrigin);
				const key = `${STORAGE_KEYS.HISTORY_PREFIX}${origin}`;
				if (isStorageEpochStale(opEpoch)) return;
				const writePromise = chrome.storage.local.set({ [key]: updated });
				await storageWriteBarrier.track(writePromise);
			} catch (err) {
				recordStorageFailure(err);
				throw err;
			}
		});
		return storageWriteBarrier.track(opPromise);
	},
	async pruneAllHistory(now = Date.now(), settings, epoch) {
		if (typeof chrome === "undefined" || chrome.storage?.local === void 0) return;
		const opEpoch = epoch ?? getStorageResetEpoch();
		if (isStorageEpochStale(opEpoch)) return;
		await storageWriteBarrier.enter();
		if (isStorageEpochStale(opEpoch)) return;
		try {
			const currentSettings = settings ?? await this.getSettings();
			if (isStorageEpochStale(opEpoch)) return;
			const all = await chrome.storage.local.get(null);
			if (isStorageEpochStale(opEpoch)) return;
			const updates = {};
			const toRemove = [];
			for (const [key, value] of Object.entries(all)) if (key.startsWith(STORAGE_KEYS.HISTORY_PREFIX) || key.startsWith("history:")) {
				if (Array.isArray(value)) {
					const pruned = pruneHistoryItems(value, now, currentSettings.retainHistoryDays, currentSettings.maxHistoryPerOrigin);
					if (pruned.length === 0) toRemove.push(key);
					else updates[key] = pruned;
				}
			} else if (key.startsWith(STORAGE_KEYS.AUTH_DIFF_PREFIX)) {
				if (Array.isArray(value)) {
					const pruned = pruneAuthDiffItems(value, now, currentSettings.retainHistoryDays, currentSettings.maxHistoryPerOrigin);
					if (pruned.length === 0) toRemove.push(key);
					else updates[key] = pruned;
				}
			} else if (key.startsWith(STORAGE_KEYS.GRAPH_PREFIX)) {
				if (typeof value === "object" && value !== null && "nodes" in value && Array.isArray(value.nodes)) {
					const graph = value;
					const cutoff = now - (currentSettings.retainHistoryDays > 0 ? currentSettings.retainHistoryDays * 24 * 60 * 60 * 1e3 : GRAPH_NODE_TTL_MS);
					const filteredNodes = graph.nodes.filter((n) => n.isApex || !n.lastSeen || n.lastSeen >= cutoff);
					const validHosts = new Set(filteredNodes.map((n) => n.hostname));
					const filteredEdges = graph.edges.filter((e) => validHosts.has(e.source) && validHosts.has(e.target));
					if (filteredNodes.length <= 1 && filteredEdges.length === 0 && (graph.lastUpdated || 0) < cutoff) toRemove.push(key);
					else if (filteredNodes.length !== graph.nodes.length || filteredEdges.length !== graph.edges.length) updates[key] = {
						...graph,
						nodes: filteredNodes,
						edges: filteredEdges,
						lastUpdated: now
					};
				}
			}
			if (isStorageEpochStale(opEpoch)) return;
			if (Object.keys(updates).length > 0) {
				const p1 = chrome.storage.local.set(updates);
				await storageWriteBarrier.track(p1);
			}
			if (toRemove.length > 0) {
				const p2 = chrome.storage.local.remove(toRemove);
				await storageWriteBarrier.track(p2);
			}
		} catch (err) {
			recordStorageFailure(err);
			throw err;
		}
	},
	async purgeOriginData(origin, epoch) {
		if (!origin || typeof chrome === "undefined" || chrome.storage?.local === void 0) return;
		const opEpoch = epoch ?? getStorageResetEpoch();
		if (isStorageEpochStale(opEpoch)) return;
		await storageWriteBarrier.enter();
		if (isStorageEpochStale(opEpoch)) return;
		const opPromise = storageMutex.runExclusive(`origin:${origin}`, async () => {
			try {
				if (isStorageEpochStale(opEpoch)) return;
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
						if (isStorageEpochStale(opEpoch)) return;
						if (graph) {
							graph.nodes = graph.nodes.filter((n) => n.hostname !== hostname);
							graph.edges = graph.edges.filter((e) => e.source !== hostname && e.target !== hostname);
							if (graph.nodes.length <= 1 && graph.nodes.every((n) => n.isApex)) keysToRemove.push(`${STORAGE_KEYS.GRAPH_PREFIX}${apex}`);
							else await this.saveGraph(graph, opEpoch);
						}
					}
				}
				if (hostname && hostname !== apex) keysToRemove.push(`${STORAGE_KEYS.GRAPH_PREFIX}${hostname}`);
				if (isStorageEpochStale(opEpoch)) return;
				const p1 = chrome.storage.local.remove(keysToRemove);
				await storageWriteBarrier.track(p1);
				if (typeof chrome !== "undefined" && chrome.storage?.session !== void 0) try {
					const allSession = await chrome.storage.session.get(null);
					if (isStorageEpochStale(opEpoch)) return;
					const baselinePrefix = `${STORAGE_KEYS.AUTH_BASELINE_PREFIX}${origin}`;
					const sessionKeysToRemove = Object.keys(allSession).filter((k) => k === baselinePrefix || k.startsWith(`${baselinePrefix}#tab:`));
					if (sessionKeysToRemove.length > 0) {
						const p2 = chrome.storage.session.remove(sessionKeysToRemove);
						await storageWriteBarrier.track(p2);
					}
				} catch {}
			} catch (err) {
				recordStorageFailure(err);
				throw err;
			}
		});
		return storageWriteBarrier.track(opPromise);
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
	async recordAuthDiff(origin, diff, epoch) {
		if (!origin) return;
		const opEpoch = epoch ?? getStorageResetEpoch();
		if (isStorageEpochStale(opEpoch)) return;
		await storageWriteBarrier.enter();
		if (isStorageEpochStale(opEpoch)) return;
		const opPromise = storageMutex.runExclusive(`auth_diff:${origin}`, async () => {
			try {
				if (isStorageEpochStale(opEpoch)) return;
				const history = await this.getAuthDiffHistory(origin);
				if (isStorageEpochStale(opEpoch)) return;
				const settings = await this.getSettings();
				if (isStorageEpochStale(opEpoch)) return;
				const updated = pruneAuthDiffItems([...history, diff], diff.timestamp || Date.now(), settings.retainHistoryDays, settings.maxHistoryPerOrigin);
				const key = `${STORAGE_KEYS.AUTH_DIFF_PREFIX}${origin}`;
				if (isStorageEpochStale(opEpoch)) return;
				const writePromise = chrome.storage.local.set({ [key]: updated });
				await storageWriteBarrier.track(writePromise);
			} catch (err) {
				recordStorageFailure(err);
				throw err;
			}
		});
		return storageWriteBarrier.track(opPromise);
	},
	async getGraph(apexDomain) {
		if (!apexDomain) return null;
		const key = `${STORAGE_KEYS.GRAPH_PREFIX}${apexDomain}`;
		return (await chrome.storage.local.get(key))[key] ?? null;
	},
	async saveGraph(graph, epoch) {
		if (!graph.apexDomain) return;
		const opEpoch = epoch ?? getStorageResetEpoch();
		if (isStorageEpochStale(opEpoch)) return;
		await storageWriteBarrier.enter();
		if (isStorageEpochStale(opEpoch)) return;
		const opPromise = storageMutex.runExclusive(`graph:${graph.apexDomain}`, async () => {
			try {
				if (isStorageEpochStale(opEpoch)) return;
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
				if (isStorageEpochStale(opEpoch)) return;
				const writePromise = chrome.storage.local.set({ [key]: boundedGraph });
				await storageWriteBarrier.track(writePromise);
			} catch (err) {
				recordStorageFailure(err);
				throw err;
			}
		});
		return storageWriteBarrier.track(opPromise);
	},
	/**
	* Atomically mutates the attack surface graph for an apex domain within a mutex.
	* Guarantees read-modify-write safety without lost updates.
	*/
	async mutateGraph(apexDomain, mutator, epoch) {
		if (!apexDomain) return null;
		const opEpoch = epoch ?? getStorageResetEpoch();
		if (isStorageEpochStale(opEpoch)) return null;
		await storageWriteBarrier.enter();
		if (isStorageEpochStale(opEpoch)) return null;
		const opPromise = storageMutex.runExclusive(`graph:${apexDomain}`, async () => {
			try {
				if (isStorageEpochStale(opEpoch)) return null;
				const current = await this.getGraph(apexDomain);
				if (isStorageEpochStale(opEpoch)) return null;
				const updated = mutator(current);
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
				if (isStorageEpochStale(opEpoch)) return null;
				const writePromise = chrome.storage.local.set({ [key]: boundedGraph });
				await storageWriteBarrier.track(writePromise);
				return boundedGraph;
			} catch (err) {
				recordStorageFailure(err);
				throw err;
			}
		});
		return storageWriteBarrier.track(opPromise);
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
	async deleteAllHistory(epoch) {
		const opEpoch = epoch ?? getStorageResetEpoch();
		if (isStorageEpochStale(opEpoch)) return;
		await storageWriteBarrier.enter();
		if (isStorageEpochStale(opEpoch)) return;
		try {
			const all = await chrome.storage.local.get(null);
			if (isStorageEpochStale(opEpoch)) return;
			const histKeys = Object.keys(all).filter((k) => k.startsWith(STORAGE_KEYS.HISTORY_PREFIX) || k.startsWith("history:"));
			if (histKeys.length > 0) {
				const p = chrome.storage.local.remove(histKeys);
				await storageWriteBarrier.track(p);
			}
		} catch (err) {
			recordStorageFailure(err);
			throw err;
		}
	},
	async deletePrivateRecords(epoch) {
		const opEpoch = epoch ?? getStorageResetEpoch();
		if (isStorageEpochStale(opEpoch)) return;
		await storageWriteBarrier.enter();
		if (isStorageEpochStale(opEpoch)) return;
		try {
			const all = await chrome.storage.session.get(null);
			if (isStorageEpochStale(opEpoch)) return;
			const toRemove = Object.entries(all).filter(([k, v]) => k.startsWith(STORAGE_KEYS.TAB_PREFIX) && typeof v === "object" && v !== null && v.isIncognito === true).map(([k]) => k);
			if (toRemove.length > 0) {
				const p = chrome.storage.session.remove(toRemove);
				await storageWriteBarrier.track(p);
			}
		} catch (err) {
			recordStorageFailure(err);
			throw err;
		}
	},
	async resetAllData() {
		incrementStorageResetEpoch();
		await storageWriteBarrier.closeBarrierAndDrain();
		try {
			await chrome.storage.local.clear();
			if (typeof chrome.storage.session !== "undefined") await chrome.storage.session.clear();
		} catch (err) {
			recordStorageFailure(err);
			throw err;
		} finally {
			storageWriteBarrier.openBarrier();
		}
	},
	async clearAll() {
		incrementStorageResetEpoch();
		await storageWriteBarrier.closeBarrierAndDrain();
		try {
			await chrome.storage.local.clear();
		} catch (err) {
			recordStorageFailure(err);
			throw err;
		} finally {
			storageWriteBarrier.openBarrier();
		}
	}
};
//#endregion
//#region src/shared/messaging.ts
/**
* Tracks open named ports by (portName, tabId).
* Stored in the service worker's global scope so it survives within
* one SW lifetime, but rebuilt from storage after revival.
*/
var PortRegistry = class {
	ports = /* @__PURE__ */ new Map();
	key(portName, tabId) {
		return `${portName}:${tabId}`;
	}
	register(port, tabId) {
		const name = port.name === "popup" || port.name === "sidepanel" ? port.name : POPUP_PORT_NAME;
		const k = this.key(name, tabId);
		this.ports.set(k, port);
		port.onDisconnect.addListener(() => {
			this.ports.delete(k);
		});
	}
	/** Remove registered ports for a closed or navigated tab. */
	unregisterTab(tabId) {
		for (const portName of [POPUP_PORT_NAME, SIDEPANEL_PORT_NAME]) this.ports.delete(this.key(portName, tabId));
	}
	/** Send a message to every open port for a given tab. */
	broadcast(tabId, msg) {
		for (const portName of [POPUP_PORT_NAME, SIDEPANEL_PORT_NAME]) {
			const port = this.ports.get(this.key(portName, tabId));
			if (port != null) portSend(port, msg);
		}
	}
	/** Send a message to every open port across all tabs. */
	broadcastAll(msg) {
		for (const port of this.ports.values()) portSend(port, msg);
	}
};
/** Fire-and-forget port send. Silently drops if port is disconnected. */
function portSend(port, msg) {
	try {
		port.postMessage(msg);
	} catch {}
}
/**
* Send a one-shot message to the service worker and await its reply.
* For use from UI scripts (popup, options).
*/
function sendToBackground(msg) {
	return new Promise((resolve, reject) => {
		chrome.runtime.sendMessage(msg, (response) => {
			if (chrome.runtime.lastError != null) {
				reject(new Error(chrome.runtime.lastError.message));
				return;
			}
			resolve(response);
		});
	});
}
//#endregion
export { GRADE_THRESHOLDS as A, sanitizeUrlForStorage as C, settingsTransitionPipeline as D, resolveCookieOverlaps as E, SEVERITY_ORDER as F, SIDEPANEL_PORT_NAME as I, POPUP_PORT_NAME as M, RESTRICTED_SCHEMES as N, BADGE_COLORS as O, SCORE_VERSION as P, sanitizeEvidence as S, normalizeCookieList as T, originFromUrl as _, SessionStorage as a, redactUrlPath as b, setStorageResetEpoch as c, checkDuplicateHeaders as d, extractSetCookieHeaders as f, normalizeHeaders as g, isSensitiveCookie as h, LocalStorage as i, MAINTENANCE_ALARM as j, DEFAULT_SETTINGS as k, checkSubdomainTrust as l, headersDiffer as m, portSend as n, getStorageResetEpoch as o, hasCspBypassProtection as p, sendToBackground as r, incrementStorageResetEpoch as s, PortRegistry as t, registrableDomain as u, parseCspDirectives as v, SettingsService as w, sanitizeCspPolicyForStorage as x, redactHeaderValue as y };

//# sourceMappingURL=messaging-BvANQDmr.js.map