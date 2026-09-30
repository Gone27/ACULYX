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
	ONBOARDING_DISMISSED: "onboarding_dismissed"
};
/** Runtime port name for popup ↔ service worker connection. */
var POPUP_PORT_NAME = "popup";
/**
* Runtime port name for side panel ↔ service worker connection.
* Channel is registered now; the panel UI ships in Phase 3.
*/
var SIDEPANEL_PORT_NAME = "sidepanel";
var KEEPALIVE_ALARM = "keepalive";
/** Period in minutes — must stay under the ~30 s Chrome idle threshold. */
var KEEPALIVE_PERIOD_MINUTES = .4;
var DEFAULT_SETTINGS = {
	monitoringMode: "per-site",
	allowedOrigins: [],
	severityFilter: [
		"critical",
		"high",
		"medium",
		"low",
		"info"
	],
	retainHistoryDays: 7,
	alwaysSensitiveCookies: [],
	alwaysIgnoreCookies: []
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
var SessionStorage = {
	async getTabState(tabId) {
		const key = `${STORAGE_KEYS.TAB_PREFIX}${tabId}`;
		const raw = (await chrome.storage.session.get(key))[key];
		if (raw === void 0) return null;
		return deserializeTabState(raw);
	},
	async setTabState(state) {
		for (const cookie of state.cookies) if ("value" in cookie) throw new Error(`[SecCheck] Cookie value detected on ${cookie.name} — storage aborted.`);
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
	}
};
var LocalStorage = {
	async getSettings() {
		const stored = (await chrome.storage.local.get(STORAGE_KEYS.SETTINGS))[STORAGE_KEYS.SETTINGS];
		return {
			...DEFAULT_SETTINGS,
			...stored
		};
	},
	async setSettings(settings) {
		await chrome.storage.local.set({ [STORAGE_KEYS.SETTINGS]: settings });
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
export { SessionStorage as a, GRADE_THRESHOLDS as c, POPUP_PORT_NAME as d, RESTRICTED_SCHEMES as f, SIDEPANEL_PORT_NAME as h, LocalStorage as i, KEEPALIVE_ALARM as l, SEVERITY_ORDER as m, portSend as n, BADGE_COLORS as o, SCORE_VERSION as p, sendToBackground as r, DEFAULT_SETTINGS as s, PortRegistry as t, KEEPALIVE_PERIOD_MINUTES as u };

//# sourceMappingURL=messaging-B3-Oxiul.js.map