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
	alwaysIgnoreCookies: [],
	isPro: false
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
export { DEFAULT_SETTINGS as a, KEEPALIVE_PERIOD_MINUTES as c, SCORE_VERSION as d, SEVERITY_ORDER as f, BADGE_COLORS as i, POPUP_PORT_NAME as l, STORAGE_KEYS as m, portSend as n, GRADE_THRESHOLDS as o, SIDEPANEL_PORT_NAME as p, sendToBackground as r, KEEPALIVE_ALARM as s, PortRegistry as t, RESTRICTED_SCHEMES as u };

//# sourceMappingURL=messaging-BiWicsg3.js.map