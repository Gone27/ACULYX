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
export { isRestrictedUrl as n, isModeCaptureAllowed as t };

//# sourceMappingURL=gating-BKxraNh3.js.map