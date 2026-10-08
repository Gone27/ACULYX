import { i as LocalStorage } from "./messaging-CTMeVYaN.js";
//#region src/shared/appearance.ts
/**
* src/shared/appearance.ts — Unified appearance preferences application
*
* Applies theme (system/dark/light), layout density (comfortable/compact),
* and reduced motion (system/always/never) across all extension surfaces:
* Options, Popup, and Side Panel.
*/
function applyAppearance(theme, density, reducedMotion, targetDocument = document) {
	const root = targetDocument.documentElement;
	if (theme !== void 0) {
		root.removeAttribute("data-theme");
		if (theme === "dark" || theme === "light") root.setAttribute("data-theme", theme);
	}
	if (density !== void 0 && targetDocument.body !== null) targetDocument.body.classList.toggle("density-compact", density === "compact");
	if (reducedMotion !== void 0) {
		root.removeAttribute("data-motion");
		if (reducedMotion === "always") root.setAttribute("data-motion", "reduce");
		else if (reducedMotion === "never") root.setAttribute("data-motion", "no-reduce");
	}
}
async function bootstrapAppearance(targetDocument = document) {
	try {
		const settings = await LocalStorage.getSettings();
		applyAppearance(settings.theme, settings.density, settings.reducedMotion, targetDocument);
	} catch {}
}
//#endregion
export { bootstrapAppearance as n, applyAppearance as t };

//# sourceMappingURL=appearance-Cjc7_Dji.js.map