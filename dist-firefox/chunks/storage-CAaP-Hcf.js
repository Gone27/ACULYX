import { a as DEFAULT_SETTINGS, m as STORAGE_KEYS } from "./messaging-BMItIkAu.js";
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
export { SessionStorage as n, LocalStorage as t };

//# sourceMappingURL=storage-CAaP-Hcf.js.map