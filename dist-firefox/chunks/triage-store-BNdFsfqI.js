//#region src/shared/reporting/triage-store.ts
var TRIAGE_STORAGE_PREFIX = "triage:";
var VALID_REVIEW_STATES = [
	"unreviewed",
	"needs-manual-verification",
	"verified-by-researcher",
	"not-reproducible",
	"not-a-finding"
];
function isValidReviewState(state) {
	return typeof state === "string" && VALID_REVIEW_STATES.includes(state);
}
/** In-memory fallback map for test environments and incognito sessions. */
var memoryStore = /* @__PURE__ */ new Map();
var incognitoStore = /* @__PURE__ */ new Map();
function getStorageKey(findingId) {
	return `${TRIAGE_STORAGE_PREFIX}${findingId}`;
}
function hasLocalStorage() {
	return typeof chrome !== "undefined" && Boolean(chrome.storage) && Boolean(chrome.storage.local);
}
var TriageStore = class {
	/**
	* Retrieves the triage annotation for a specific finding.
	* If isIncognito is true, searches the ephemeral incognito store first.
	*/
	static async getAnnotation(findingId, options) {
		if (!findingId || typeof findingId !== "string") return null;
		if (options?.isIncognito === true) return incognitoStore.get(findingId) ?? null;
		if (!hasLocalStorage()) return memoryStore.get(findingId) ?? null;
		try {
			const key = getStorageKey(findingId);
			const raw = (await chrome.storage.local.get(key))[key];
			if (raw !== void 0 && typeof raw === "object" && raw !== null) {
				const item = raw;
				if (typeof item.findingId === "string" && item.findingId.length > 0 && isValidReviewState(item.state)) return item;
			}
			return null;
		} catch {
			return memoryStore.get(findingId) ?? null;
		}
	}
	/**
	* Sets or updates a triage annotation for a finding.
	* Strictly decoupled: does not mutate the scanner finding.
	* If isIncognito is true, stores ONLY in the ephemeral incognito memory store.
	*/
	static async setAnnotation(findingId, state, notes, options) {
		if (!findingId || typeof findingId !== "string") throw new Error("Invalid findingId: non-empty string required");
		if (!isValidReviewState(state)) throw new Error(`Invalid ResearcherReviewState: ${String(state)}`);
		const annotation = {
			findingId,
			state,
			notes: typeof notes === "string" && notes.trim().length > 0 ? notes.trim() : void 0,
			updatedAt: Date.now()
		};
		if (options?.isIncognito === true) {
			incognitoStore.set(findingId, annotation);
			return annotation;
		}
		if (!hasLocalStorage()) {
			memoryStore.set(findingId, annotation);
			return annotation;
		}
		try {
			const key = getStorageKey(findingId);
			await chrome.storage.local.set({ [key]: annotation });
			memoryStore.set(findingId, annotation);
			return annotation;
		} catch {
			memoryStore.set(findingId, annotation);
			return annotation;
		}
	}
	/**
	* Removes a triage annotation for a finding.
	*/
	static async deleteAnnotation(findingId, options) {
		if (!findingId || typeof findingId !== "string") return false;
		if (options?.isIncognito === true) return incognitoStore.delete(findingId);
		let deleted = false;
		if (memoryStore.has(findingId)) {
			memoryStore.delete(findingId);
			deleted = true;
		}
		if (hasLocalStorage()) try {
			const key = getStorageKey(findingId);
			await chrome.storage.local.remove(key);
			deleted = true;
		} catch {}
		return deleted;
	}
	/**
	* Retrieves all triage annotations for the provided finding IDs or all stored annotations.
	*/
	static async getAnnotations(findingIds, options) {
		const result = {};
		if (options?.isIncognito === true) {
			if (findingIds && findingIds.length > 0) for (const id of findingIds) {
				const ann = incognitoStore.get(id);
				if (ann) result[id] = ann;
			}
			else for (const [id, ann] of incognitoStore.entries()) result[id] = ann;
			return result;
		}
		if (!hasLocalStorage()) {
			if (findingIds && findingIds.length > 0) for (const id of findingIds) {
				const ann = memoryStore.get(id);
				if (ann) result[id] = ann;
			}
			else for (const [id, ann] of memoryStore.entries()) result[id] = ann;
			return result;
		}
		try {
			if (findingIds !== void 0 && findingIds.length > 0) {
				const keys = findingIds.map(getStorageKey);
				const data = await chrome.storage.local.get(keys);
				for (const id of findingIds) {
					const raw = data[getStorageKey(id)];
					if (raw !== void 0 && isValidReviewState(raw.state)) result[id] = raw;
				}
			} else {
				const all = await chrome.storage.local.get(null);
				for (const [key, raw] of Object.entries(all)) if (key.startsWith("triage:")) {
					const id = key.slice(7);
					const ann = raw;
					if (ann !== void 0 && isValidReviewState(ann.state)) result[id] = ann;
				}
			}
			return result;
		} catch {
			if (findingIds !== void 0 && findingIds.length > 0) for (const id of findingIds) {
				const ann = memoryStore.get(id);
				if (ann !== void 0) result[id] = ann;
			}
			else for (const [id, ann] of memoryStore.entries()) result[id] = ann;
			return result;
		}
	}
	/**
	* Purges all persistent and in-memory triage annotations.
	*/
	static async clearAll(options) {
		if (options?.isIncognitoOnly === true) {
			incognitoStore.clear();
			return;
		}
		incognitoStore.clear();
		memoryStore.clear();
		if (hasLocalStorage()) try {
			const all = await chrome.storage.local.get(null);
			const keysToRemove = Object.keys(all).filter((k) => k.startsWith(TRIAGE_STORAGE_PREFIX));
			if (keysToRemove.length > 0) await chrome.storage.local.remove(keysToRemove);
		} catch {}
	}
	/**
	* Resets in-memory stores for testing.
	*/
	static _resetMemoryStores() {
		memoryStore.clear();
		incognitoStore.clear();
	}
};
//#endregion
export { TriageStore as t };

//# sourceMappingURL=triage-store-BNdFsfqI.js.map