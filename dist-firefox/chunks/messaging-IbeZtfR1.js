const SCORE_VERSION = "1.2.0";
const RESTRICTED_SCHEMES = [
  "chrome://",
  "chrome-extension://",
  "devtools://",
  "about:",
  "data:",
  "blob:"
];
const BADGE_COLORS = {
  A: "#27ae60",
  B: "#2980b9",
  C: "#f39c12",
  D: "#e67e22",
  F: "#c0392b",
  "?": "#7f8c8d"
};
const SEVERITY_ORDER = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
  "pass"
];
const GRADE_THRESHOLDS = [
  { min: 90, grade: "A" },
  { min: 70, grade: "B" },
  { min: 50, grade: "C" },
  { min: 30, grade: "D" },
  { min: 0, grade: "F" }
];
const MAX_EVIDENCE_LENGTH = 500;
const STORAGE_KEYS = {
  SETTINGS: "settings",
  TAB_PREFIX: "tab:",
  HISTORY_PREFIX: "hist:",
  ONBOARDING_DISMISSED: "onboarding_dismissed"
};
const POPUP_PORT_NAME = "popup";
const SIDEPANEL_PORT_NAME = "sidepanel";
const KEEPALIVE_ALARM = "keepalive";
const KEEPALIVE_PERIOD_MINUTES = 0.4;
const DEFAULT_SETTINGS = {
  monitoringMode: "per-site",
  allowedOrigins: [],
  severityFilter: ["critical", "high", "medium", "low", "info"],
  retainHistoryDays: 7
};
const SessionStorage = {
  async getTabState(tabId) {
    const key = `${STORAGE_KEYS.TAB_PREFIX}${tabId}`;
    const result = await chrome.storage.session.get(key);
    return result[key] ?? null;
  },
  async setTabState(state) {
    for (const cookie of state.cookies) {
      if ("value" in cookie) {
        throw new Error(
          `[SecCheck] Cookie value detected on ${cookie.name} — storage aborted.`
        );
      }
    }
    const key = `${STORAGE_KEYS.TAB_PREFIX}${state.tabId}`;
    await chrome.storage.session.set({ [key]: state });
  },
  async removeTabState(tabId) {
    const key = `${STORAGE_KEYS.TAB_PREFIX}${tabId}`;
    await chrome.storage.session.remove(key);
  },
  async getAllTabStates() {
    const all = await chrome.storage.session.get(null);
    return Object.entries(all).filter(([k]) => k.startsWith(STORAGE_KEYS.TAB_PREFIX)).map(([, v]) => v);
  }
};
const LocalStorage = {
  async getSettings() {
    const result = await chrome.storage.local.get(STORAGE_KEYS.SETTINGS);
    const stored = result[STORAGE_KEYS.SETTINGS];
    return { ...DEFAULT_SETTINGS, ...stored };
  },
  async setSettings(settings) {
    await chrome.storage.local.set({ [STORAGE_KEYS.SETTINGS]: settings });
  },
  async getOriginHistory(origin) {
    if (!origin) return [];
    const key = `${STORAGE_KEYS.HISTORY_PREFIX}${origin}`;
    const result = await chrome.storage.local.get(key);
    return result[key] ?? [];
  },
  async recordOriginHistory(origin, item) {
    if (!origin) return;
    const history = await this.getOriginHistory(origin);
    const last = history[history.length - 1];
    if (last && last.score === item.score && last.grade === item.grade && item.timestamp - last.timestamp < 6e4) {
      return;
    }
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
class PortRegistry {
  ports = /* @__PURE__ */ new Map();
  key(portName, tabId) {
    return `${portName}:${tabId}`;
  }
  register(port, tabId) {
    const name = port.name === POPUP_PORT_NAME || port.name === SIDEPANEL_PORT_NAME ? port.name : POPUP_PORT_NAME;
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
      if (port != null) {
        portSend(port, msg);
      }
    }
  }
  /** Send a message to every open port across all tabs. */
  broadcastAll(msg) {
    for (const port of this.ports.values()) {
      portSend(port, msg);
    }
  }
}
function portSend(port, msg) {
  try {
    port.postMessage(msg);
  } catch {
  }
}
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
export {
  BADGE_COLORS as B,
  GRADE_THRESHOLDS as G,
  KEEPALIVE_ALARM as K,
  LocalStorage as L,
  MAX_EVIDENCE_LENGTH as M,
  POPUP_PORT_NAME as P,
  RESTRICTED_SCHEMES as R,
  SessionStorage as S,
  KEEPALIVE_PERIOD_MINUTES as a,
  SCORE_VERSION as b,
  SIDEPANEL_PORT_NAME as c,
  PortRegistry as d,
  SEVERITY_ORDER as e,
  portSend as p,
  sendToBackground as s
};
//# sourceMappingURL=messaging-IbeZtfR1.js.map
