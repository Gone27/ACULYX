import type { TabState, Settings } from './types';
import { POPUP_PORT_NAME, SIDEPANEL_PORT_NAME } from './constants';

// ─── Message union ────────────────────────────────────────────────────────────

export interface TabStateUpdateMessage {
  type: 'TAB_STATE_UPDATE';
  state: TabState;
}

export interface RequestStateMessage {
  type: 'REQUEST_STATE';
  tabId: number;
}

export interface StateResponseMessage {
  type: 'STATE_RESPONSE';
  state: TabState | null;
}

export interface PermissionsChangedMessage {
  type: 'PERMISSIONS_CHANGED';
  granted: boolean;
  origins: string[];
}

export interface SettingsChangedMessage {
  type: 'SETTINGS_CHANGED';
  settings: Settings;
}

export interface SettingsChangedResponse {
  type: 'SETTINGS_CHANGED_RESPONSE';
  success: boolean;
  settings?: Settings;
  error?: string;
}

export interface ServiceWorkerStatusMessage {
  type: 'SERVICE_WORKER_STATUS';
  status: 'controlled' | 'not-controlled';
  serviceWorkerUrl: string | null;
  generation?: number;
  eventId?: string;
}

export interface MetaCspFoundMessage {
  type: 'META_CSP_FOUND';
  /** Raw CSP policy strings found in <meta http-equiv="Content-Security-Policy"> tags. */
  policies?: string[];
  generation?: number;
  eventId?: string;
}

export interface SriScanMessage {
  type: 'SRI_SCAN';
  externalScripts: number;
  missingIntegrity: number;
  /** External stylesheets (<link rel="stylesheet">) found on the page. */
  externalStylesheets?: number;
  /** Stylesheets missing an integrity attribute. */
  missingStyleIntegrity?: number;
  generation?: number;
  eventId?: string;
}

export interface RequestGraphMessage {
  type: 'REQUEST_GRAPH';
  apexDomain: string;
  tabId?: number;
}

export interface GraphResponseMessage {
  type: 'GRAPH_RESPONSE';
  graph: import('./types').AttackSurfaceGraph;
}

export interface GeneratePocMessage {
  type: 'GENERATE_POC';
  tabId: number;
  pocType: 'clickjacking' | 'coop';
}

export interface GeneratePocResponse {
  type: 'GENERATE_POC_RESPONSE';
  success: boolean;
  error?: string;
  url?: string;
}

export interface ResetAllDataMessage {
  type: 'RESET_ALL_DATA';
}

export interface ResetAllDataResponse {
  type: 'RESET_ALL_DATA_RESPONSE';
  success: boolean;
  error?: string;
}

export interface DomLeadsCollectedMessage {
  type: 'DOM_LEADS_COLLECTED';
  tabId?: number;
  url: string;
  origin: string;
  generation?: number;
  data: {
    forms: Array<{ action: string; method: string; inputNames: string[] }>;
    iframes: Array<{ src: string; sandbox: string; allow: string }>;
    scripts: Array<{ src: string; inlineContent?: string; sourceMappingURL?: string }>;
    links: Array<{ href: string; rel?: string }>;
    metaTags: Array<{ name: string; content: string; generator?: string }>;
    comments: string[];
    hydrationGlobals: {
      nextData?: string;
      nuxt?: string;
      initialState?: string;
      apolloState?: string;
      env?: string;
    };
    resourceTiming: string[];
    storageKeyNames: {
      localStorage: string[];
      sessionStorage: string[];
    };
  };
}

export interface MainWorldLeadsEventMessage {
  type: 'MAIN_WORLD_LEADS_EVENT';
  tabId?: number;
  url: string;
  origin: string;
  generation?: number;
  event: {
    eventType: 'sink' | 'postmessage_call' | 'postmessage_listener' | 'storage_write';
    sinkName?: string;
    sourceValue?: string;
    targetOrigin?: string;
    hasOriginCheck?: boolean;
    storageKey?: string;
    tokenShape?: string;
    location?: string;
    details?: string;
  };
}

export interface GetLeadsStateMessage {
  type: 'GET_LEADS_STATE';
  tabId?: number;
  origin?: string;
}

export interface LeadStateUpdateMessage {
  type: 'LEAD_STATE_UPDATE';
  tabId?: number;
  origin: string;
  leads: import('../leads/types').Lead[];
  activeChains?: Array<{ chain: import('../leads/types').ChainRule; matchedLeads: import('../leads/types').Lead[] }>;
  stats?: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

export interface LeadActionMessage {
  type: 'LEAD_ACTION';
  leadId: string;
  action: 'pin' | 'unpin' | 'triage';
  triageState?: import('../leads/types').Lead['triageState'];
  pinned?: boolean;
  origin?: string;
}

export interface LeadActionResponse {
  type: 'LEAD_ACTION_RESPONSE';
  success: boolean;
  leadId: string;
  error?: string;
}

export interface ReconGetMessage {
  type: 'RECON_GET';
  origin?: string;
}

export interface ReconGetResponse {
  type: 'RECON_GET_RESPONSE';
  memory: import('../leads/types').ReconMemory;
}

export interface ReconResetMessage {
  type: 'RECON_RESET';
  origin?: string;
}

export interface ReconResetResponse {
  type: 'RECON_RESET_RESPONSE';
  success: boolean;
}

export interface HunterRunProbeMessage {
  type: 'HUNTER_RUN_PROBE';
  probe: import('../leads/types').HunterProbeRequest;
  scopeStatus?: import('../leads/types').Lead['scopeStatus'];
}

export interface HunterRunProbeResponse {
  type: 'HUNTER_RUN_PROBE_RESPONSE';
  entry: import('../leads/types').HunterLedgerEntry;
}

export interface DevToolsLeadsCollectedMessage {
  type: 'DEVTOOLS_LEADS_COLLECTED';
  tabId?: number;
  leads: import('../leads/types').Lead[];
}

/** All messages that cross the service worker ↔ UI boundary. */
export type ExtensionMessage =
  | TabStateUpdateMessage
  | RequestStateMessage
  | StateResponseMessage
  | PermissionsChangedMessage
  | SettingsChangedMessage
  | SettingsChangedResponse
  | ServiceWorkerStatusMessage
  | MetaCspFoundMessage
  | SriScanMessage
  | RequestGraphMessage
  | GraphResponseMessage
  | GeneratePocMessage
  | GeneratePocResponse
  | ResetAllDataMessage
  | ResetAllDataResponse
  | DomLeadsCollectedMessage
  | MainWorldLeadsEventMessage
  | GetLeadsStateMessage
  | LeadStateUpdateMessage
  | LeadActionMessage
  | LeadActionResponse
  | ReconGetMessage
  | ReconGetResponse
  | ReconResetMessage
  | ReconResetResponse
  | HunterRunProbeMessage
  | HunterRunProbeResponse
  | DevToolsLeadsCollectedMessage;

// ─── Port registry ────────────────────────────────────────────────────────────

/**
 * Tracks open named ports by (portName, tabId).
 * Stored in the service worker's global scope so it survives within
 * one SW lifetime, but rebuilt from storage after revival.
 */
export class PortRegistry {
  private readonly ports = new Map<string, chrome.runtime.Port>();

  private key(portName: string, tabId: number): string {
    return `${portName}:${tabId}`;
  }

  register(port: chrome.runtime.Port, tabId: number): void {
    const name = port.name === POPUP_PORT_NAME || port.name === SIDEPANEL_PORT_NAME
      ? port.name
      : POPUP_PORT_NAME;
    const k = this.key(name, tabId);
    this.ports.set(k, port);
    port.onDisconnect.addListener(() => {
      this.ports.delete(k);
    });
  }

  /** Remove registered ports for a closed or navigated tab. */
  unregisterTab(tabId: number): void {
    for (const portName of [POPUP_PORT_NAME, SIDEPANEL_PORT_NAME]) {
      this.ports.delete(this.key(portName, tabId));
    }
  }

  /** Send a message to every open port for a given tab. */
  broadcast(tabId: number, msg: ExtensionMessage): void {
    for (const portName of [POPUP_PORT_NAME, SIDEPANEL_PORT_NAME]) {
      const port = this.ports.get(this.key(portName, tabId));
      if (port != null) {
        portSend(port, msg);
      }
    }
  }

  /** Send a message to every open port across all tabs. */
  broadcastAll(msg: ExtensionMessage): void {
    for (const port of this.ports.values()) {
      portSend(port, msg);
    }
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Fire-and-forget port send. Silently drops if port is disconnected. */
export function portSend(port: chrome.runtime.Port, msg: ExtensionMessage): void {
  try {
    port.postMessage(msg);
  } catch {
    // Port already disconnected — no action needed.
  }
}

/**
 * Send a one-shot message to the service worker and await its reply.
 * For use from UI scripts (popup, options).
 */
export function sendToBackground(msg: ExtensionMessage): Promise<ExtensionMessage> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(msg, (response: unknown) => {
      if (chrome.runtime.lastError != null) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      resolve(response as ExtensionMessage);
    });
  });
}
