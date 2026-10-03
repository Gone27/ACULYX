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
  | ResetAllDataResponse;

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
