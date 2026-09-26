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

export interface ServiceWorkerStatusMessage {
  type: 'SERVICE_WORKER_STATUS';
  status: 'controlled' | 'not-controlled';
  serviceWorkerUrl: string | null;
}

/** All messages that cross the service worker ↔ UI boundary. */
export type ExtensionMessage =
  | TabStateUpdateMessage
  | RequestStateMessage
  | StateResponseMessage
  | PermissionsChangedMessage
  | SettingsChangedMessage
  | ServiceWorkerStatusMessage;

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
