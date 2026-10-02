/**
 * lifecycle.ts
 *
 * Manages periodic maintenance (via chrome.alarms) and restores
 * in-memory tab state from chrome.storage.session after an SW revival.
 *
 * MV3 service workers are terminated after inactivity. Correctness relies
 * entirely on persistent storage and session hydration—never keepalive alarms.
 */

import { MAINTENANCE_ALARM, MAINTENANCE_PERIOD_MINUTES } from '../shared/constants';
import { SessionStorage, LocalStorage } from '../shared/storage';
import type { TabState, AuthBaseline } from '../shared/types';

// ---------------------------------------------------------------------------
// In-memory store
// ---------------------------------------------------------------------------

/**
 * Primary in-memory store for per-tab security analysis state.
 * Keyed by Chrome tabId.  Persisted to chrome.storage.session so it
 * survives SW restarts; re-hydrated via hydrateFromSession().
 */
export const tabStates: Map<number, TabState> = new Map();

/**
 * In-memory cache for origin pre/post auth baselines.
 * Persisted to chrome.storage.session so it survives SW restarts.
 */
export const originAuthBaselines: Map<string, AuthBaseline> = new Map();

// ---------------------------------------------------------------------------
// Maintenance alarm
// ---------------------------------------------------------------------------

/**
 * Registers the periodic maintenance alarm and its listener.
 *
 * Runs periodic history pruning sweeps and cleans up expired data.
 * Never uses keepalive alarms.
 */
export function initLifecycle(): void {
  void chrome.alarms.create(MAINTENANCE_ALARM, {
    periodInMinutes: MAINTENANCE_PERIOD_MINUTES,
  });

  chrome.alarms.onAlarm.addListener((alarm: chrome.alarms.Alarm): void => {
    if (alarm.name === MAINTENANCE_ALARM) {
      void LocalStorage.pruneAllHistory();
    }
  });
}

// ---------------------------------------------------------------------------
// Session hydration
// ---------------------------------------------------------------------------

/**
 * Loads all previously persisted TabState records from chrome.storage.session
 * into the in-memory {@link tabStates} map.
 *
 * Must be awaited before registering WebRequest listeners so that any
 * in-flight state from before the SW restart is available immediately.
 */
export async function hydrateFromSession(): Promise<void> {
  const all = await SessionStorage.getAllTabStates();

  for (const state of all) {
    const existing = tabStates.get(state.tabId);
    if (!existing || (state.updatedAt > existing.updatedAt)) {
      tabStates.set(state.tabId, state);
    }
  }

  const baselines = await SessionStorage.getAllAuthBaselines();
  for (const [origin, baseline] of baselines) {
    if (!originAuthBaselines.has(origin)) {
      originAuthBaselines.set(origin, baseline);
    }
  }

  // Initial maintenance sweep on SW startup/hydration
  void LocalStorage.pruneAllHistory();
}
