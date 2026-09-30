/**
 * lifecycle.ts
 *
 * Manages MV3 service-worker keepalive (via chrome.alarms) and restores
 * in-memory tab state from chrome.storage.session after an SW revival.
 *
 * MV3 service workers are terminated after ~30 s of inactivity.  Firing a
 * periodic alarm forces the browser to wake the worker so it can keep
 * processing WebRequest events without dropping state.
 */

import { KEEPALIVE_ALARM, KEEPALIVE_PERIOD_MINUTES } from '../shared/constants';
import { SessionStorage } from '../shared/storage';
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
// Keepalive
// ---------------------------------------------------------------------------

/**
 * Registers the recurring keepalive alarm and its listener.
 *
 * Call once at SW startup (both fresh install and revival).
 * chrome.alarms.create is idempotent for a given name — calling it again
 * while the alarm already exists simply resets the period, which is fine.
 */
export function initLifecycle(): void {
  // Create (or re-arm) the periodic alarm that prevents the SW from sleeping.
  void chrome.alarms.create(KEEPALIVE_ALARM, {
    periodInMinutes: KEEPALIVE_PERIOD_MINUTES,
  });

  // The alarm listener does nothing intentionally: merely *receiving* the
  // alarm event is enough to wake/keep the service worker alive.
  chrome.alarms.onAlarm.addListener((alarm: chrome.alarms.Alarm): void => {
    if (alarm.name === KEEPALIVE_ALARM) {
      // Intentional no-op — wakeup is the sole purpose.
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
    tabStates.set(state.tabId, state);
  }

  const baselines = await SessionStorage.getAllAuthBaselines();
  for (const [origin, baseline] of baselines) {
    originAuthBaselines.set(origin, baseline);
  }
}
