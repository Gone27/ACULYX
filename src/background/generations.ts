/**
 * generations.ts
 *
 * Per-tab navigation generation counter.
 * Incremented on onBeforeNavigate (top-level frameId === 0).
 * Tags hops, API hops, cookie changes, and page signals.
 * Late arrivals for older generations are discarded immediately.
 */

export const tabGenerations = new Map<number, number>();

export function getTabGeneration(tabId: number): number {
  return tabGenerations.get(tabId) ?? 0;
}

export function incrementTabGeneration(tabId: number): number {
  const next = (tabGenerations.get(tabId) ?? 0) + 1;
  tabGenerations.set(tabId, next);
  return next;
}
