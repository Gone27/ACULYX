import { describe, it, expect, beforeEach, vi } from 'vitest';
import { pruneHistoryItems, LocalStorage } from '../../src/shared/storage';
import { STORAGE_KEYS } from '../../src/shared/constants';
import type { OriginHistoryItem, SettingsV2 } from '../../src/shared/types';

describe('History retention pruning (pruneHistoryItems)', () => {
  const ONE_DAY_MS = 24 * 60 * 60 * 1000;
  const now = 1_700_000_000_000;

  it('prunes items older than retainHistoryDays when retainHistoryDays > 0', () => {
    const items: OriginHistoryItem[] = [
      { timestamp: now - 10 * ONE_DAY_MS, score: 80, grade: 'B' }, // 10 days old
      { timestamp: now - 6 * ONE_DAY_MS, score: 85, grade: 'B' },  // 6 days old
      { timestamp: now - 2 * ONE_DAY_MS, score: 95, grade: 'A' },  // 2 days old
      { timestamp: now, score: 100, grade: 'A' },                  // 0 days old
    ];

    const pruned = pruneHistoryItems(items, now, 7, 10);
    // Should keep 6 days, 2 days, and 0 days (cutoff is now - 7 days)
    expect(pruned).toHaveLength(3);
    expect(pruned[0]?.score).toBe(85);
    expect(pruned[1]?.score).toBe(95);
    expect(pruned[2]?.score).toBe(100);
  });

  it('preserves all entries regardless of age when retainHistoryDays is 0 (keep forever)', () => {
    const items: OriginHistoryItem[] = [
      { timestamp: now - 365 * ONE_DAY_MS, score: 60, grade: 'C' },
      { timestamp: now - 100 * ONE_DAY_MS, score: 75, grade: 'B' },
      { timestamp: now, score: 90, grade: 'A' },
    ];

    const pruned = pruneHistoryItems(items, now, 0, 10);
    expect(pruned).toHaveLength(3);
    expect(pruned[0]?.score).toBe(60);
  });

  it('enforces maxHistoryPerOrigin by retaining the newest entries', () => {
    const items: OriginHistoryItem[] = Array.from({ length: 15 }, (_, i) => ({
      timestamp: now - (15 - i) * 1000,
      score: 70 + i,
      grade: 'B' as const,
    }));

    const pruned = pruneHistoryItems(items, now, 30, 5);
    expect(pruned).toHaveLength(5);
    // Should retain the last 5 items
    expect(pruned[0]?.score).toBe(80);
    expect(pruned[4]?.score).toBe(84);
  });

  it('strictly respects precedence: age pruning runs first, count cap runs second', () => {
    // 8 old items (> 7 days) + 6 recent items (< 7 days)
    const oldItems: OriginHistoryItem[] = Array.from({ length: 8 }, (_, i) => ({
      timestamp: now - (10 + i) * ONE_DAY_MS,
      score: 50,
      grade: 'D' as const,
    }));

    const recentItems: OriginHistoryItem[] = Array.from({ length: 6 }, (_, i) => ({
      timestamp: now - i * ONE_DAY_MS,
      score: 90,
      grade: 'A' as const,
    })).reverse();

    const items = [...oldItems, ...recentItems];

    // Cap is 10, retain is 7 days
    // Age pruning removes 8 old items -> 6 recent items remain -> fits under cap of 10
    const pruned = pruneHistoryItems(items, now, 7, 10);
    expect(pruned).toHaveLength(6);
    expect(pruned.every((item) => item.score === 90)).toBe(true);
  });

  it('clamps maxHistoryPerOrigin between 1 and 50', () => {
    const items: OriginHistoryItem[] = Array.from({ length: 60 }, (_, i) => ({
      timestamp: now - (60 - i) * 1000,
      score: 80,
      grade: 'B' as const,
    }));

    // Cap = 0 -> clamped to 1
    const clampedUnder = pruneHistoryItems(items, now, 0, 0);
    expect(clampedUnder).toHaveLength(1);

    // Cap = 100 -> clamped to 50
    const clampedOver = pruneHistoryItems(items, now, 0, 100);
    expect(clampedOver).toHaveLength(50);
  });
});

describe('LocalStorage pruning and purging', () => {
  const ONE_DAY_MS = 24 * 60 * 60 * 1000;
  const now = 1_700_000_000_000;
  let mockStore: Record<string, unknown> = {};

  beforeEach(() => {
    mockStore = {};
    (globalThis as unknown as { chrome: unknown }).chrome = {
      storage: {
        local: {
          get: vi.fn((keys: unknown) => {
            if (keys === null) return Promise.resolve({ ...mockStore });
            if (typeof keys === 'string') return Promise.resolve({ [keys]: mockStore[keys] });
            if (Array.isArray(keys)) {
              const res: Record<string, unknown> = {};
              for (const k of keys as string[]) res[k] = mockStore[k];
              return Promise.resolve(res);
            }
            return Promise.resolve({});
          }),
          set: vi.fn((items: Record<string, unknown>) => {
            Object.assign(mockStore, items);
            return Promise.resolve();
          }),
          remove: vi.fn((keys: string | string[]) => {
            const list = Array.isArray(keys) ? keys : [keys];
            for (const k of list) delete mockStore[k];
            return Promise.resolve();
          }),
          clear: vi.fn(() => {
            mockStore = {};
            return Promise.resolve();
          }),
        },
        session: {
          get: vi.fn(() => Promise.resolve({})),
          set: vi.fn(() => Promise.resolve()),
          remove: vi.fn(() => Promise.resolve()),
        },
      },
    };
  });

  it('pruneAllHistory prunes stale entries and removes empty origin keys', async () => {
    const settings: SettingsV2 = {
      schemaVersion: 2,
      monitoringMode: 'per-site',
      severityFilter: ['critical'],
      retainHistoryDays: 7,
      maxHistoryPerOrigin: 10,
      sensitiveCookieNames: [],
      ignoredCookieNames: [],
      evaluationMode: false,
    };

    mockStore[`${STORAGE_KEYS.HISTORY_PREFIX}https://stale.com`] = [
      { timestamp: now - 15 * ONE_DAY_MS, score: 60, grade: 'C' },
    ];

    mockStore[`${STORAGE_KEYS.HISTORY_PREFIX}https://active.com`] = [
      { timestamp: now - 10 * ONE_DAY_MS, score: 60, grade: 'C' }, // pruned
      { timestamp: now - 2 * ONE_DAY_MS, score: 90, grade: 'A' },  // kept
    ];

    await LocalStorage.pruneAllHistory(now, settings);

    // Stale key has 0 items remaining -> should be removed
    expect(mockStore[`${STORAGE_KEYS.HISTORY_PREFIX}https://stale.com`]).toBeUndefined();

    // Active key has 1 item remaining
    const activeHistory = mockStore[`${STORAGE_KEYS.HISTORY_PREFIX}https://active.com`] as OriginHistoryItem[];
    expect(activeHistory).toHaveLength(1);
    expect(activeHistory[0]?.score).toBe(90);
  });

  it('purgeOriginData removes all history, auth diffs, and associated graph data for origin', async () => {
    const origin = 'https://app.example.com';
    mockStore[`${STORAGE_KEYS.HISTORY_PREFIX}${origin}`] = [{ timestamp: now, score: 90, grade: 'A' }];
    mockStore[`history:${origin}`] = [{ timestamp: now, score: 90, grade: 'A' }];
    mockStore[`${STORAGE_KEYS.AUTH_DIFF_PREFIX}${origin}`] = [{ timestamp: now, scoreDelta: 5 }];
    mockStore[`${STORAGE_KEYS.AUTH_BASELINE_PREFIX}${origin}`] = { origin };
    mockStore[`${STORAGE_KEYS.GRAPH_PREFIX}example.com`] = {
      apexDomain: 'example.com',
      nodes: [
        { hostname: 'example.com', isApex: true, lastSeen: now, discoveredVia: ['navigation'] },
        { hostname: 'app.example.com', isApex: false, lastSeen: now, discoveredVia: ['navigation'] },
        { hostname: 'api.example.com', isApex: false, lastSeen: now, discoveredVia: ['navigation'] },
      ],
      edges: [
        { source: 'app.example.com', target: 'example.com', type: 'subdomain', severity: 'low', provenance: 'inferred' },
        { source: 'api.example.com', target: 'example.com', type: 'subdomain', severity: 'low', provenance: 'inferred' },
      ],
    };

    await LocalStorage.purgeOriginData(origin);

    expect(mockStore[`${STORAGE_KEYS.HISTORY_PREFIX}${origin}`]).toBeUndefined();
    expect(mockStore[`history:${origin}`]).toBeUndefined();
    expect(mockStore[`${STORAGE_KEYS.AUTH_DIFF_PREFIX}${origin}`]).toBeUndefined();
    expect(mockStore[`${STORAGE_KEYS.AUTH_BASELINE_PREFIX}${origin}`]).toBeUndefined();

    // In the graph, app.example.com should be purged from nodes and edges
    const graph = mockStore[`${STORAGE_KEYS.GRAPH_PREFIX}example.com`] as { nodes: { hostname: string }[]; edges: { source: string }[] };
    expect(graph.nodes.some((n) => n.hostname === 'app.example.com')).toBe(false);
    expect(graph.nodes.some((n) => n.hostname === 'api.example.com')).toBe(true);
    expect(graph.edges.some((e) => e.source === 'app.example.com')).toBe(false);
    expect(graph.edges.some((e) => e.source === 'api.example.com')).toBe(true);
  });
});
