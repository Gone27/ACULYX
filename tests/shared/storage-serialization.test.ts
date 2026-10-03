import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  KeyedAsyncMutex,
  LocalStorage,
  SessionStorage,
  assertNoSensitiveSecrets,
  getStorageHealth,
  resetStorageHealth,
  recordStorageFailure,
  MAX_GRAPH_NODES,
  MAX_GRAPH_EDGES,
  GRAPH_NODE_TTL_MS,
} from '../../src/shared/storage';
import type { AttackSurfaceGraph, GraphNode, GraphEdge, TabState } from '../../src/shared/types';

describe('KeyedAsyncMutex', () => {
  it('serializes operations with the same key', async () => {
    const mutex = new KeyedAsyncMutex();
    const order: number[] = [];

    const task1 = mutex.runExclusive('keyA', async () => {
      await new Promise((r) => setTimeout(r, 20));
      order.push(1);
    });

    const task2 = mutex.runExclusive('keyA', async () => {
      await Promise.resolve();
      order.push(2);
    });

    await Promise.all([task1, task2]);
    expect(order).toEqual([1, 2]);
  });

  it('allows operations with different keys to run concurrently', async () => {
    const mutex = new KeyedAsyncMutex();
    let keyBFinishedFirst = false;

    const taskA = mutex.runExclusive('keyA', async () => {
      await new Promise((r) => setTimeout(r, 40));
    });

    const taskB = mutex.runExclusive('keyB', async () => {
      await Promise.resolve();
      keyBFinishedFirst = true;
    });

    await taskB;
    expect(keyBFinishedFirst).toBe(true);
    await taskA;
  });

  it('releases lock and does not deadlock when a task throws', async () => {
    const mutex = new KeyedAsyncMutex();

    await expect(
      mutex.runExclusive('errKey', async () => {
        await Promise.resolve();
        throw new Error('Task failure');
      }),
    ).rejects.toThrow('Task failure');

    expect(mutex.isLocked('errKey')).toBe(false);

    // Subsequent operation on the same key must proceed normally
    const result = await mutex.runExclusive('errKey', async () => {
      await Promise.resolve();
      return 'success';
    });
    expect(result).toBe('success');
  });
});

describe('StorageHealth tracking', () => {
  beforeEach(() => {
    resetStorageHealth();
  });

  it('starts in healthy non-degraded state', () => {
    const health = getStorageHealth();
    expect(health.isDegraded).toBe(false);
    expect(health.lastError).toBeNull();
    expect(health.lastErrorTimestamp).toBeNull();
  });

  it('records failure and marks storage as degraded', () => {
    recordStorageFailure(new Error('QuotaExceeded'));
    const health = getStorageHealth();
    expect(health.isDegraded).toBe(true);
    expect(health.lastError).toBe('QuotaExceeded');
    expect(health.lastErrorTimestamp).toBeGreaterThan(0);
  });

  it('resets back to healthy on resetStorageHealth', () => {
    recordStorageFailure('Custom error string');
    expect(getStorageHealth().isDegraded).toBe(true);
    resetStorageHealth();
    expect(getStorageHealth().isDegraded).toBe(false);
    expect(getStorageHealth().lastError).toBeNull();
  });
});

describe('LocalStorage.mutateGraph serialization and bounds', () => {
  let mockStore: Record<string, unknown> = {};

  beforeEach(() => {
    mockStore = {};
    resetStorageHealth();

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
        },
        session: {
          get: vi.fn(() => Promise.resolve({})),
          set: vi.fn((items: Record<string, unknown>) => {
            Object.assign(mockStore, items);
            return Promise.resolve();
          }),
          remove: vi.fn((keys: string | string[]) => {
            const list = Array.isArray(keys) ? keys : [keys];
            for (const k of list) delete mockStore[k];
            return Promise.resolve();
          }),
        },
      },
    };
  });

  it('serializes concurrent mutations to prevent lost graph updates', async () => {
    const apex = 'example.com';
    const initialGraph: AttackSurfaceGraph = {
      apexDomain: apex,
      nodes: [{ hostname: apex, isApex: true, lastSeen: Date.now(), discoveredVia: ['navigation'] }],
      edges: [],
      isPro: false,
      lastUpdated: Date.now(),
    };
    await LocalStorage.saveGraph(initialGraph);

    // Launch two concurrent mutations
    const op1 = LocalStorage.mutateGraph(apex, (current): AttackSurfaceGraph => {
      const g = current ?? initialGraph;
      const newNode: GraphNode = {
        hostname: 'sub1.example.com',
        isApex: false,
        lastSeen: Date.now(),
        discoveredVia: ['api'],
      };
      const newEdge: GraphEdge = {
        source: apex,
        target: 'sub1.example.com',
        type: 'csp',
        severity: 'info',
      };
      return {
        ...g,
        nodes: [...g.nodes, newNode],
        edges: [...g.edges, newEdge],
      };
    });

    const op2 = LocalStorage.mutateGraph(apex, (current): AttackSurfaceGraph => {
      const g = current ?? initialGraph;
      const newNode: GraphNode = {
        hostname: 'sub2.example.com',
        isApex: false,
        lastSeen: Date.now(),
        discoveredVia: ['api'],
      };
      const newEdge: GraphEdge = {
        source: apex,
        target: 'sub2.example.com',
        type: 'csp',
        severity: 'info',
      };
      return {
        ...g,
        nodes: [...g.nodes, newNode],
        edges: [...g.edges, newEdge],
      };
    });

    await Promise.all([op1, op2]);

    const finalGraph = await LocalStorage.getGraph(apex);
    expect(finalGraph).not.toBeNull();
    const hostnames = finalGraph?.nodes.map((n) => n.hostname) ?? [];
    expect(hostnames).toContain('example.com');
    expect(hostnames).toContain('sub1.example.com');
    expect(hostnames).toContain('sub2.example.com');
    expect(finalGraph?.edges).toHaveLength(2);
  });

  it('bounds graph nodes to MAX_GRAPH_NODES (100) and preserves apex node', async () => {
    const apex = 'target.com';
    const now = Date.now();
    const nodes: GraphNode[] = [
      { hostname: apex, isApex: true, lastSeen: now - 1000, discoveredVia: ['navigation'] },
      ...Array.from({ length: 120 }, (_, i): GraphNode => ({
        hostname: `sub${i}.target.com`,
        isApex: false,
        lastSeen: now - i * 10,
        discoveredVia: ['api'],
      })),
    ];

    const graph: AttackSurfaceGraph = {
      apexDomain: apex,
      nodes,
      edges: [],
      isPro: true,
      lastUpdated: now,
    };

    await LocalStorage.saveGraph(graph);

    const saved = await LocalStorage.getGraph(apex);
    expect(saved).not.toBeNull();
    expect(saved?.nodes.length).toBeLessThanOrEqual(MAX_GRAPH_NODES);
    expect(saved?.nodes.some((n) => n.isApex)).toBe(true);
  });

  it('evicts nodes older than GRAPH_NODE_TTL_MS and prunes dangling edges', async () => {
    const apex = 'example.org';
    const now = Date.now();
    const expiredTimestamp = now - (GRAPH_NODE_TTL_MS + 1000);

    const graph: AttackSurfaceGraph = {
      apexDomain: apex,
      nodes: [
        { hostname: apex, isApex: true, lastSeen: now, discoveredVia: ['navigation'] },
        { hostname: 'fresh.example.org', isApex: false, lastSeen: now, discoveredVia: ['api'] },
        { hostname: 'expired.example.org', isApex: false, lastSeen: expiredTimestamp, discoveredVia: ['api'] },
      ],
      edges: [
        { source: apex, target: 'fresh.example.org', type: 'csp', severity: 'info' },
        { source: apex, target: 'expired.example.org', type: 'csp', severity: 'info' }, // Dangling after eviction
      ],
      isPro: true,
      lastUpdated: now,
    };

    await LocalStorage.saveGraph(graph);

    const saved = await LocalStorage.getGraph(apex);
    expect(saved).not.toBeNull();
    const nodeHosts = saved?.nodes.map((n) => n.hostname) ?? [];
    expect(nodeHosts).toContain('example.org');
    expect(nodeHosts).toContain('fresh.example.org');
    expect(nodeHosts).not.toContain('expired.example.org');

    // Edge pointing to expired host must be pruned
    expect(saved?.edges).toHaveLength(1);
    expect(saved?.edges[0]?.target).toBe('fresh.example.org');
  });

  it('bounds edges to MAX_GRAPH_EDGES (150)', async () => {
    const apex = 'edges.com';
    const now = Date.now();
    const nodes: GraphNode[] = [
      { hostname: apex, isApex: true, lastSeen: now, discoveredVia: ['navigation'] },
      ...Array.from({ length: 50 }, (_, i): GraphNode => ({
        hostname: `sub${i}.edges.com`,
        isApex: false,
        lastSeen: now,
        discoveredVia: ['api'],
      })),
    ];

    const edges: GraphEdge[] = Array.from({ length: 200 }, (_, i) => ({
      source: apex,
      target: `sub${i % 50}.edges.com`,
      type: 'csp' as const,
      severity: 'info' as const,
    }));

    const graph: AttackSurfaceGraph = {
      apexDomain: apex,
      nodes,
      edges,
      isPro: true,
      lastUpdated: now,
    };

    await LocalStorage.saveGraph(graph);

    const saved = await LocalStorage.getGraph(apex);
    expect(saved?.edges.length).toBeLessThanOrEqual(MAX_GRAPH_EDGES);
  });

  it('records storage failure in StorageHealth when chrome.storage throws', async () => {
    (globalThis as unknown as { chrome: { storage: { local: { set: unknown } } } }).chrome.storage.local.set = vi
      .fn()
      .mockRejectedValue(new Error('Disk full'));

    const graph: AttackSurfaceGraph = {
      apexDomain: 'fail.com',
      nodes: [{ hostname: 'fail.com', isApex: true, lastSeen: Date.now(), discoveredVia: ['navigation'] }],
      edges: [],
      isPro: false,
      lastUpdated: Date.now(),
    };

    await expect(LocalStorage.saveGraph(graph)).rejects.toThrow('Disk full');

    const health = getStorageHealth();
    expect(health.isDegraded).toBe(true);
    expect(health.lastError).toBe('Disk full');
  });
});

describe('assertNoSensitiveSecrets & SessionStorage guard verification', () => {
  const createBaseState = (): TabState => ({
    tabId: 101,
    origin: 'https://example.com',
    url: 'https://example.com/dashboard',
    hops: [
      {
        requestId: 'req-1',
        url: 'https://example.com/dashboard',
        status: 200,
        headers: {
          'set-cookie': 'session=[REDACTED]; Path=/; Secure; HttpOnly',
        },
        rawHeaders: [
          { name: 'Set-Cookie', value: 'session=[REDACTED]; Path=/; Secure; HttpOnly' },
        ],
        fromCache: false,
        isHstsUpgrade: false,
        capturedAt: 'onResponseStarted',
        headersDiffer: false,
        timestamp: Date.now(),
      },
    ],
    cookies: [
      {
        name: 'session',
        domain: 'example.com',
        path: '/',
        secure: true,
        httpOnly: true,
        sameSite: 'lax',
        session: true,
        expiresAt: null,
        partitioned: false,
        setByJs: false,
        isThirdParty: false,
        domainAttributePresent: true,
      },
    ],
    findings: [],
    grade: 'A',
    score: 95,
    qualityScore: 90,
    qualityGrade: 'A',
    scoreVersion: '1.0.0',
    scoreBreakdown: [],
    coverage: {
      hopsExpected: 1,
      hopsCaptured: 1,
      hasCache: false,
      hasServiceWorker: false,
      serviceWorkerStatus: 'not-controlled',
      serviceWorkerUrl: null,
      isRestricted: false,
      metaCspFound: false,
      metaCspPolicies: [],
    },
    subdomainTrust: { hasEscalationPath: false, vectors: [] },
    monitoredByUser: true,
    updatedAt: Date.now(),
  });

  it('rejects raw cookie value attribute in cookies array', () => {
    const state = createBaseState();
    (state.cookies[0] as unknown as { value: string }).value = 'SECRET_COOKIE_VALUE';
    expect(() => assertNoSensitiveSecrets(state)).toThrowError(/Cookie value detected on session/);
  });

  it('rejects serviceWorkerUrl with query parameters', () => {
    const state = createBaseState();
    state.coverage.serviceWorkerUrl = 'https://example.com/sw.js?token=secret123';
    expect(() => assertNoSensitiveSecrets(state)).toThrowError(/Unredacted query string detected in serviceWorkerUrl/);
  });

  it('rejects serviceWorkerUrl with embedded credentials', () => {
    const state = createBaseState();
    state.coverage.serviceWorkerUrl = 'https://admin:pass123@example.com/sw.js';
    expect(() => assertNoSensitiveSecrets(state)).toThrowError(/Unredacted credentials detected in serviceWorkerUrl/);
  });

  it('rejects serviceWorkerUrl with unredacted UUID path segment', () => {
    const state = createBaseState();
    state.coverage.serviceWorkerUrl = 'https://example.com/worker/550e8400-e29b-41d4-a716-446655440000.js';
    expect(() => assertNoSensitiveSecrets(state)).toThrowError(/Unredacted sensitive token\/path detected in serviceWorkerUrl/);
  });

  it('rejects serviceWorkerUrl with unredacted JWT path segment', () => {
    const state = createBaseState();
    state.coverage.serviceWorkerUrl = 'https://example.com/api/eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozG6tPqSTcT3M7W-Tss8T_mAmc8G_6bB5g';
    expect(() => assertNoSensitiveSecrets(state)).toThrowError(/Unredacted sensitive token\/path detected in serviceWorkerUrl/);
  });

  it('rejects serviceWorkerUrl with 32-character hex token', () => {
    const state = createBaseState();
    state.coverage.serviceWorkerUrl = 'https://example.com/sw/4a8f9c2d1e0b3a7f8e9d0c1b2a3f4e5d.js';
    expect(() => assertNoSensitiveSecrets(state)).toThrowError(/Unredacted sensitive token\/path detected in serviceWorkerUrl/);
  });

  it('rejects metaCspPolicies with unredacted sensitive tokens', () => {
    const state = createBaseState();
    state.coverage.metaCspPolicies = [
      "default-src 'self'; report-uri https://collector.example.com/report/550e8400-e29b-41d4-a716-446655440000.js",
    ];
    expect(() => assertNoSensitiveSecrets(state)).toThrowError(/Unredacted sensitive token\/path detected in metaCspPolicies/);
  });

  it('allows cleanly sanitized serviceWorkerUrl and metaCspPolicies', () => {
    const state = createBaseState();
    state.coverage.serviceWorkerUrl = 'https://example.com/worker/[id]';
    state.coverage.metaCspPolicies = [
      "default-src 'self'; report-uri https://collector.example.com/report/[id]",
    ];
    expect(() => assertNoSensitiveSecrets(state)).not.toThrow();
  });

  it('SessionStorage.setTabState enforces assertNoSensitiveSecrets', async () => {
    const badState = createBaseState();
    badState.coverage.serviceWorkerUrl = 'https://example.com/sw.js?token=secret123';

    await expect(SessionStorage.setTabState(badState)).rejects.toThrowError(/Unredacted query string/);

    const goodState = createBaseState();
    goodState.coverage.serviceWorkerUrl = 'https://example.com/sw.js';
    await expect(SessionStorage.setTabState(goodState)).resolves.toBeUndefined();
  });
});

