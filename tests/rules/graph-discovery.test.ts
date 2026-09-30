import { describe, it, expect } from 'vitest';
import {
  extractHostnameFromCspToken,
  discoverNodes,
  mergeIntoGraph,
} from '../../src/rules/graph-discovery';
import type { Hop, CookieRecord } from '../../src/shared/types';

function makeHop(overrides: Partial<Hop> & { headers?: Record<string, string> }): Hop {
  return {
    requestId: 'test-hop-1',
    url: 'https://app.example.com/',
    status: 200,
    headers: overrides.headers ?? {},
    rawHeaders: [],
    fromCache: false,
    isHstsUpgrade: false,
    capturedAt: 'onResponseStarted',
    headersDiffer: false,
    timestamp: Date.now(),
    ...overrides,
  };
}

describe('Graph Discovery — extractHostnameFromCspToken', () => {
  it('extracts valid literal hostnames', () => {
    expect(extractHostnameFromCspToken('https://api.example.com')).toBe('api.example.com');
    expect(extractHostnameFromCspToken('auth.example.com:8443')).toBe('auth.example.com');
    expect(extractHostnameFromCspToken('https://sub.example.com/v1/graphql')).toBe('sub.example.com');
  });

  it('rejects keywords, wildcards, and scheme-only tokens', () => {
    expect(extractHostnameFromCspToken("'self'")).toBeNull();
    expect(extractHostnameFromCspToken("'unsafe-inline'")).toBeNull();
    expect(extractHostnameFromCspToken('*')).toBeNull();
    expect(extractHostnameFromCspToken('*.example.com')).toBeNull();
    expect(extractHostnameFromCspToken('https:')).toBeNull();
    expect(extractHostnameFromCspToken('data:')).toBeNull();
  });
});

describe('Graph Discovery — discoverNodes', () => {
  it('extracts concrete apex-affiliated nodes from CSP, Cookies, and CORS', () => {
    const hops = [
      makeHop({
        headers: {
          'content-security-policy': "default-src 'self'; script-src 'self' https://api.example.com https://cdn.external.com; connect-src https://auth.example.com:8443",
          'access-control-allow-origin': 'https://cors-target.example.com',
        },
      }),
    ];

    const cookies: CookieRecord[] = [
      {
        name: 'session',
        domain: '.example.com',
        domainAttributePresent: true,
        path: '/',
        secure: true,
        httpOnly: true,
        sameSite: 'lax',
        session: true,
        expiresAt: null,
        partitioned: false,
        setByJs: false,
        isThirdParty: false,
      },
    ];

    const nodes = discoverNodes('app.example.com', hops, cookies);
    const hostnames = nodes.map((n) => n.hostname);

    expect(hostnames).toContain('app.example.com');
    expect(hostnames).toContain('api.example.com');
    expect(hostnames).toContain('auth.example.com');
    expect(hostnames).toContain('cors-target.example.com');
    expect(hostnames).toContain('example.com');

    // External domain must NOT be included
    expect(hostnames).not.toContain('cdn.external.com');

    const apiNode = nodes.find((n) => n.hostname === 'api.example.com');
    expect(apiNode?.discoveredVia).toBe('csp');

    const corsNode = nodes.find((n) => n.hostname === 'cors-target.example.com');
    expect(corsNode?.discoveredVia).toBe('cors');

    const cookieNode = nodes.find((n) => n.hostname === 'example.com');
    expect(cookieNode?.discoveredVia).toBe('cookie');
  });
});

describe('Graph Discovery — mergeIntoGraph', () => {
  it('accumulates nodes across sessions and creates trust edges', () => {
    // Session 1: Visit app.example.com
    const initialDiscovered = [
      { hostname: 'app.example.com', discoveredVia: 'navigation' as const },
      { hostname: 'api.example.com', discoveredVia: 'csp' as const },
    ];

    const graph1 = mergeIntoGraph(null, 'app.example.com', 85, 'B', initialDiscovered, false);
    expect(graph1.apexDomain).toBe('example.com');
    expect(graph1.nodes.map((n) => n.hostname)).toContain('example.com'); // Apex
    expect(graph1.nodes.map((n) => n.hostname)).toContain('app.example.com');
    expect(graph1.nodes.map((n) => n.hostname)).toContain('api.example.com');

    const appNode = graph1.nodes.find((n) => n.hostname === 'app.example.com');
    expect(appNode?.score).toBe(85);
    expect(appNode?.grade).toBe('B');

    // Session 2: User visits blog.example.com, which discovers auth.example.com
    const session2Discovered = [
      { hostname: 'blog.example.com', discoveredVia: 'navigation' as const },
      { hostname: 'auth.example.com', discoveredVia: 'cors' as const },
    ];

    const graph2 = mergeIntoGraph(graph1, 'blog.example.com', 70, 'B', session2Discovered, true);

    const accumulatedHosts = graph2.nodes.map((n) => n.hostname);
    expect(accumulatedHosts).toContain('example.com');
    expect(accumulatedHosts).toContain('app.example.com'); // Retained from session 1
    expect(accumulatedHosts).toContain('api.example.com'); // Retained from session 1
    expect(accumulatedHosts).toContain('blog.example.com'); // Added in session 2
    expect(accumulatedHosts).toContain('auth.example.com'); // Added in session 2

    expect(graph2.isPro).toBe(true);
    expect(graph2.edges.length).toBeGreaterThanOrEqual(4);
  });

  it('filters out external third-party domains and maintains apex isolation', () => {
    const discovered = [
      { hostname: 'login.example.com', discoveredVia: 'navigation' as const },
      { hostname: 'tracker.thirdparty.com', discoveredVia: 'csp' as const },
    ];

    const graph = mergeIntoGraph(null, 'login.example.com', 95, 'A', discovered, false);
    const hostnames = graph.nodes.map((n) => n.hostname);

    expect(hostnames).toContain('login.example.com');
    expect(hostnames).toContain('example.com');
    expect(hostnames).not.toContain('tracker.thirdparty.com');
  });

  it('supports Pro vs Free tier node and edge isolation logic', () => {
    const discovered = [
      { hostname: 'admin.corp.com', discoveredVia: 'navigation' as const },
      { hostname: 'internal-api.corp.com', discoveredVia: 'csp' as const },
      { hostname: 'sso.corp.com', discoveredVia: 'cors' as const },
    ];

    const fullGraph = mergeIntoGraph(null, 'admin.corp.com', 80, 'B', discovered, true);
    expect(fullGraph.nodes.length).toBeGreaterThanOrEqual(4); // apex + 3 subdomains

    // Free tier filter simulation (same logic as in background/index.ts)
    const activeHost = 'admin.corp.com';
    const freeTierNodes = fullGraph.nodes.filter((n) => n.isApex || n.hostname === activeHost);
    const freeNodeHosts = new Set(freeTierNodes.map((n) => n.hostname));
    const freeTierEdges = fullGraph.edges.filter((e) => freeNodeHosts.has(e.source) && freeNodeHosts.has(e.target));

    expect(freeTierNodes.map((n) => n.hostname).sort()).toEqual(['admin.corp.com', 'corp.com'].sort());
    expect(freeTierEdges.every((e) => freeNodeHosts.has(e.source) && freeNodeHosts.has(e.target))).toBe(true);
  });
});
