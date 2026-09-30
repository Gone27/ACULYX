/**
 * graph-discovery.ts
 *
 * Discovers concrete subdomains and trust relationships for the Attack Surface Graph.
 * Extracts literal (non-wildcard) hostnames sharing the registrable apex from:
 *   1. CSP source-list directives (script-src, connect-src, frame-src, default-src, etc.)
 *   2. Cookie Domain= attributes
 *   3. CORS Access-Control-Allow-Origin response headers
 */

import type { Hop, CookieRecord, DiscoveredNode, GraphNode, GraphEdge, AttackSurfaceGraph, Grade, Severity } from '../shared/types';
import { registrableDomain } from './headers/subdomain-trust';

/**
 * Extracts candidate hostnames from a CSP source token.
 * Strips scheme (https://), port (:443), and paths (/api).
 * Returns null if token is a keyword ('self'), wildcard (*), or scheme-only (https:).
 */
export function extractHostnameFromCspToken(token: string): string | null {
  const trimmed = token.trim().toLowerCase();
  if (!trimmed || trimmed.startsWith("'") || trimmed.endsWith("'")) return null;
  if (trimmed === '*' || trimmed.startsWith('*.') || trimmed.endsWith(':')) return null;

  try {
    // If it has a scheme, parse via URL
    if (trimmed.includes('://')) {
      const u = new URL(trimmed);
      return u.hostname;
    }

    // Otherwise split host from port/path
    const withoutPath = trimmed.split('/')[0] ?? '';
    const withoutPort = withoutPath.split(':')[0] ?? '';
    if (withoutPort.includes('.') && !withoutPort.includes('*')) {
      return withoutPort;
    }
  } catch {
    return null;
  }

  return null;
}

/**
 * Scans captured hops and cookies for concrete hostnames belonging to the apex domain.
 */
export function discoverNodes(
  currentHostname: string,
  hops: Hop[],
  cookies: CookieRecord[],
  apiEndpoints?: Map<string, import('../shared/types').ApiEndpointState>,
): DiscoveredNode[] {
  const apex = registrableDomain(currentHostname) ?? currentHostname;
  const discoveredMap = new Map<string, DiscoveredNode['discoveredVia']>();

  // 1. Current host is always a navigation node
  discoveredMap.set(currentHostname.toLowerCase(), 'navigation');

  // 2. Discover from CSP source-list tokens
  for (const hop of hops) {
    const csp = hop.headers['content-security-policy'] ?? hop.headers['content-security-policy-report-only'];
    if (csp != null && csp.length > 0) {
      const tokens = csp.split(/[\s;]+/);
      for (const token of tokens) {
        const host = extractHostnameFromCspToken(token);
        if (host != null && host.length > 0 && (host === apex || host.endsWith(`.${apex}`))) {
          if (!discoveredMap.has(host)) {
            discoveredMap.set(host, 'csp');
          }
        }
      }
    }
  }

  // 3. Discover from Cookie Domain attributes
  for (const cookie of cookies) {
    if (cookie.domain != null && cookie.domain.length > 0) {
      const cleanDomain = cookie.domain.replace(/^\./, '').toLowerCase();
      if (cleanDomain.length > 0 && (cleanDomain === apex || cleanDomain.endsWith(`.${apex}`))) {
        if (!discoveredMap.has(cleanDomain)) {
          discoveredMap.set(cleanDomain, 'cookie');
        }
      }
    }
  }

  // 4. Discover from CORS Access-Control-Allow-Origin on document hops
  for (const hop of hops) {
    const acao = hop.headers['access-control-allow-origin']?.trim();
    if (acao != null && acao.length > 0 && acao !== '*' && acao !== 'null') {
      try {
        const u = new URL(acao);
        const host = u.hostname.toLowerCase();
        if (host === apex || host.endsWith(`.${apex}`)) {
          if (!discoveredMap.has(host)) {
            discoveredMap.set(host, 'cors');
          }
        }
      } catch {
        // Not a full URL, skip
      }
    }
  }

  // 5. Discover from captured API endpoints (endpoint host and CORS headers)
  if (apiEndpoints != null) {
    for (const endpoint of apiEndpoints.values()) {
      const hop = endpoint.lastHop;

      try {
        const u = new URL(hop.url);
        const host = u.hostname.toLowerCase();
        if (host === apex || host.endsWith(`.${apex}`)) {
          if (!discoveredMap.has(host)) {
            discoveredMap.set(host, 'api');
          }
        }
      } catch {
        // Not a valid URL
      }

      const acao = hop.headers['access-control-allow-origin']?.trim();
      if (acao != null && acao.length > 0 && acao !== '*' && acao !== 'null') {
        try {
          const u = new URL(acao);
          const host = u.hostname.toLowerCase();
          if (host === apex || host.endsWith(`.${apex}`)) {
            if (!discoveredMap.has(host)) {
              discoveredMap.set(host, 'cors');
            }
          }
        } catch {
          // Not a valid URL
        }
      }
    }
  }

  return Array.from(discoveredMap.entries()).map(([hostname, discoveredVia]) => ({
    hostname,
    discoveredVia,
  }));
}

/**
 * Merges freshly discovered nodes and current score/grade into an accumulated AttackSurfaceGraph.
 */
export function mergeIntoGraph(
  existingGraph: AttackSurfaceGraph | null,
  currentHostname: string,
  score: number,
  grade: Grade,
  discovered: DiscoveredNode[],
  isPro: boolean = false
): AttackSurfaceGraph {
  const apex = registrableDomain(currentHostname) ?? currentHostname;
  const now = Date.now();

  const nodeMap = new Map<string, GraphNode>();

  // Ensure apex node exists
  nodeMap.set(apex, {
    hostname: apex,
    isApex: true,
    lastSeen: now,
    discoveredVia: ['navigation'],
  });

  // Restore existing nodes if same apex
  if (existingGraph && existingGraph.apexDomain === apex) {
    for (const n of existingGraph.nodes) {
      nodeMap.set(n.hostname, { ...n });
    }
  }

  // Update current node's score, grade, and timestamp
  const currentNode = nodeMap.get(currentHostname) ?? {
    hostname: currentHostname,
    isApex: currentHostname === apex,
    lastSeen: now,
    discoveredVia: ['navigation'],
  };
  currentNode.score = score;
  currentNode.grade = grade;
  currentNode.lastSeen = now;
  if (!currentNode.discoveredVia.includes('navigation')) {
    currentNode.discoveredVia.push('navigation');
  }
  nodeMap.set(currentHostname, currentNode);

  // Add newly discovered nodes (must belong to apex domain)
  for (const d of discovered) {
    const host = d.hostname.toLowerCase();
    if (host !== apex && !host.endsWith(`.${apex}`)) {
      continue;
    }
    const existing = nodeMap.get(host);
    if (existing !== undefined) {
      existing.lastSeen = now;
      if (!existing.discoveredVia.includes(d.discoveredVia)) {
        existing.discoveredVia.push(d.discoveredVia);
      }
    } else {
      nodeMap.set(host, {
        hostname: host,
        isApex: host === apex,
        lastSeen: now,
        discoveredVia: [d.discoveredVia],
      });
    }
  }

  // Cap graph nodes to prevent unbounded memory/storage growth (max 100 nodes per apex)
  const MAX_GRAPH_NODES = 100;
  if (nodeMap.size > MAX_GRAPH_NODES) {
    const allNodes = Array.from(nodeMap.values());
    const essentialNodes = allNodes.filter((n) => n.isApex || n.hostname === currentHostname);
    const nonEssentialNodes = allNodes
      .filter((n) => !n.isApex && n.hostname !== currentHostname)
      .sort((a, b) => b.lastSeen - a.lastSeen);
    const retained = [...essentialNodes, ...nonEssentialNodes.slice(0, MAX_GRAPH_NODES - essentialNodes.length)];
    nodeMap.clear();
    for (const n of retained) {
      nodeMap.set(n.hostname, n);
    }
  }

  // Build edges: connect each non-apex node to apex and/or current host
  const edges: GraphEdge[] = [];
  const edgeSet = new Set<string>();

  for (const node of nodeMap.values()) {
    if (node.hostname === apex) continue;

    // Primary trust edge: connect node to apex
    for (const via of node.discoveredVia) {
      const edgeKey = `${node.hostname}->${apex}:${via}`;
      if (!edgeSet.has(edgeKey)) {
        edgeSet.add(edgeKey);
        let severity: Severity = 'low';
        let edgeType: GraphEdge['type'] = 'csp';
        let provenance: GraphEdge['provenance'] = 'inferred';

        if (via === 'cookie') {
          edgeType = 'cookie';
          severity = 'high';
          provenance = 'inferred';
        } else if (via === 'cors') {
          edgeType = 'cors';
          severity = 'medium';
          provenance = 'observed';
        } else if (via === 'csp') {
          edgeType = 'csp';
          severity = 'medium';
          provenance = 'inferred';
        } else if (via === 'api') {
          edgeType = 'cors';
          severity = 'low';
          provenance = 'inferred';
        }

        edges.push({
          source: node.hostname,
          target: apex,
          type: edgeType,
          severity,
          provenance,
        });
      }
    }
  }

  return {
    apexDomain: apex,
    nodes: Array.from(nodeMap.values()),
    edges,
    isPro,
    lastUpdated: now,
  };
}
