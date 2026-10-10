import type { Lead } from '../types';
import { maskSecret, maskLocation } from '../sieve/mask';

const SEMANTIC_TAGS: Record<string, string> = {
  admin: 'admin',
  internal: 'internal',
  debug: 'debug',
  export: 'export',
  upload: 'upload',
  webhook: 'webhook',
  impersonate: 'impersonate',
  reset: 'reset',
  invite: 'invite',
  billing: 'billing',
  v0: 'legacy-api',
  v1: 'api-v1',
  v2: 'api-v2',
  graphql: 'graphql',
};

let leadCounter = 0;
function nextLeadId(prefix: string): string {
  leadCounter++;
  return `LD-${prefix}-${Date.now().toString(36)}-${leadCounter}`;
}

export function detectEndpoints(
  code: string,
  url: string,
  scopeStatus: Lead['scopeStatus'] = 'unknown'
): Lead[] {
  const leads: Lead[] = [];
  if (!code || typeof code !== 'string') return leads;

  const origin = (() => {
    try {
      return new URL(url).origin;
    } catch {
      return 'https://unknown';
    }
  })();

  const discoveredPaths = new Set<string>();

  // 1. END-001: Fetch / Axios / XHR / Beacon / URL Paths
  const fetchPatterns = [
    /(?:fetch|axios(?:\.[a-z]+)?|\$\.ajax|\.open|\.sendBeacon)\s*\(\s*["'`](\/[a-zA-Z0-9_\-./]+)["'`]/g,
    /["'`](\/(?:api|rest|v[0-9]|graphql|admin|internal)\/[a-zA-Z0-9_\-./]*)["'`]/g,
    /new\s+(?:WebSocket|EventSource)\s*\(\s*["'`](\/[a-zA-Z0-9_\-./]+)["'`]/g,
  ];

  for (const regex of fetchPatterns) {
    let match: RegExpExecArray | null;
    while ((match = regex.exec(code)) !== null) {
      const path = match[1];
      if (path && path.length > 2 && !discoveredPaths.has(path)) {
        discoveredPaths.add(path);

        const tags: string[] = ['endpoint', 'discovered-url'];
        let hasInterestingSemantic = false;

        const lowerPath = path.toLowerCase();
        for (const [keyword, tag] of Object.entries(SEMANTIC_TAGS)) {
          if (lowerPath.includes(keyword)) {
            tags.push(tag);
            hasInterestingSemantic = true;
          }
        }

        const isSensitive = tags.includes('admin') || tags.includes('internal') || tags.includes('debug');

        leads.push({
          id: nextLeadId('END-HTTP'),
          ruleId: hasInterestingSemantic ? 'END-004' : 'END-001',
          family: 'F2',
          tier: 'observed',
          potential: isSensitive ? 'high' : 'info',
          confidence: 0.9,
          title: `Discovered Endpoint: ${path}`,
          needs: ['verify authentication and authorization controls on endpoint'],
          doesNotProve: ['unauthenticated access', 'authorization bypass'],
          evidence: {
            preview: maskSecret(path),
            location: maskLocation(url),
            context: `Discovered from network client call in script: ${match[0].slice(0, 50)}`,
            extractedNames: [path],
          },
          tags,
          scopeStatus,
          timestamp: Date.now(),
          origin,
          url,
          sourceSensor: 'S2',
        });
      }
    }
  }

  // 2. END-002: Router Tables & Webpack Chunk Maps
  const routerPathRegex = /(?:<Route\s+[^>]*path=["']([^"']+)["']|path:\s*["'](\/[a-zA-Z0-9_\-./]+)["'])/g;
  let routeMatch: RegExpExecArray | null;
  while ((routeMatch = routerPathRegex.exec(code)) !== null) {
    const route = routeMatch[1] || routeMatch[2];
    if (route && !discoveredPaths.has(route)) {
      discoveredPaths.add(route);
      const tags = ['router-path'];
      for (const [kw, t] of Object.entries(SEMANTIC_TAGS)) {
        if (route.toLowerCase().includes(kw)) tags.push(t);
      }
      leads.push({
        id: nextLeadId('END-ROUTER'),
        ruleId: 'END-002',
        family: 'F2',
        tier: 'observed',
        potential: tags.includes('admin') ? 'medium' : 'info',
        confidence: 0.85,
        title: `Client Router Path Discovered: ${route}`,
        needs: ['verify corresponding backend route presence'],
        doesNotProve: ['backend endpoint exists'],
        evidence: {
          preview: maskSecret(route),
          location: maskLocation(url),
          extractedNames: [route],
        },
        tags,
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S2',
      });
    }
  }

  // Webpack chunk map & Next.js manifest
  if (code.includes('__webpack_require__.u') || code.includes('_buildManifest')) {
    leads.push({
      id: nextLeadId('END-CHUNKMAP'),
      ruleId: 'END-002',
      family: 'F2',
      tier: 'observed',
      potential: 'info',
      confidence: 1.0,
      title: 'Webpack Chunk Map / Next.js Manifest Present',
      needs: ['extract all referenced chunk paths for endpoint harvesting'],
      doesNotProve: ['vulnerability'],
      evidence: {
        preview: maskSecret('__webpack_require__.u / _buildManifest'),
        location: maskLocation(url),
      },
      tags: ['build-manifest', 'webpack', 'recon'],
      scopeStatus,
      timestamp: Date.now(),
      origin,
      url,
      sourceSensor: 'S2',
    });
  }

  // 3. END-003: GraphQL operations, introspection & endpoint
  const gqlQueryRegex = /(?:query|mutation|subscription)\s+([A-Za-z0-9_]+)\s*[{]/g;
  let gqlMatch: RegExpExecArray | null;
  const gqlOps: string[] = [];
  while ((gqlMatch = gqlQueryRegex.exec(code)) !== null) {
    if (gqlMatch[1]) {
      gqlOps.push(gqlMatch[1]);
    }
  }

  if (code.includes('/graphql') || gqlOps.length > 0 || code.includes('__schema') || code.includes('__typename')) {
    leads.push({
      id: nextLeadId('END-GQL'),
      ruleId: 'END-003',
      family: 'F2',
      tier: 'observed',
      potential: 'medium',
      confidence: 0.9,
      title: 'GraphQL API Surface & Operation Names Discovered',
      needs: ['test introspection query on /graphql', 'check field suggestion disclosure'],
      doesNotProve: ['GraphQL introspection is enabled'],
      evidence: {
        preview: maskSecret(gqlOps.length > 0 ? gqlOps.join(', ') : '/graphql'),
        location: maskLocation(url),
        extractedNames: gqlOps,
        context: `Discovered ${gqlOps.length} GraphQL operation definitions`,
      },
      tags: ['graphql', 'api-endpoint'],
      scopeStatus,
      timestamp: Date.now(),
      origin,
      url,
      sourceSensor: 'S2',
    });
  }

  return leads;
}
