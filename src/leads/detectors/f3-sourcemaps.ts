import type { Lead } from '../types';
import { maskSecret, maskLocation } from '../sieve/mask';

let leadCounter = 0;
function nextLeadId(prefix: string): string {
  leadCounter++;
  return `LD-${prefix}-${Date.now().toString(36)}-${leadCounter}`;
}

export function detectSourceMaps(
  code: string,
  headers: Record<string, string> = {},
  url: string,
  scopeStatus: Lead['scopeStatus'] = 'unknown'
): Lead[] {
  const leads: Lead[] = [];
  if (code.length === 0 && Object.keys(headers).length === 0) return leads;

  const origin = (() => {
    try {
      return new URL(url).origin;
    } catch {
      return 'https://unknown';
    }
  })();

  // 1. MAP-001: sourceMappingURL comment or header
  const h1 = headers['sourcemap'];
  const h2 = headers['x-sourcemap'];
  const smHeader = typeof h1 === 'string' && h1.length > 0 ? h1 : (typeof h2 === 'string' && h2.length > 0 ? h2 : undefined);
  const smCommentMatch = code.length > 0 ? code.match(/(?:\/\/|[\/][*])#\s*sourceMappingURL=([^\s*]+)/) : null;
  const smComment = smCommentMatch !== null && smCommentMatch[1] !== undefined ? smCommentMatch[1] : undefined;
  const smTarget = smHeader !== undefined ? smHeader : smComment;

  if (smTarget !== undefined && smTarget.length > 0) {
    leads.push({
      id: nextLeadId('MAP-REF'),
      ruleId: 'MAP-001',
      family: 'F3',
      tier: 'observed',
      potential: 'low',
      confidence: 1.0,
      title: 'JavaScript Source Map Reference Detected',
      needs: ['fetch source map URL to verify unminified original source retrieval'],
      doesNotProve: ['original source code download succeeds', 'secrets in source code'],
      evidence: {
        preview: maskSecret(smTarget),
        location: maskLocation(url),
        context: smHeader !== undefined ? 'SourceMap HTTP response header' : 'sourceMappingURL comment in script',
      },
      tags: ['sourcemap', 'recon'],
      scopeStatus,
      timestamp: Date.now(),
      origin,
      url,
      sourceSensor: 'S2',
      remediation: 'Remove production source map references if unminified source code contains proprietary logic.',
    });
  }

  // 2. MAP-002: Inline Source Maps
  if (code.length > 0 && code.includes('sourceMappingURL=data:application/json')) {
    const inlineMatch = code.match(/sourceMappingURL=data:application\/json;base64,([A-Za-z0-9+/=]+)/);
    const internalPaths: string[] = [];

    if (inlineMatch !== null && inlineMatch[1] !== undefined && inlineMatch[1].length > 0) {
      try {
        const decoded = typeof atob !== 'undefined'
          ? atob(inlineMatch[1])
          : Buffer.from(inlineMatch[1], 'base64').toString('utf8');
        const parsed = JSON.parse(decoded) as Record<string, unknown>;
        if (Array.isArray(parsed.sources)) {
          for (const s of parsed.sources) {
            if (typeof s === 'string' && (s.includes('/Users/') || s.includes('/home/') || s.includes('C:\\') || s.startsWith('webpack:///'))) {
              internalPaths.push(s);
            }
          }
        }
      } catch {
        // Fallback
      }
    }

    leads.push({
      id: nextLeadId('MAP-INLINE'),
      ruleId: 'MAP-002',
      family: 'F3',
      tier: 'observed',
      potential: 'medium',
      confidence: 1.0,
      title: 'Inline Source Map with Internal Build Paths',
      needs: ['inspect extracted source tree for hardcoded configs'],
      doesNotProve: ['runtime exploitability'],
      evidence: {
        preview: maskSecret(internalPaths.length > 0 ? internalPaths.slice(0, 3).join(', ') : 'Inline Data SourceMap'),
        location: maskLocation(url),
        extractedNames: internalPaths.slice(0, 10),
      },
      tags: ['sourcemap', 'internal-paths'],
      scopeStatus,
      timestamp: Date.now(),
      origin,
      url,
      sourceSensor: 'S2',
    });
  }

  // 3. MAP-003: Version fingerprinting from code banners
  if (code.length > 0) {
    const librarySignatures = [
      { name: 'jQuery', regex: /jQuery\s+v?([0-9]+\.[0-9]+\.[0-9]+)/i },
      { name: 'Lodash', regex: /lodash\s+v?([0-9]+\.[0-9]+\.[0-9]+)/i },
      { name: 'React', regex: /React\s+v?([0-9]+\.[0-9]+\.[0-9]+)/i },
      { name: 'Angular', regex: /AngularJS\s+v?([0-9]+\.[0-9]+\.[0-9]+)/i },
      { name: 'Vue', regex: /Vue\.js\s+v?([0-9]+\.[0-9]+\.[0-9]+)/i },
    ];

    for (const lib of librarySignatures) {
      const match = code.match(lib.regex);
      if (match !== null && match[1] !== undefined && match[1].length > 0) {
        leads.push({
          id: nextLeadId('MAP-LIB'),
          ruleId: 'MAP-003',
          family: 'F3',
          tier: 'whisper',
          potential: 'info',
          confidence: 0.7,
          title: `Library Version Fingerprint: ${lib.name} ${match[1]} (version-based, exploitability unproven)`,
          needs: ['verify if known CVE is triggerable in this application configuration'],
          doesNotProve: ['exploitability in current application context'],
          evidence: {
            preview: maskSecret(`${lib.name} ${match[1]}`),
            location: maskLocation(url),
          },
          tags: ['library-fingerprint', lib.name.toLowerCase()],
          scopeStatus,
          timestamp: Date.now(),
          origin,
          url,
          sourceSensor: 'S2',
        });
      }
    }
  }

  return leads;
}
