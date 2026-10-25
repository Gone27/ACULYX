import type { Lead, Masked } from '../types';
import { maskSecret, maskLocation } from '../sieve/mask';

function nextLeadId(prefix: string): string {
  const uid = typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID().replace(/-/g, '').slice(0, 12)
    : Math.random().toString(36).slice(2, 14);
  return `LD-${prefix}-${uid}`;
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

  if (smTarget !== undefined && smTarget.length > 0 && !smTarget.startsWith('data:')) {
    const maskedTarget = maskLocation(smTarget);
    leads.push({
      id: nextLeadId('MAP-REF'),
      ruleId: 'MAP-001',
      family: 'F3',
      tier: 'observed',
      potential: 'low',
      confidence: 1.0,
      title: maskedTarget.length > 0 ? `JavaScript Source Map Reference Detected: ${maskedTarget}` : 'JavaScript Source Map Reference Detected',
      needs: ['fetch source map URL to verify unminified original source retrieval'],
      doesNotProve: ['original source code download succeeds', 'secrets in source code'],
      evidence: {
        preview: maskedTarget.length > 0 ? maskedTarget : maskSecret(smTarget),
        location: maskLocation(url),
        context: smHeader !== undefined ? 'SourceMap HTTP response header' : 'sourceMappingURL comment in script',
      },
      tags: ['sourcemap', 'recon'],
      scopeStatus,
      timestamp: Date.now(),
      origin,
      url: maskLocation(url),
      sourceSensor: 'S2',
      remediation: 'Remove production source map references if unminified source code contains proprietary logic.',
    });
  }

  // 2. MAP-002: Inline Source Maps
  let validMapParsed: Record<string, unknown> | null = null;
  const inlineMatch = code.length > 0 ? code.match(/(?:\/\/|[\/][*])#\s*sourceMappingURL=data:application\/json([^,\s]*),([^\s*]+)/) : null;
  if (inlineMatch !== null && inlineMatch[2] !== undefined) {
    const meta = inlineMatch[1] ?? '';
    const payload = inlineMatch[2];
    try {
      let jsonStr: string;
      if (meta.includes('base64')) {
        jsonStr = typeof atob !== 'undefined'
          ? atob(payload)
          : Buffer.from(payload, 'base64').toString('utf8');
      } else {
        jsonStr = decodeURIComponent(payload);
      }
      const parsed = JSON.parse(jsonStr) as unknown;
      if (parsed !== null && typeof parsed === 'object') {
        validMapParsed = parsed as Record<string, unknown>;
      }
    } catch {
      validMapParsed = null;
    }
  }

  if (validMapParsed !== null) {
    const internalPaths: string[] = [];
    if (Array.isArray(validMapParsed.sources)) {
      for (const s of validMapParsed.sources) {
        if (typeof s === 'string' && (s.includes('/Users/') || s.includes('/home/') || s.includes('C:\\') || s.startsWith('webpack:///'))) {
          internalPaths.push(s);
        }
      }
    }

    const hasInternalPaths = internalPaths.length > 0;
    leads.push({
      id: nextLeadId('MAP-INLINE'),
      ruleId: 'MAP-002',
      family: 'F3',
      tier: 'observed',
      potential: hasInternalPaths ? 'medium' : 'low',
      confidence: hasInternalPaths ? 1.0 : 0.85,
      title: hasInternalPaths
        ? 'Inline Source Map with Internal Build Paths'
        : 'Inline JavaScript Source Map Detected',
      needs: ['inspect extracted source tree for hardcoded configs'],
      doesNotProve: hasInternalPaths
        ? ['runtime exploitability']
        : ['internal build paths disclosed', 'runtime exploitability'],
      evidence: {
        preview: (hasInternalPaths
          ? internalPaths.slice(0, 3).map(p => maskLocation(p)).join(', ')
          : 'Inline Data SourceMap') as Masked<string>,
        location: maskLocation(url),
        extractedNames: internalPaths.slice(0, 10).map(p => maskLocation(p)),
      },
      tags: hasInternalPaths ? ['sourcemap', 'internal-paths'] : ['sourcemap'],
      scopeStatus,
      timestamp: Date.now(),
      origin,
      url: maskLocation(url),
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
