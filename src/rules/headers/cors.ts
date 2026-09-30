/** CORS response policy checks for the captured document or API response. */

import type { Finding, Hop, ApiHop } from '../../shared/types';
import { sanitizeEvidence } from '../utils';

const REF_CORS = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS';

export function checkCors(hop: Hop | ApiHop): Finding[] {
  // CDNs frequently apply ACAO: * to all resources, including HTML documents.
  // Since top-level HTML navigation isn't gated by CORS anyway, this is usually 
  // harmless noise on public pages. We only flag non-HTML responses.
  const contentType = hop.headers['content-type']?.toLowerCase() ?? '';
  if (contentType.includes('text/html')) {
    return [];
  }

  const allowOrigin = hop.headers['access-control-allow-origin']?.trim();
  if (allowOrigin === undefined) return [];

  const credentials = hop.headers['access-control-allow-credentials']?.trim().toLowerCase() === 'true';
  const lowerOrigin = allowOrigin.toLowerCase();
  const requestOrigin = (hop as ApiHop).requestOrigin;

  // Case 1: Reflected Origin with credentials enabled
  if (credentials && requestOrigin !== undefined && requestOrigin.length > 0 && allowOrigin === requestOrigin) {
    return [{
      ruleId: 'CORS-001',
      category: 'cors',
      severity: 'high',
      confidence: 'deterministic',
      title: 'CORS reflects arbitrary request Origin with credentials allowed',
      impact: 'Any website can induce a user browser to make requests to this endpoint and read the response using the victim ambient credentials (cookies/auth).',
      evidence: sanitizeEvidence(`Request Origin: ${requestOrigin} -> ACAO: ${allowOrigin}; ACAC: true`),
      recommendation: 'Do not dynamically reflect the request Origin header when Access-Control-Allow-Credentials is true. Validate against a strict, static allowlist.',
      reference: REF_CORS,
    }];
  }

  // Case 2: Origin "null" allowed
  if (lowerOrigin === 'null') {
    return [{
      ruleId: 'CORS-001',
      category: 'cors',
      severity: credentials ? 'high' : 'medium',
      confidence: 'deterministic',
      title: "CORS allows the 'null' origin to read this response",
      impact: 'Allowing the "null" origin permits sandboxed iframes, local files, and data: URIs from arbitrary origins to read sensitive data.',
      evidence: sanitizeEvidence(`Access-Control-Allow-Origin: null${credentials ? '; Access-Control-Allow-Credentials: true' : ''}`),
      recommendation: 'Remove "null" from CORS allowlists. Sandboxed attacker iframes can forge a null origin.',
      reference: REF_CORS,
    }];
  }

  // Case 3: Wildcard ACAO
  if (allowOrigin === '*') {
    return [{
      ruleId: 'CORS-001',
      category: 'cors',
      severity: 'medium',
      confidence: 'deterministic',
      title: 'CORS allows every origin to read this response',
      impact: 'Any website can read this response through browser JavaScript; this is risky when the response contains non-public data.',
      evidence: sanitizeEvidence(`Access-Control-Allow-Origin: *${credentials ? '; Access-Control-Allow-Credentials: true (credentials are ignored with wildcard origin)' : ''}`),
      recommendation: 'Replace the wildcard with an explicit allowlist of trusted origins when this response contains data that should not be public.',
      reference: REF_CORS,
    }];
  }

  return [];
}
