/** CORS response policy checks for the captured document response. */

import type { Finding, Hop } from '../../shared/types';
import { sanitizeEvidence } from '../utils';

const REF_CORS = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS';

export function checkCors(hop: Hop): Finding[] {
  // CDNs frequently apply ACAO: * to all resources, including HTML documents.
  // Since top-level HTML navigation isn't gated by CORS anyway, this is usually 
  // harmless noise on public pages. We only flag non-HTML responses.
  const contentType = hop.headers['content-type']?.toLowerCase() ?? '';
  if (contentType.includes('text/html')) {
    return [];
  }

  const allowOrigin = hop.headers['access-control-allow-origin']?.trim();
  if (allowOrigin !== '*') return [];

  const credentials = hop.headers['access-control-allow-credentials']?.trim().toLowerCase() === 'true';
  return [{
    ruleId: 'CORS-001',
    category: 'cors',
    severity: 'medium',
    title: 'CORS allows every origin to read this response',
    impact: 'Any website can read this response through browser JavaScript; this is risky when the response contains non-public data.',
    evidence: sanitizeEvidence(`Access-Control-Allow-Origin: ${allowOrigin}${credentials ? '; Access-Control-Allow-Credentials: true (credentials are ignored with wildcard origin)' : ''}`),
    recommendation: 'Replace the wildcard with an explicit allowlist of trusted origins when this response contains data that should not be public.',
    reference: REF_CORS,
  }];
}
