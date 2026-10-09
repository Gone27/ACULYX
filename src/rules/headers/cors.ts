/** CORS response policy checks for the captured document or API response. */

import type { Finding, Hop, ApiHop } from '../../shared/types';
import { sanitizeEvidence, originFromUrl } from '../utils';

const REF_CORS = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS';

export function checkCors(hop: Hop | ApiHop): Finding[] {
  const isApi = 'method' in hop || 'normalizedPath' in hop;
  const contentType = hop.headers['content-type']?.toLowerCase() ?? '';

  if (!isApi && (contentType.includes('text/html') || contentType === '')) {
    return [];
  }

  const allowOrigin = hop.headers['access-control-allow-origin']?.trim();
  if (allowOrigin === undefined) return [];

  const credentials = hop.headers['access-control-allow-credentials']?.trim().toLowerCase() === 'true';
  const lowerOrigin = allowOrigin.toLowerCase();
  const requestOrigin = (hop as ApiHop).requestOrigin;
  const fromCache = hop.fromCache === true;

  // Case 1: Reflected Origin with credentials enabled
  // Known-safe configuration protection: Echoing the server's OWN same-origin origin is safe!
  // Only flag potential reflection if requestOrigin is cross-origin.
  if (credentials && requestOrigin !== undefined && requestOrigin.length > 0 && allowOrigin === requestOrigin) {
    const hopOrigin = originFromUrl(hop.url);
    const isSameOrigin = hopOrigin !== null && hopOrigin.toLowerCase() === requestOrigin.toLowerCase();

    if (!isSameOrigin) {
      return [{
        ruleId: 'CORS-001',
        category: 'cors',
        severity: 'medium',
        confidence: 'heuristic',
        provenance: 'response-header',
        outcome: fromCache ? 'partial-coverage' : 'fail',
        title: 'CORS allows cross-origin request Origin with credentials (potential reflection)',
        impact: 'Any cross-origin website can induce a user browser to make requests to this endpoint and read the response using victim credentials if the server dynamically reflects the origin.',
        evidence: sanitizeEvidence(`Request Origin: ${requestOrigin} -> ACAO: ${allowOrigin}; ACAC: true`),
        recommendation: 'Verify that the server does not dynamically reflect arbitrary Origin headers when Access-Control-Allow-Credentials is true. Validate incoming Origin headers against a strict, static allowlist.',
        reference: REF_CORS,
        limitations: fromCache
          ? ['Response served from browser cache; CORS reflection behavior may differ on live origin hit.']
          : ['Passive observation only; did not actively probe endpoint with forged Origin headers.'],
      }];
    }
  }

  // Case 2: Origin "null" allowed
  if (lowerOrigin === 'null') {
    return [{
      ruleId: 'CORS-001',
      category: 'cors',
      severity: credentials ? 'high' : 'medium',
      confidence: 'deterministic',
      provenance: 'response-header',
      outcome: fromCache ? 'partial-coverage' : 'fail',
      title: "CORS allows the 'null' origin to read this response",
      impact: 'Allowing the "null" origin permits sandboxed iframes, local files, and data: URIs from arbitrary origins to read sensitive data.',
      evidence: sanitizeEvidence(`Access-Control-Allow-Origin: null${credentials ? '; Access-Control-Allow-Credentials: true' : ''}`),
      recommendation: 'Remove "null" from CORS allowlists. Sandboxed attacker iframes can forge a null origin.',
      reference: REF_CORS,
      limitations: [
        'Passive observation of ACAO: null.',
        credentials ? 'Credentials allowed with null origin' : 'Ambient credentials disabled (ACAC not true)',
      ],
    }];
  }

  // Case 3: Wildcard ACAO (informational observation without evidence of sensitivity)
  if (allowOrigin === '*') {
    return [{
      ruleId: 'CORS-001',
      category: 'cors',
      severity: 'info',
      confidence: 'heuristic',
      provenance: 'response-header',
      outcome: 'pass',
      title: 'CORS policy permits wildcard origin (Access-Control-Allow-Origin: *)',
      impact: 'Allows any website to read this response via browser JavaScript. Standard and safe for public APIs and resources; hazardous only if sensitive or authenticated user data is exposed.',
      evidence: sanitizeEvidence(`Access-Control-Allow-Origin: *${credentials ? '; Access-Control-Allow-Credentials: true (ignored by browsers with wildcard origin)' : ''}`),
      recommendation: 'Verify that this endpoint exposes only public resources. If user-specific or sensitive data is returned, specify an explicit trusted origin instead of wildcard.',
      reference: REF_CORS,
      limitations: [
        'Passive observation: wildcard CORS is permissible for public endpoints, hazardous only for sensitive endpoints.',
        'Browsers reject credentialed requests (cookies/HTTP auth) when Access-Control-Allow-Origin is "*".',
      ],
    }];
  }

  return [];
}
