/** Cross-origin isolation and Permissions Policy configuration signals. */

import type { Finding, Hop } from '../../shared/types';
import { sanitizeEvidence } from '../utils';

const REF_COEP = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy';
const REF_CORP = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy';
const REF_PERMISSIONS_POLICY = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy';

export function checkIsolationHeaders(hop: Hop): Finding[] {
  const findings: Finding[] = [];
  const coepHeader = hop.headers['cross-origin-embedder-policy']?.trim().toLowerCase();
  const coep = coepHeader?.split(';', 1)[0]?.trim();
  const corp = hop.headers['cross-origin-resource-policy']?.trim().toLowerCase();
  const permissionsPolicy = hop.headers['permissions-policy'] ?? '';

  if (coep === undefined || coep === 'unsafe-none') {
    findings.push({
      ruleId: 'COEP-001',
      category: 'header',
      severity: 'info',
      title: 'Cross-Origin-Embedder-Policy does not enable cross-origin isolation',
      impact: 'Features requiring cross-origin isolation, such as SharedArrayBuffer in some contexts, may be unavailable.',
      evidence: sanitizeEvidence(coep ?? '(header absent; browser default is unsafe-none)'),
      recommendation: 'If the application needs cross-origin isolation, evaluate COEP: require-corp or credentialless together with COOP: same-origin and compatible resource policies.',
      reference: REF_COEP,
    });
  } else if (coep !== 'require-corp' && coep !== 'credentialless') {
    findings.push({
      ruleId: 'COEP-002',
      category: 'header',
      severity: 'info',
      title: 'Cross-Origin-Embedder-Policy has an unrecognized value',
      evidence: sanitizeEvidence(coep),
      recommendation: 'Use a supported COEP value (require-corp or credentialless) when cross-origin isolation is required.',
      reference: REF_COEP,
    });
  }

  if (corp === undefined) {
    findings.push({
      ruleId: 'CORP-001',
      category: 'header',
      severity: 'info',
      title: 'Cross-Origin-Resource-Policy is not explicitly set',
      impact: 'Other sites may be able to embed this resource unless another browser policy or CORS rule limits access.',
      evidence: sanitizeEvidence('(header absent)'),
      recommendation: 'Set same-origin or same-site when the resource should not be embedded cross-origin; use cross-origin only when intended.',
      reference: REF_CORP,
    });
  } else if (corp !== 'same-origin' && corp !== 'same-site' && corp !== 'cross-origin') {
    findings.push({
      ruleId: 'CORP-002',
      category: 'header',
      severity: 'info',
      title: 'Cross-Origin-Resource-Policy has an unrecognized value',
      evidence: sanitizeEvidence(corp),
      recommendation: 'Use same-origin, same-site, or cross-origin according to the resource sharing requirements.',
      reference: REF_CORP,
    });
  } else if (corp === 'cross-origin') {
    findings.push({
      ruleId: 'CORP-003',
      category: 'header',
      severity: 'info',
      title: 'Cross-Origin-Resource-Policy permits cross-origin embedding',
      evidence: sanitizeEvidence(corp),
      recommendation: 'Confirm cross-origin embedding is intended for this resource; choose same-origin or same-site if not.',
      reference: REF_CORP,
    });
  }

  const permissiveFeatures = permissionsPolicy
    .split(',')
    .map((directive) => directive.trim())
    .filter((directive) => /^[a-z0-9-]+\s*=\s*\(\s*\*\s*\)$/i.test(directive));
  if (permissiveFeatures.length > 0) {
    findings.push({
      ruleId: 'PERMPOLICY-001',
      category: 'header',
      severity: 'info',
      title: 'Permissions-Policy allows features in all origins',
      evidence: sanitizeEvidence(permissiveFeatures.join(', ')),
      recommendation: 'Restrict sensitive features to self or an explicit origin allowlist, or disable unused features with an empty allowlist.',
      reference: REF_PERMISSIONS_POLICY,
    });
  }

  return findings;
}
