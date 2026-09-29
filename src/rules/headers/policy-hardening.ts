/** Advisory checks for newer browser policy response headers. */

import type { Finding, Hop } from '../../shared/types';
import { sanitizeEvidence } from '../utils';

const REF_DOCUMENT_POLICY = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Document-Policy';
const REF_INTEGRITY_POLICY = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Integrity-Policy';

export function checkPolicyHardeningHeaders(hop: Hop): Finding[] {
  const findings: Finding[] = [];
  const documentPolicy = hop.headers['document-policy'];
  const integrityPolicy = hop.headers['integrity-policy'];
  const integrityReportOnly = hop.headers['integrity-policy-report-only'];

  if (documentPolicy === undefined) {
    findings.push({
      ruleId: 'DOC-001',
      category: 'header',
      severity: 'info',
      title: 'Document-Policy is not configured',
      evidence: sanitizeEvidence('(header absent)'),
      recommendation: 'Consider disabling document features the application does not need using browser-supported Document-Policy directives.',
      reference: REF_DOCUMENT_POLICY,
    });
  }

  if (integrityPolicy === undefined && integrityReportOnly !== undefined) {
    findings.push({
      ruleId: 'INTEGRITY-002',
      category: 'header',
      severity: 'info',
      title: 'Integrity-Policy-Report-Only is configured without enforcement',
      evidence: sanitizeEvidence(integrityReportOnly),
      recommendation: 'Review reports and consider promoting supported directives to Integrity-Policy after verifying resources have integrity metadata.',
      reference: REF_INTEGRITY_POLICY,
    });
  } else if (integrityPolicy === undefined) {
    findings.push({
      ruleId: 'INTEGRITY-001',
      category: 'header',
      severity: 'info',
      title: 'Integrity-Policy is not configured',
      evidence: sanitizeEvidence('(header absent)'),
      recommendation: 'Consider Integrity-Policy for enforcing integrity metadata on script resources after checking browser support and application compatibility.',
      reference: REF_INTEGRITY_POLICY,
    });
  }

  return findings;
}
