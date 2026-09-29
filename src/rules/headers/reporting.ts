/** Reporting API, CSP reporting, and Network Error Logging configuration signals. */

import type { Finding, Hop } from '../../shared/types';
import { sanitizeEvidence } from '../utils';

const REF_REPORTING = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Reporting-Endpoints';
const REF_NEL = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Network_Error_Logging';
const REF_CSP = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-to';

function endpointGroups(value: string): Set<string> {
  return new Set([...value.matchAll(/(?:^|,)\s*([a-zA-Z0-9_-]+)\s*=/g)].map((match) => (match[1] ?? '').toLowerCase()).filter(Boolean));
}

export function checkReportingHeaders(hop: Hop): Finding[] {
  const findings: Finding[] = [];
  const csp = hop.headers['content-security-policy'] ?? '';
  const endpoints = hop.headers['reporting-endpoints'] ?? '';
  const nel = hop.headers['nel'];
  const groups = endpointGroups(endpoints);

  if (csp.length > 0 && !/\breport-to\b|\breport-uri\b/i.test(csp)) {
    findings.push({
      ruleId: 'CSP-REPORT-001',
      category: 'header',
      severity: 'info',
      title: 'CSP violation reporting is not configured',
      evidence: sanitizeEvidence('(neither report-to nor report-uri directive found)'),
      recommendation: 'Consider configuring report-to with a Reporting-Endpoints group to observe policy violations; report-uri is deprecated but remains a compatibility fallback.',
      reference: REF_CSP,
    });
  }

  if (endpoints.length === 0) {
    findings.push({
      ruleId: 'REPORT-001',
      category: 'header',
      severity: 'info',
      title: 'Reporting-Endpoints header is not configured',
      evidence: sanitizeEvidence('(header absent)'),
      recommendation: 'Configure Reporting-Endpoints if the application intends to receive browser-generated CSP, deprecation, or network reports.',
      reference: REF_REPORTING,
    });
  }

  if (nel !== undefined) {
    let reportTo: string | undefined;
    try {
      const parsed: unknown = JSON.parse(nel);
      if (typeof parsed === 'object' && parsed !== null && 'report_to' in parsed) {
        const value = (parsed as { report_to?: unknown }).report_to;
        if (typeof value === 'string') reportTo = value.toLowerCase();
      }
    } catch {
      findings.push({
        ruleId: 'REPORT-003',
        category: 'header',
        severity: 'info',
        title: 'NEL header is not valid JSON',
        evidence: sanitizeEvidence(nel),
        recommendation: 'Provide a valid Network Error Logging JSON object and verify its report_to group.',
        reference: REF_NEL,
      });
      return findings;
    }

    if (reportTo === undefined || !groups.has(reportTo)) {
      findings.push({
        ruleId: 'REPORT-002',
        category: 'header',
        severity: 'info',
        title: 'NEL report_to group does not match Reporting-Endpoints',
        evidence: sanitizeEvidence(`NEL report_to=${reportTo ?? '(missing)'}; configured groups=${[...groups].join(', ') || '(none)'}`),
        recommendation: 'Set NEL report_to to a group name declared in Reporting-Endpoints.',
        reference: REF_NEL,
      });
    }
  }

  return findings;
}
