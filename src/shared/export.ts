import type { TabState, Finding, CoverageInfo, CookieRecord } from './types';
import { sanitizeUrlForStorage, sanitizeCspPolicyForStorage } from '../rules/utils';

export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: Array<{
          id: string;
          name: string;
          shortDescription: { text: string };
          fullDescription: { text: string };
          helpUri?: string;
          properties?: Record<string, unknown>;
        }>;
      };
    };
    results: Array<{
      ruleId: string;
      ruleIndex?: number;
      level: 'error' | 'warning' | 'note';
      message: { text: string };
      locations: Array<{
        physicalLocation: {
          artifactLocation: { uri: string };
        };
      }>;
      properties?: Record<string, unknown>;
    }>;
    properties: Record<string, unknown>;
  }>;
}

/**
 * Creates a sanitized deep clone of TabState ensuring all URLs, serviceWorkerUrl,
 * metaCspPolicies, and coverage ledger entries are sanitized without sensitive query params,
 * credentials, or opaque tokens.
 */
export function sanitizeStateForExport(state: TabState): TabState {
  const cloned: TabState = {
    ...state,
    url: sanitizeUrlForStorage(state.url),
    cookies: Array.isArray(state.cookies)
      ? state.cookies.map((c) => {
          const copy = { ...c } as CookieRecord & { value?: unknown };
          delete copy.value;
          return copy;
        })
      : [],
    findings: Array.isArray(state.findings) ? [...state.findings] : [],
    hops: Array.isArray(state.hops)
      ? state.hops.map((h) => ({
          ...h,
          url: sanitizeUrlForStorage(h.url),
        }))
      : [],
  };

  const cov: CoverageInfo = {
    ...state.coverage,
    serviceWorkerUrl:
      typeof state.coverage.serviceWorkerUrl === 'string' && state.coverage.serviceWorkerUrl.length > 0
        ? sanitizeUrlForStorage(state.coverage.serviceWorkerUrl)
        : null,
    metaCspPolicies: Array.isArray(state.coverage.metaCspPolicies)
      ? state.coverage.metaCspPolicies.map((p) => sanitizeCspPolicyForStorage(p))
      : [],
  };
  if (Array.isArray(state.coverage.ledger)) {
    cov.ledger = state.coverage.ledger.map((entry) => ({
      ...entry,
      url: sanitizeUrlForStorage(entry.url),
    }));
  }
  cloned.coverage = cov;

  return cloned;
}

/**
 * Generates a SARIF 2.1.0 document from TabState with guaranteed sanitization of all URLs.
 */
export function generateSarif(state: TabState): SarifLog {
  const sanitized = sanitizeStateForExport(state);
  const rules = new Map<string, Finding>();
  for (const finding of sanitized.findings) {
    if (!rules.has(finding.ruleId)) rules.set(finding.ruleId, finding);
  }
  const ruleList = [...rules.entries()];
  const ruleIndexes = new Map(ruleList.map(([ruleId], index) => [ruleId, index]));

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'ACULYX',
            version: '2.0.0',
            informationUri: 'https://github.com/Gone27/ACULYX',
            rules: ruleList.map(([ruleId, finding]) => ({
              id: ruleId,
              name: ruleId,
              shortDescription: { text: finding.title },
              fullDescription: { text: finding.impact ?? finding.recommendation },
              helpUri: finding.reference,
              properties: { category: finding.category },
            })),
          },
        },
        results: sanitized.findings.map((finding) => {
          const ruleIndex = ruleIndexes.get(finding.ruleId);
          const artifactUri =
            typeof finding.sourceUrl === 'string' && finding.sourceUrl.length > 0
              ? sanitizeUrlForStorage(finding.sourceUrl)
              : sanitized.url;
          return {
            ruleId: finding.ruleId,
            ...(ruleIndex !== undefined ? { ruleIndex } : {}),
            level:
              finding.severity === 'critical' || finding.severity === 'high'
                ? ('error' as const)
                : finding.severity === 'medium'
                  ? ('warning' as const)
                  : ('note' as const),
            message: { text: `${finding.title}\n${finding.recommendation}` },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: artifactUri },
                },
              },
            ],
            properties: {
              evidence: finding.evidence,
              impact: finding.impact,
              category: finding.category,
              confidence: finding.confidence ?? 'deterministic',
            },
          };
        }),
        properties: {
          target: sanitized.url,
          score: sanitized.score,
          grade: sanitized.grade,
          qualityScore: sanitized.qualityScore,
          qualityGrade: sanitized.qualityGrade,
          serviceWorkerUrl: sanitized.coverage.serviceWorkerUrl,
          metaCspPolicies: sanitized.coverage.metaCspPolicies ?? [],
        },
      },
    ],
  };
}

export const generateSarifReport = generateSarif;

/**
 * Exports SARIF 2.1.0 report as a formatted JSON string.
 */
export function exportSarifReport(state: TabState): string {
  return JSON.stringify(generateSarif(state), null, 2);
}

/**
 * Exports sanitized TabState as JSON string.
 */
export function exportJsonReport(state: TabState): string {
  const sanitized = sanitizeStateForExport(state);
  return JSON.stringify(
    sanitized,
    (_key, val: unknown) => {
      if (val instanceof Map) {
        return Array.from(val.entries());
      }
      return val;
    },
    2
  );
}

export const generateJsonReport = exportJsonReport;

/**
 * Exports sanitized TabState as Markdown report.
 */
export function exportMarkdownReport(state: TabState): string {
  const sanitized = sanitizeStateForExport(state);
  const date = new Date(sanitized.updatedAt || Date.now()).toISOString();
  let md = `# Security Audit Report — ${sanitized.origin}\n\n`;
  md += `**Date:** ${date}  \n`;
  md += `**Target URL:** ${sanitized.url}  \n`;
  md += `**Overall Security Grade:** **${sanitized.grade}** (${sanitized.score} / 100)  \n\n`;
  md += `**Configuration Quality:** ${sanitized.qualityGrade ?? 'A'} (${sanitized.qualityScore ?? 100} / 100)  \n\n`;

  md += `## Executive Summary\n`;
  md += `ACULYX conducted an automated, passive inspection of HTTP response headers and cookies for \`${sanitized.origin}\`.\n\n`;

  if (sanitized.subdomainTrust.hasEscalationPath) {
    md += `> ⚠️ **Subdomain Escalation Path Detected:** Trust bridges exist between this site and its subdomains that could allow a compromised subdomain to compromise main-domain sessions or data.\n\n`;
  }

  md += `## Key Findings (${sanitized.findings.length} total)\n\n`;
  if (sanitized.findings.length === 0) {
    md += `No security weaknesses detected. All standard headers and cookie protections are configured properly.\n\n`;
  } else {
    for (const f of sanitized.findings) {
      md += `### [${f.severity.toUpperCase()}] ${f.title}\n`;
      md += `- **Rule ID:** \`${f.ruleId}\`\n`;
      if (f.impact != null && f.impact.length > 0) md += `- **Real-World Impact:** ${f.impact}\n`;
      if (f.evidence.length > 0) md += `- **Evidence:** \`${f.evidence}\`\n`;
      md += `- **Recommendation:** ${f.recommendation}\n`;
      if (f.reference) md += `- **Reference:** ${f.reference}\n`;
      md += `\n`;
    }
  }

  if (Array.isArray(sanitized.subdomainTrust.vectors) && sanitized.subdomainTrust.vectors.length > 0) {
    md += `## Subdomain Trust Analysis\n\n`;
    md += `| Vector ID | Assessment | Detail |\n`;
    md += `|---|---|---|\n`;
    for (const v of sanitized.subdomainTrust.vectors) {
      const status = v.present === true ? '⚠️ Risk confirmed' : v.present === false ? '✅ Protected' : 'ℹ️ N/A';
      md += `| \`${v.id}\` | ${status} | ${v.detail} |\n`;
    }
    md += `\n`;
  }

  const hasSw = typeof sanitized.coverage.serviceWorkerUrl === 'string' && sanitized.coverage.serviceWorkerUrl.length > 0;
  const hasMetaCsp = Array.isArray(sanitized.coverage.metaCspPolicies) && sanitized.coverage.metaCspPolicies.length > 0;

  if (hasSw || hasMetaCsp) {
    md += `## Coverage\n\n`;
    if (hasSw && sanitized.coverage.serviceWorkerUrl !== null) {
      md += `- **Service Worker:** \`${sanitized.coverage.serviceWorkerUrl}\`\n`;
    }
    if (hasMetaCsp && Array.isArray(sanitized.coverage.metaCspPolicies)) {
      md += `- **Meta CSP Policies:**\n`;
      for (const p of sanitized.coverage.metaCspPolicies) {
        md += `  - \`${p}\`\n`;
      }
    }
    md += `\n`;
  }

  md += `---\n*Generated locally by ACULYX - Header & Cookie Security Checker*\n`;
  return md;
}

export const generateMarkdownReport = exportMarkdownReport;
