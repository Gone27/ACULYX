import type { Lead } from '../types';
import type { ScopeProfile, ScopeRule } from '../../shared/scope/contracts';
import { maskSecret, maskLocation } from '../sieve/mask';

export interface ExtendedScopeRule extends ScopeRule {
  effect: 'in-scope' | 'out-of-scope';
}

export interface ExtendedScopeProfile extends Omit<ScopeProfile, 'rules'> {
  rules: ExtendedScopeRule[];
}

/**
 * Parses HackerOne structured scope JSON.
 */
export function parseHackerOneScope(jsonStr: string): ExtendedScopeProfile {
  const data = JSON.parse(jsonStr);
  const name = data.program || data.name || 'HackerOne Program';
  const rawScopes = data.structured_scopes || data.targets || [];

  const rules: ExtendedScopeRule[] = rawScopes.map((item: any) => {
    const pattern = item.asset_identifier || item.target || item.uri || '';
    const instruction = typeof item.instruction === 'string' ? item.instruction.toLowerCase() : '';
    const isOut =
      item.eligible_for_bounty === false ||
      instruction.includes('do not test') ||
      instruction.includes('out of scope');

    return {
      pattern,
      type: isOut ? 'exclude' : 'include',
      effect: isOut ? 'out-of-scope' : 'in-scope',
      description: item.instruction || undefined,
    };
  });

  return {
    id: `h1-${Date.now()}`,
    name,
    rules,
    lastReviewed: Date.now(),
  };
}

/**
 * Parses Bugcrowd target scope JSON.
 */
export function parseBugcrowdScope(jsonStr: string): ExtendedScopeProfile {
  const data = JSON.parse(jsonStr);
  const name = data.name || 'Bugcrowd Program';
  const rawTargets = data.targets || [];

  const rules: ExtendedScopeRule[] = rawTargets.map((item: any) => {
    let pattern = item.uri || item.target || '';
    // Strip scheme for wildcard or host pattern matching
    pattern = pattern.replace(/^https?:\/\//i, '');

    const isOut = item.category === 'out_of_scope' || item.in_scope === false;

    return {
      pattern,
      type: isOut ? 'exclude' : 'include',
      effect: isOut ? 'out-of-scope' : 'in-scope',
      description: item.category || undefined,
    };
  });

  return {
    id: `bc-${Date.now()}`,
    name,
    rules,
    lastReviewed: Date.now(),
  };
}

/**
 * Parses Intigriti scope JSON.
 */
export function parseIntigritiScope(jsonStr: string): ExtendedScopeProfile {
  const data = JSON.parse(jsonStr);
  const name = data.companyName || data.name || 'Intigriti Program';
  const rawDomains = data.domains || data.targets || [];

  const rules: ExtendedScopeRule[] = rawDomains.map((item: any) => {
    let pattern = item.endpoint || item.domain || '';
    pattern = pattern.replace(/^https?:\/\//i, '');

    const isIn = item.inScope === true || item.in_scope === true;

    return {
      pattern,
      type: isIn ? 'include' : 'exclude',
      effect: isIn ? 'in-scope' : 'out-of-scope',
      description: item.type || undefined,
    };
  });

  return {
    id: `intigriti-${Date.now()}`,
    name,
    rules,
    lastReviewed: Date.now(),
  };
}

/**
 * Generates deduped name-only wordlist from discovered parameters and endpoints.
 */
export function generateNameOnlyWordlist(params: string[], endpoints: string[]): string {
  const uniqueNames = new Set<string>();

  for (const p of params) {
    if (typeof p === 'string' && p.trim().length > 0) {
      uniqueNames.add(p.trim());
    }
  }

  for (const e of endpoints) {
    if (typeof e === 'string' && e.trim().length > 0) {
      uniqueNames.add(e.trim());
    }
  }

  return Array.from(uniqueNames).join('\n');
}

function sanitizeReportLead(lead: Lead): Lead {
  const preview = maskSecret(lead.evidence.preview || '');
  const location = maskLocation(lead.evidence.location || '');
  const url = maskLocation(lead.url || '');

  return {
    ...lead,
    url,
    evidence: {
      ...lead.evidence,
      preview,
      location,
    },
  };
}

/**
 * Exports leads to a Markdown report without leaking secrets or canaries.
 */
export function formatLeadsReportMarkdown(leads: Lead[]): string {
  const sanitized = leads.map(sanitizeReportLead);

  const lines: string[] = [
    '# ACULYX Security Leads Assessment Report',
    '',
    `Generated on: ${new Date().toISOString()}`,
    `Total leads: ${sanitized.length}`,
    '',
    '---',
    '',
  ];

  for (const lead of sanitized) {
    lines.push(`## [${lead.potential.toUpperCase()}] ${lead.title} (${lead.ruleId})`);
    lines.push(`- **Family**: ${lead.family} | **Tier**: ${lead.tier} | **Confidence**: ${lead.confidence}`);
    lines.push(`- **Scope Status**: ${lead.scopeStatus}`);
    lines.push(`- **Observed Location**: \`${lead.evidence.location}\``);
    lines.push(`- **Evidence Preview**: \`${lead.evidence.preview}\``);
    if (lead.evidence.context) {
      lines.push(`- **Context**: ${lead.evidence.context}`);
    }
    if (lead.evidence.extractedNames && lead.evidence.extractedNames.length > 0) {
      lines.push(`- **Extracted Names**: ${lead.evidence.extractedNames.join(', ')}`);
    }
    if (lead.tags && lead.tags.length > 0) {
      lines.push(`- **Tags**: ${lead.tags.map(t => `\`${t}\``).join(' ')}`);
    }
    if (lead.chainIds && lead.chainIds.length > 0) {
      lines.push(`- **Correlated Chains**: ${lead.chainIds.join(', ')}`);
    }
    if (lead.remediation) {
      lines.push(`- **Remediation**: ${lead.remediation}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

/**
 * Exports leads to a sanitized JSON report.
 */
export function formatLeadsReportJson(leads: Lead[]): string {
  const sanitized = leads.map(sanitizeReportLead);
  return JSON.stringify(sanitized, null, 2);
}

/**
 * Exports leads to SARIF 2.1.0 format.
 */
export function formatLeadsReportSarif(leads: Lead[]): string {
  const sanitized = leads.map(sanitizeReportLead);

  const levelMap: Record<Lead['potential'], string> = {
    critical: 'error',
    high: 'error',
    medium: 'warning',
    low: 'note',
    info: 'none',
  };

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'ACULYX Lead Engine',
            version: '2.0.0',
            informationUri: 'https://github.com/Gone27/Cookie-and-header-reader-extention',
            rules: Array.from(new Set(sanitized.map(l => l.ruleId))).map(ruleId => ({
              id: ruleId,
              shortDescription: {
                text: sanitized.find(l => l.ruleId === ruleId)?.title || ruleId,
              },
            })),
          },
        },
        results: sanitized.map(lead => ({
          ruleId: lead.ruleId,
          level: levelMap[lead.potential] || 'note',
          message: {
            text: `${lead.title}: ${lead.evidence.preview}`,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: lead.evidence.location,
                },
              },
            },
          ],
        })),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
