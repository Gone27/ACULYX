import type { Lead } from '../types';
import type { ScopeProfile, ScopeRule } from '../../shared/scope/contracts';
import { maskSecret, maskLocation } from '../sieve/mask';

export interface ExtendedScopeRule extends ScopeRule {
  effect: 'in-scope' | 'out-of-scope';
}

export interface ExtendedScopeProfile extends Omit<ScopeProfile, 'rules'> {
  rules: ExtendedScopeRule[];
}

interface H1ScopeItem {
  asset_identifier?: string;
  target?: string;
  uri?: string;
  instruction?: string;
  eligible_for_bounty?: boolean;
}

interface H1ScopeData {
  program?: string;
  name?: string;
  structured_scopes?: H1ScopeItem[];
  targets?: H1ScopeItem[];
}

/**
 * Parses HackerOne structured scope JSON.
 */
export function parseHackerOneScope(jsonStr: string): ExtendedScopeProfile {
  const data = JSON.parse(jsonStr) as H1ScopeData;
  const progName = typeof data.program === 'string' && data.program.length > 0 ? data.program : (typeof data.name === 'string' && data.name.length > 0 ? data.name : 'HackerOne Program');
  const rawScopes = Array.isArray(data.structured_scopes) ? data.structured_scopes : (Array.isArray(data.targets) ? data.targets : []);

  const rules: ExtendedScopeRule[] = rawScopes.map((item: H1ScopeItem) => {
    const rawPattern = typeof item.asset_identifier === 'string' && item.asset_identifier.length > 0
      ? item.asset_identifier
      : (typeof item.target === 'string' && item.target.length > 0
        ? item.target
        : (typeof item.uri === 'string' && item.uri.length > 0 ? item.uri : ''));
    const instruction = typeof item.instruction === 'string' ? item.instruction.toLowerCase() : '';
    const isOut =
      item.eligible_for_bounty === false ||
      instruction.includes('do not test') ||
      instruction.includes('out of scope');

    const rule: ExtendedScopeRule = {
      pattern: rawPattern,
      type: isOut ? 'exclude' : 'include',
      effect: isOut ? 'out-of-scope' : 'in-scope',
    };
    if (typeof item.instruction === 'string' && item.instruction.length > 0) {
      rule.description = item.instruction;
    }
    return rule;
  });

  return {
    id: `h1-${Date.now()}`,
    name: progName,
    rules,
    lastReviewed: Date.now(),
  };
}

interface BugcrowdTarget {
  uri?: string;
  target?: string;
  category?: string;
  in_scope?: boolean;
}

interface BugcrowdScopeData {
  name?: string;
  targets?: BugcrowdTarget[];
}

/**
 * Parses Bugcrowd target scope JSON.
 */
export function parseBugcrowdScope(jsonStr: string): ExtendedScopeProfile {
  const data = JSON.parse(jsonStr) as BugcrowdScopeData;
  const progName = typeof data.name === 'string' && data.name.length > 0 ? data.name : 'Bugcrowd Program';
  const rawTargets = Array.isArray(data.targets) ? data.targets : [];

  const rules: ExtendedScopeRule[] = rawTargets.map((item: BugcrowdTarget) => {
    let rawPattern = typeof item.uri === 'string' && item.uri.length > 0 ? item.uri : (typeof item.target === 'string' && item.target.length > 0 ? item.target : '');
    // Strip scheme for wildcard or host pattern matching
    rawPattern = rawPattern.replace(/^https?:\/\//i, '');

    const isOut = item.category === 'out_of_scope' || item.in_scope === false;

    const rule: ExtendedScopeRule = {
      pattern: rawPattern,
      type: isOut ? 'exclude' : 'include',
      effect: isOut ? 'out-of-scope' : 'in-scope',
    };
    if (typeof item.category === 'string' && item.category.length > 0) {
      rule.description = item.category;
    }
    return rule;
  });

  return {
    id: `bc-${Date.now()}`,
    name: progName,
    rules,
    lastReviewed: Date.now(),
  };
}

interface IntigritiDomain {
  endpoint?: string;
  domain?: string;
  inScope?: boolean;
  in_scope?: boolean;
  type?: string;
}

interface IntigritiScopeData {
  companyName?: string;
  name?: string;
  domains?: IntigritiDomain[];
  targets?: IntigritiDomain[];
}

/**
 * Parses Intigriti scope JSON.
 */
export function parseIntigritiScope(jsonStr: string): ExtendedScopeProfile {
  const data = JSON.parse(jsonStr) as IntigritiScopeData;
  const progName = typeof data.companyName === 'string' && data.companyName.length > 0
    ? data.companyName
    : (typeof data.name === 'string' && data.name.length > 0 ? data.name : 'Intigriti Program');
  const rawDomains = Array.isArray(data.domains) ? data.domains : (Array.isArray(data.targets) ? data.targets : []);

  const rules: ExtendedScopeRule[] = rawDomains.map((item: IntigritiDomain) => {
    let rawPattern = typeof item.endpoint === 'string' && item.endpoint.length > 0 ? item.endpoint : (typeof item.domain === 'string' && item.domain.length > 0 ? item.domain : '');
    rawPattern = rawPattern.replace(/^https?:\/\//i, '');

    const isIn = item.inScope === true || item.in_scope === true;

    const rule: ExtendedScopeRule = {
      pattern: rawPattern,
      type: isIn ? 'include' : 'exclude',
      effect: isIn ? 'in-scope' : 'out-of-scope',
    };
    if (typeof item.type === 'string' && item.type.length > 0) {
      rule.description = item.type;
    }
    return rule;
  });

  return {
    id: `intigriti-${Date.now()}`,
    name: progName,
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
    if (p.trim().length > 0) {
      uniqueNames.add(p.trim());
    }
  }

  for (const ep of endpoints) {
    const segments = ep.split(/[/\\?&#=._-]+/).filter(s => s.trim().length > 0);
    for (const seg of segments) {
      if (!/^[0-9]+$/.test(seg) && seg.length > 1) {
        uniqueNames.add(seg.trim());
      }
    }
    if (ep.trim().length > 0) {
      uniqueNames.add(ep.trim());
    }
  }

  return Array.from(uniqueNames).join('\n');
}

function sanitizeReportLead(lead: Lead): Lead {
  const rawPreview = lead.evidence.preview;
  const rawLoc = lead.evidence.location;
  const rawUrl = lead.url;
  const preview = maskSecret(typeof rawPreview === 'string' && rawPreview.length > 0 ? rawPreview : '');
  const location = maskLocation(typeof rawLoc === 'string' && rawLoc.length > 0 ? rawLoc : '');
  const url = maskLocation(typeof rawUrl === 'string' && rawUrl.length > 0 ? rawUrl : '');

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
    if (typeof lead.evidence.context === 'string' && lead.evidence.context.length > 0) {
      lines.push(`- **Context**: ${lead.evidence.context}`);
    }
    if (lead.evidence.extractedNames !== undefined && lead.evidence.extractedNames.length > 0) {
      lines.push(`- **Extracted Names**: ${lead.evidence.extractedNames.join(', ')}`);
    }
    if (lead.tags !== undefined && lead.tags.length > 0) {
      lines.push(`- **Tags**: ${lead.tags.map(t => `\`${t}\``).join(' ')}`);
    }
    if (lead.chainIds !== undefined && lead.chainIds.length > 0) {
      lines.push(`- **Correlated Chains**: ${lead.chainIds.join(', ')}`);
    }
    if (typeof lead.remediation === 'string' && lead.remediation.length > 0) {
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
            rules: Array.from(new Set(sanitized.map(l => l.ruleId))).map(ruleId => {
              const matching = sanitized.find(l => l.ruleId === ruleId);
              return {
                id: ruleId,
                shortDescription: {
                  text: matching !== undefined ? matching.title : ruleId,
                },
              };
            }),
          },
        },
        results: sanitized.map(lead => ({
          ruleId: lead.ruleId,
          level: levelMap[lead.potential] ?? 'note',
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
