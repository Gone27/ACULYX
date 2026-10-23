import type { Lead } from '../types';
import type { ScopeProfile, ScopeRule } from '../../shared/scope/contracts';
import { maskSecret, maskLocation } from '../sieve/mask';
import { redactAllSecrets } from '../../shared/reporting/report-builder';

const VALID_FAMILIES = new Set<string>(['F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8']);
const VALID_TIERS = new Set<string>(['observed', 'strong', 'weak', 'whisper']);
const VALID_POTENTIALS = new Set<string>(['critical', 'high', 'medium', 'low', 'info']);
const VALID_SENSORS = new Set<string>(['S1', 'S2', 'S3', 'S4', 'S5']);
const VALID_SCOPES = new Set<string>(['in-scope', 'out-of-scope', 'unknown']);
const VALID_TRIAGE_STATES = new Set<string>(['open', 'triaged', 'false_positive', 'resolved']);

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

/**
 * Sanitizes a single string field for export: strips secrets, tokens, and canaries,
 * and redacts query strings, fragments, and sensitive path tokens.
 */
function sanitizeExportString(raw: string): string {
  if (raw.length === 0) return raw;
  const secretRedacted = redactAllSecrets(raw);
  const locMasked = maskLocation(secretRedacted);
  return locMasked.length > 0 ? locMasked : maskSecret(secretRedacted);
}

function sanitizeReportLead(lead: Lead): Lead {
  const id = sanitizeExportString(typeof lead.id === 'string' ? lead.id : '');
  const ruleId = sanitizeExportString(typeof lead.ruleId === 'string' ? lead.ruleId : '');
  const title = sanitizeExportString(typeof lead.title === 'string' ? lead.title : '');
  const origin = sanitizeExportString(typeof lead.origin === 'string' ? lead.origin : '');
  const url = maskLocation(typeof lead.url === 'string' && lead.url.length > 0 ? lead.url : '');

  const rawPreview = lead.evidence?.preview;
  const rawLoc = lead.evidence?.location;
  const preview = maskSecret(typeof rawPreview === 'string' && rawPreview.length > 0 ? rawPreview : '');
  const location = maskLocation(typeof rawLoc === 'string' && rawLoc.length > 0 ? rawLoc : '');

  // Sanitize context (free-text; may contain parameter values or canary tokens)
  const rawContext = lead.evidence?.context;
  const sanitizedContext: string | undefined =
    typeof rawContext === 'string' && rawContext.length > 0
      ? sanitizeExportString(rawContext)
      : undefined;

  // Sanitize extractedNames (each name is a potential token)
  const rawNames = lead.evidence?.extractedNames;
  const sanitizedNames: string[] | undefined =
    Array.isArray(rawNames) && rawNames.length > 0
      ? rawNames.map((n) => sanitizeExportString(n))
      : undefined;

  // Sanitize tags, chainIds, needs, doesNotProve, remediation
  const tags = Array.isArray(lead.tags)
    ? lead.tags.map((t) => sanitizeExportString(t))
    : [];

  const chainIds = Array.isArray(lead.chainIds)
    ? lead.chainIds.map((c) => sanitizeExportString(c))
    : undefined;

  const needs = Array.isArray(lead.needs)
    ? lead.needs.map((n) => sanitizeExportString(n))
    : [];

  const doesNotProve = Array.isArray(lead.doesNotProve)
    ? lead.doesNotProve.map((d) => sanitizeExportString(d))
    : [];

  const remediation =
    typeof lead.remediation === 'string' && lead.remediation.length > 0
      ? sanitizeExportString(lead.remediation)
      : undefined;

  const family = VALID_FAMILIES.has(lead.family) ? lead.family : 'F8';
  const tier = VALID_TIERS.has(lead.tier) ? lead.tier : 'whisper';
  const potential = VALID_POTENTIALS.has(lead.potential) ? lead.potential : 'info';
  const sourceSensor = VALID_SENSORS.has(lead.sourceSensor) ? lead.sourceSensor : 'S2';
  const scopeStatus = VALID_SCOPES.has(lead.scopeStatus) ? lead.scopeStatus : 'unknown';
  const confidence = typeof lead.confidence === 'number' && Number.isFinite(lead.confidence)
    ? Math.min(1.0, Math.max(0.0, lead.confidence))
    : 0.8;
  const timestamp = typeof lead.timestamp === 'number' && Number.isFinite(lead.timestamp)
    ? lead.timestamp
    : Date.now();
  const triageState = lead.triageState !== undefined && VALID_TRIAGE_STATES.has(lead.triageState)
    ? lead.triageState
    : undefined;

  return {
    id,
    ruleId,
    family,
    tier,
    potential,
    confidence,
    title,
    needs,
    doesNotProve,
    evidence: {
      preview,
      location,
      ...(sanitizedContext !== undefined ? { context: sanitizedContext } : {}),
      ...(sanitizedNames !== undefined ? { extractedNames: sanitizedNames } : {}),
    },
    tags,
    scopeStatus,
    timestamp,
    origin,
    url,
    sourceSensor,
    ...(chainIds !== undefined ? { chainIds } : {}),
    ...(typeof lead.priority === 'number' && Number.isFinite(lead.priority) ? { priority: lead.priority } : {}),
    ...(typeof lead.novelty === 'boolean' ? { novelty: lead.novelty } : {}),
    ...(typeof lead.pinned === 'boolean' ? { pinned: lead.pinned } : {}),
    ...(triageState !== undefined ? { triageState } : {}),
    ...(remediation !== undefined ? { remediation } : {}),
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
    lines.push(`## [${lead.potential.toUpperCase()} POTENTIAL (HYPOTHESIS)] ${lead.title} (${lead.ruleId})`);
    lines.push(`- **Status**: Lead Hypothesis (Not a verified exploit) | **Family**: ${lead.family} | **Tier**: ${lead.tier} | **Confidence**: ${lead.confidence}`);
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
    if (lead.needs !== undefined && lead.needs.length > 0) {
      lines.push(`- **Needs** (to confirm impact): ${lead.needs.join('; ')}`);
    }
    if (lead.doesNotProve !== undefined && lead.doesNotProve.length > 0) {
      lines.push(`- **Does NOT prove**: ${lead.doesNotProve.join('; ')}`);
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
 *
 * SARIF severity note: Lead `potential` is an unconfirmed hypothesis, NOT a confirmed
 * vulnerability severity. SARIF `level` is always `"warning"` regardless of potential.
 * The `potential` value is preserved in `properties.potential` for tooling that wants it.
 */
export function formatLeadsReportSarif(leads: Lead[]): string {
  const sanitized = leads.map(sanitizeReportLead);

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
                properties: {
                  // potential is a hypothesis label, not a confirmed severity
                  potentialImpact: matching !== undefined ? matching.potential : 'unknown',
                },
              };
            }),
          },
        },
        results: sanitized.map(lead => ({
          ruleId: lead.ruleId,
          // INVARIANT: always "warning" — potential is unconfirmed hypothesis, not severity
          level: 'warning' as const,
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
          properties: {
            // Preserve potential as informational, NOT as severity
            potential: lead.potential,
            tier: lead.tier,
            confidence: lead.confidence,
            scopeStatus: lead.scopeStatus,
            needs: lead.needs ?? [],
            doesNotProve: lead.doesNotProve ?? [],
            corroborationStatus: 'unconfirmed',
          },
        })),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
