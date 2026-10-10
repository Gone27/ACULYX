import type { Lead } from '../types';
import { maskSecret, maskLocation } from '../sieve/mask';

export type ParamCategory =
  | 'redirect'
  | 'ssrf'
  | 'file'
  | 'idor'
  | 'debug'
  | 'callback'
  | 'general';

const REDIRECT_PARAMS = new Set([
  'redirect', 'redirect_uri', 'redirect_url', 'return', 'return_url',
  'next', 'url', 'dest', 'destination', 'target', 'goto', 'rurl', 'out', 'view', 'link',
]);

const SSRF_PARAMS = new Set([
  'webhook', 'feed', 'host', 'port', 'load_from', 'proxy', 'uri', 'fetch_url',
  'remote', 'source_url', 'api_url', 'endpoint', 'service',
]);

const FILE_PARAMS = new Set([
  'file', 'filepath', 'path', 'document', 'doc', 'folder', 'root',
  'pg', 'template', 'include', 'page', 'filename', 'read',
]);

const IDOR_PARAMS = new Set([
  'id', 'user_id', 'account_id', 'doc_id', 'order_id', 'profile_id',
  'uuid', 'uid', 'customer_id', 'member_id', 'team_id', 'org_id',
]);

const DEBUG_PARAMS = new Set([
  'debug', 'test', 'dev', 'trace', 'verbose', 'dbg', 'source', 'benchmark',
]);

const CALLBACK_PARAMS = new Set([
  'callback', 'cb', 'jsonp', 'call',
]);

export function classifyParamName(paramName: string): ParamCategory {
  const norm = paramName.toLowerCase().trim();
  if (REDIRECT_PARAMS.has(norm)) return 'redirect';
  if (SSRF_PARAMS.has(norm)) return 'ssrf';
  if (FILE_PARAMS.has(norm)) return 'file';
  if (IDOR_PARAMS.has(norm)) return 'idor';
  if (DEBUG_PARAMS.has(norm)) return 'debug';
  if (CALLBACK_PARAMS.has(norm)) return 'callback';
  return 'general';
}

let leadCounter = 0;
function nextLeadId(prefix: string): string {
  leadCounter++;
  return `LD-${prefix}-${Date.now().toString(36)}-${leadCounter}`;
}

export function detectParamLeads(
  url: string,
  scopeStatus: Lead['scopeStatus'] = 'unknown'
): Lead[] {
  const leads: Lead[] = [];
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return leads;
  }

  const origin = parsed.origin;
  const paramNames = Array.from(parsed.searchParams.keys());

  for (const name of paramNames) {
    const category = classifyParamName(name);

    if (category === 'redirect') {
      leads.push({
        id: nextLeadId('PAR-REDIR'),
        ruleId: 'PAR-002',
        family: 'F5',
        tier: 'whisper',
        potential: 'medium',
        confidence: 0.65,
        title: `Open Redirect Candidate Parameter: ${name}`,
        needs: ['test off-origin redirect validation logic on parameter'],
        doesNotProve: ['unvalidated open redirect'],
        evidence: {
          preview: maskSecret(name),
          location: maskLocation(url),
          extractedNames: [name],
          context: `Parameter '${name}' belongs to redirect class`,
        },
        tags: ['open-redirect-param', 'redirect', 'param-lead'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S1',
      });
    } else if (category === 'ssrf') {
      leads.push({
        id: nextLeadId('PAR-SSRF'),
        ruleId: 'PAR-002',
        family: 'F5',
        tier: 'whisper',
        potential: 'high',
        confidence: 0.6,
        title: `SSRF Candidate Parameter: ${name}`,
        needs: ['verify if server performs server-side network requests to target value'],
        doesNotProve: ['server-side request forgery'],
        evidence: {
          preview: maskSecret(name),
          location: maskLocation(url),
          extractedNames: [name],
        },
        tags: ['ssrf-param', 'ssrf', 'param-lead'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S1',
      });
    } else if (category === 'debug') {
      leads.push({
        id: nextLeadId('PAR-DEBUG'),
        ruleId: 'PAR-002',
        family: 'F5',
        tier: 'whisper',
        potential: 'low',
        confidence: 0.7,
        title: `Debug / Diagnostic Flag Parameter: ${name}`,
        needs: ['test parameter with boolean/verbose toggles'],
        doesNotProve: ['unauthorized debug disclosure'],
        evidence: {
          preview: maskSecret(name),
          location: maskLocation(url),
          extractedNames: [name],
        },
        tags: ['debug-param', 'debug', 'param-lead'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S1',
      });
    }
  }

  return leads;
}

/**
 * Detect passive reflected inputs across DOM contexts (PAR-003).
 */
export function detectReflectedInput(
  html: string,
  params: Record<string, string>,
  url: string,
  scopeStatus: Lead['scopeStatus'] = 'unknown'
): Lead[] {
  const leads: Lead[] = [];
  if (html.length === 0) return leads;

  const origin = (() => {
    try {
      return new URL(url).origin;
    } catch {
      return 'https://unknown';
    }
  })();

  for (const [paramName, paramVal] of Object.entries(params)) {
    if (!paramVal || paramVal.length < 3) continue;

    // Skip high entropy secrets/tokens from reflection check
    if (paramVal.length > 64) continue;

    const idx = html.indexOf(paramVal);
    if (idx !== -1) {
      // Determine context
      const snippet = html.slice(Math.max(0, idx - 50), Math.min(html.length, idx + paramVal.length + 50));

      let contextTag = 'html-context';
      if (/<script[^>]*>[^<]*$/i.test(html.slice(0, idx))) {
        contextTag = 'script-context';
      } else if (/<[^>]*=[^>]*$/i.test(html.slice(0, idx))) {
        contextTag = 'attr-context';
      } else if (/<!--[^>]*$/i.test(html.slice(0, idx))) {
        contextTag = 'comment-context';
      }

      leads.push({
        id: nextLeadId('PAR-REFLECT'),
        ruleId: 'PAR-003',
        family: 'F5',
        tier: 'strong',
        potential: 'medium',
        confidence: 0.8,
        title: `Reflected Input Detected in ${contextTag}: ${paramName}`,
        needs: ['verify sanitization, encoding, and CSP script execution barriers'],
        doesNotProve: ['executable Cross-Site Scripting (XSS)'],
        evidence: {
          preview: maskSecret(`${paramName} reflected in ${contextTag}`),
          location: maskLocation(url),
          context: `Parameter reflection found in ${contextTag}. Snippet: ${snippet.slice(0, 80)}`,
          extractedNames: [paramName],
        },
        tags: ['reflected-input', contextTag, 'injection-lead'],
        scopeStatus,
        timestamp: Date.now(),
        origin,
        url,
        sourceSensor: 'S3',
        remediation: 'Ensure context-aware output encoding is applied before rendering user input.',
      });
    }
  }

  return leads;
}
