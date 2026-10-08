/**
 * Bug-Bounty Report Builder & Comprehensive Secret Redaction for ACULYX.
 *
 * Implements high-confidence Markdown and JSON bug bounty report draft generation:
 * - Deterministic reproduction steps, preconditions, expected vs observed behavior.
 * - Realistic impact narrative and remediation guidance.
 * - Strict Invariant: Zero secret leakage — credentials in URLs, sensitive path segments,
 *   fragments, raw authorization headers, Set-Cookie lines, and canaries are scrubbed.
 */

import type { Finding } from '../types';
import type { BugBountyReportDraft, ResearcherReviewState } from './types';
import { sanitizeUrlForStorage, redactHeaderValue } from '../../rules/utils';

// ─── Secret Redaction Utilities ───────────────────────────────────────────────

const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
const JWT_RE = /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g;
const HEX_TOKEN_RE = /\b[0-9a-f]{32,}\b/gi;
const CANARY_RE = /\b(?:canary|secret|token|password|passwd|apiKey|api_key)_[a-zA-Z0-9_-]+\b/gi;

const SENSITIVE_QUERY_PARAMS = new Set([
  'token',
  'access_token',
  'id_token',
  'refresh_token',
  'auth',
  'authentication',
  'api_key',
  'apikey',
  'key',
  'secret',
  'password',
  'passwd',
  'pwd',
  'session',
  'sessionid',
  'sessid',
  'sig',
  'signature',
  'code',
  'ticket',
  'credential',
  'canary',
]);

/**
 * Sanitizes a URL for report inclusion by stripping credentials,
 * redacting sensitive path segments, filtering sensitive query parameters,
 * and removing fragments.
 */
export function sanitizeUrlForReport(rawUrl: string): string {
  if (!rawUrl || typeof rawUrl !== 'string') return '';
  const trimmed = rawUrl.trim();
  if (trimmed.length === 0) return '';

  // If already sanitized by sanitizeUrlForStorage, handle query params safely
  try {
    const parsed = new URL(trimmed);
    // Strip userinfo credentials
    parsed.username = '';
    parsed.password = '';
    // Strip fragment
    parsed.hash = '';

    // Redact sensitive query parameters
    const searchParams = new URLSearchParams(parsed.search);
    const keys = Array.from(searchParams.keys());
    for (const key of keys) {
      if (SENSITIVE_QUERY_PARAMS.has(key.toLowerCase())) {
        searchParams.set(key, '[REDACTED]');
      }
    }
    parsed.search = searchParams.toString();

    // Redact path
    const sanitizedBase = sanitizeUrlForStorage(parsed.origin + parsed.pathname);
    return parsed.search.length > 0
      ? `${sanitizedBase}${parsed.search.startsWith('?') ? '' : '?'}${parsed.search}`
      : sanitizedBase;
  } catch {
    // Relative URL or invalid URL format
    const noCreds = trimmed
      .replace(/^[a-zA-Z0-9+.-]+:\/\/[^@/]+@/, '')
      .replace(/^[^@/]+@/, '');
    const beforeHash = noCreds.split('#')[0] ?? '';
    const parts = beforeHash.split('?');
    const pathPart = sanitizeUrlForStorage(parts[0] ?? '');
    if (parts.length > 1 && parts[1] !== undefined && parts[1].length > 0) {
      try {
        const sp = new URLSearchParams(parts[1]);
        for (const k of Array.from(sp.keys())) {
          if (SENSITIVE_QUERY_PARAMS.has(k.toLowerCase())) {
            sp.set(k, '[REDACTED]');
          }
        }
        return `${pathPart}?${sp.toString()}`;
      } catch {
        return pathPart;
      }
    }
    return pathPart;
  }
}

/**
 * Performs comprehensive secret and canary token redaction on arbitrary text.
 */
export function redactAllSecrets(text: string): string {
  if (!text || typeof text !== 'string') return '';

  let sanitized = text;

  // 1. Redact Authorization and Proxy-Authorization header lines
  sanitized = sanitized.replace(
    /(?:authorization|proxy-authorization)\s*:\s*(?:bearer|basic|token)?\s*[^\r\n]+/gi,
    (match) => {
      const colonIdx = match.indexOf(':');
      if (colonIdx !== -1) {
        const headerName = match.slice(0, colonIdx).trim();
        return `${headerName}: [REDACTED]`;
      }
      return match;
    },
  );

  // 2. Redact Set-Cookie header lines
  sanitized = sanitized.replace(/set-cookie\s*:\s*[^\r\n]+/gi, (match) => {
    const colonIdx = match.indexOf(':');
    if (colonIdx !== -1) {
      const headerName = match.slice(0, colonIdx).trim();
      const val = match.slice(colonIdx + 1).trim();
      return `${headerName}: ${redactHeaderValue('set-cookie', val)}`;
    }
    return match;
  });

  // 3. Redact Cookie header lines (use negative lookbehind to avoid matching Set-Cookie)
  sanitized = sanitized.replace(/(?<![\w-])cookie\s*:\s*[^\r\n]+/gi, (match) => {
    const colonIdx = match.indexOf(':');
    if (colonIdx !== -1) {
      const headerName = match.slice(0, colonIdx).trim();
      const val = match.slice(colonIdx + 1).trim();
      return `${headerName}: ${redactHeaderValue('cookie', val)}`;
    }
    return match;
  });

  // 4. Redact URL userinfo credentials (with scheme, user-only, or schemeless)
  sanitized = sanitized.replace(
    /([a-zA-Z0-9+.-]+:\/\/)([^@/\s:]+):([^@/\s]+)@/g,
    '$1[REDACTED]:[REDACTED]@',
  );
  sanitized = sanitized.replace(
    /([a-zA-Z0-9+.-]+:\/\/)([^@/\s:]+)@/g,
    '$1[REDACTED]@',
  );
  sanitized = sanitized.replace(
    /(^|[\s"'<(])([a-zA-Z0-9_.-]+):([^@/\s:]+)@([a-zA-Z0-9.-]+)/g,
    '$1[REDACTED]:[REDACTED]@$4',
  );

  // 5. Redact sensitive path segments
  sanitized = sanitized.replace(
    /(\/(?:reset|token|auth|verify|confirm)\/)([^/\s?#]+)/gi,
    '$1[token]',
  );

  // 6. Redact fragment secrets
  sanitized = sanitized.replace(
    /#(?:token|access_token|secret|canary|state|id)=[^&\s]+/gi,
    '#[REDACTED]',
  );

  // 7. Redact JWTs
  sanitized = sanitized.replace(JWT_RE, '[token]');

  // 8. Redact UUIDs
  sanitized = sanitized.replace(UUID_RE, '[id]');

  // 9. Redact hex tokens
  sanitized = sanitized.replace(HEX_TOKEN_RE, '[token]');

  // 10. Redact known canary patterns
  sanitized = sanitized.replace(CANARY_RE, '[REDACTED]');

  return sanitized;
}

// ─── Rule Knowledge Base & Default Text Generators ────────────────────────────

interface RuleMetadata {
  cweId?: string;
  cvssScore?: number;
  expectedBehavior: string;
  remediation: string;
  references: string[];
}

const RULE_KNOWLEDGE_BASE: Record<string, RuleMetadata> = {
  'HSTS-001': {
    cweId: 'CWE-319',
    cvssScore: 6.5,
    expectedBehavior:
      'The server must enforce HTTPS connections using a Strict-Transport-Security header with a max-age of at least 31536000 seconds (1 year) and includeSubDomains.',
    remediation:
      'Add the Strict-Transport-Security header to all HTTPS responses at the edge gateway or server configuration:\n`Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`',
    references: [
      'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html',
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
    ],
  },
  'CSP-001': {
    cweId: 'CWE-1021',
    cvssScore: 7.2,
    expectedBehavior:
      'The server must serve a valid, restrictive Content-Security-Policy header restricting script execution and resource loading.',
    remediation:
      "Deploy a robust Content-Security-Policy header restricting executable script sources:\n`Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-...'; object-src 'none'; base-uri 'self';`",
    references: [
      'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html',
      'https://csp.withgoogle.com/docs/strict-csp.html',
    ],
  },
  'CSP-005': {
    cweId: 'CWE-1021',
    cvssScore: 5.4,
    expectedBehavior:
      "The server must prevent unauthorized framing by defining frame-ancestors in Content-Security-Policy or using X-Frame-Options: DENY / SAMEORIGIN.",
    remediation:
      "Configure Content-Security-Policy with the frame-ancestors directive:\n`Content-Security-Policy: frame-ancestors 'self';`",
    references: [
      'https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html',
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors',
    ],
  },
  'XFO-001': {
    cweId: 'CWE-1021',
    cvssScore: 5.4,
    expectedBehavior:
      'The server must protect against clickjacking by serving an X-Frame-Options header (DENY or SAMEORIGIN) or CSP frame-ancestors.',
    remediation:
      'Add the X-Frame-Options header to all HTML responses:\n`X-Frame-Options: SAMEORIGIN`\nOr preferably enforce CSP `frame-ancestors`.',
    references: [
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options',
      'https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html',
    ],
  },
  'XCTO-001': {
    cweId: 'CWE-79',
    cvssScore: 4.3,
    expectedBehavior:
      'The server must disable MIME-type sniffing by returning X-Content-Type-Options: nosniff on all responses.',
    remediation:
      'Emit the header across all HTTP responses:\n`X-Content-Type-Options: nosniff`',
    references: [
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
    ],
  },
  'COOK-001': {
    cweId: 'CWE-614',
    cvssScore: 6.5,
    expectedBehavior:
      'All session and authentication cookies must include the Secure, HttpOnly, and SameSite attributes.',
    remediation:
      'Update session cookie generation to enforce flags:\n`Set-Cookie: session=[token]; Secure; HttpOnly; SameSite=Lax; Path=/`',
    references: [
      'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies-attributes',
    ],
  },
  'CORS-001': {
    cweId: 'CWE-942',
    cvssScore: 7.5,
    expectedBehavior:
      'The server must not reflect arbitrary Origin headers with Access-Control-Allow-Credentials: true or emit Access-Control-Allow-Origin: * on authenticated endpoints.',
    remediation:
      'Implement an explicit, strict server-side whitelist for allowed cross-origin requests. Never reflect the Origin header without strict origin validation.',
    references: [
      'https://portswigger.net/web-security/cors',
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS',
    ],
  },
};

export class ReportBuilder {
  /**
   * Generates a complete BugBountyReportDraft from a scanner finding and optional context.
   */
  static buildReportDraft(
    finding: Finding,
    options?: {
      targetUrl?: string;
      reviewState?: ResearcherReviewState;
      triageNotes?: string;
      scopeNote?: string;
    },
  ): BugBountyReportDraft {
    const target = sanitizeUrlForReport(
      options?.targetUrl ?? finding.sourceUrl ?? 'https://target.example.com',
    );
    const meta = RULE_KNOWLEDGE_BASE[finding.ruleId] ?? {
      expectedBehavior:
        'The server should implement recognized security hardening headers and standards.',
      remediation:
        finding.recommendation.length > 0 ? finding.recommendation : 'Consult security best practices to remediate this finding.',
      references: (finding.reference !== undefined && finding.reference.length > 0) ? [finding.reference] : [],
    };

    const sanitizedEvidence = redactAllSecrets(finding.evidence.length > 0 ? finding.evidence : 'Header or attribute not observed');

    const reproductionSteps: string[] = [
      `1. Open an HTTP inspection client or browser developer tools network tab.`,
      `2. Navigate to target endpoint: ${target}`,
      `3. Inspect the HTTP response headers and cookies returned by the server.`,
      `4. Verify the observed response for ${finding.ruleId}: "${sanitizedEvidence}".`,
      `5. Notice the absence of secure compliance configuration described below.`,
    ];

    const preconditions: string[] = [
      `Valid network access to ${target}.`,
      `Passive HTTP response inspection capabilities.`,
    ];

    const observedBehavior =
      finding.evidence.length > 0
        ? `Server responded with: ${sanitizedEvidence}`
        : `Server omitted the required security control for rule ${finding.ruleId}.`;

    const limitations: string[] = finding.limitations && finding.limitations.length > 0
      ? [...finding.limitations]
      : [
          'Passive observation only; no intrusive payloads were transmitted.',
          'Intermediaries or reverse-proxies may alter response headers dynamically.',
        ];

    const reviewState = options?.reviewState ?? 'unreviewed';

    const draft: BugBountyReportDraft = {
      id: `aculyx-${finding.ruleId.toLowerCase()}-${Date.now()}`,
      title: `[${finding.severity.toUpperCase()}] ${finding.title} on ${target}`,
      severity: finding.severity,
      target,
      summary:
        (finding.impact !== undefined && finding.impact.length > 0)
          ? finding.impact
          : `Passive analysis identified ${finding.title} (${finding.ruleId}) on target ${target}.`,
      reproductionSteps,
      preconditions,
      expectedBehavior: meta.expectedBehavior,
      observedBehavior,
      impact:
        (finding.impact !== undefined && finding.impact.length > 0)
          ? finding.impact
          : 'Potential security exposure resulting from missing or improperly configured HTTP security controls.',
      evidence: sanitizedEvidence,
      remediation: meta.remediation.length > 0 ? meta.remediation : finding.recommendation,
      limitations,
      reviewState,
      updatedAt: Date.now(),
      createdAt: Date.now(),
      ruleId: finding.ruleId,
    };

    if (finding.scopeStatus !== undefined) {
      draft.scopeStatus = finding.scopeStatus;
    }
    if (meta.cweId !== undefined) {
      draft.cweId = meta.cweId;
    }
    if (meta.cvssScore !== undefined) {
      draft.cvssScore = meta.cvssScore;
    }
    if (meta.references.length > 0) {
      draft.references = [...meta.references];
    }

    return draft;
  }

  /**
   * Formats a BugBountyReportDraft into clean, submission-ready Markdown.
   */
  static formatReportAsMarkdown(draft: BugBountyReportDraft): string {
    const lines: string[] = [];

    lines.push(`# ${draft.title}\n`);

    lines.push(`## Vulnerability Details`);
    lines.push(`- **Target:** \`${draft.target}\``);
    lines.push(`- **Severity:** **${draft.severity.toUpperCase()}**`);
    if (draft.ruleId !== undefined && draft.ruleId.length > 0) lines.push(`- **Rule ID:** \`${draft.ruleId}\``);
    if (draft.cweId !== undefined && draft.cweId.length > 0) lines.push(`- **CWE:** [${draft.cweId}](https://cwe.mitre.org/data/definitions/${draft.cweId.replace('CWE-', '')}.html)`);
    if (draft.cvssScore !== undefined) lines.push(`- **CVSS Score:** ${draft.cvssScore.toFixed(1)}`);
    if (draft.scopeStatus !== undefined) lines.push(`- **Scope Status:** \`${draft.scopeStatus}\``);
    lines.push(`- **Researcher Review State:** \`${draft.reviewState}\`\n`);

    lines.push(`## Executive Summary`);
    lines.push(`${draft.summary}\n`);

    lines.push(`## Preconditions`);
    for (const pre of draft.preconditions) {
      lines.push(`- ${pre}`);
    }
    lines.push('');

    lines.push(`## Reproduction Steps`);
    for (const step of draft.reproductionSteps) {
      lines.push(`${step}`);
    }
    lines.push('');

    lines.push(`## Expected vs Observed Behavior`);
    lines.push(`**Expected:**\n${draft.expectedBehavior}\n`);
    lines.push(`**Observed:**\n${draft.observedBehavior}\n`);

    lines.push(`## Sanitized Evidence`);
    lines.push('```http');
    lines.push(draft.evidence);
    lines.push('```\n');

    lines.push(`## Security Impact`);
    lines.push(`${draft.impact}\n`);

    lines.push(`## Remediation`);
    lines.push(`${draft.remediation}\n`);

    if (draft.limitations.length > 0) {
      lines.push(`## Detection Limitations & Caveats`);
      for (const lim of draft.limitations) {
        lines.push(`- ${lim}`);
      }
      lines.push('');
    }

    if (draft.references !== undefined && draft.references.length > 0) {
      lines.push(`## References`);
      for (const ref of draft.references) {
        lines.push(`- ${ref}`);
      }
      lines.push('');
    }

    lines.push(`---\n*Report generated by ACULYX Passive Bug-Bounty Scanner. All credentials and sensitive tokens were strictly redacted.*`);

    return lines.join('\n');
  }

  /**
   * Serializes a BugBountyReportDraft into formatted JSON string.
   */
  static formatReportAsJson(draft: BugBountyReportDraft): string {
    return JSON.stringify(draft, null, 2);
  }
}
