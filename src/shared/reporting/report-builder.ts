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
const CANARY_RE = /\b[a-zA-Z0-9_-]*(?:canary|secret|token|password|passwd|apiKey|api_key)_[a-zA-Z0-9_-]+\b/gi;

/**
 * Sanitizes a URL for report inclusion by stripping credentials,
 * query strings, and fragments by default, and sanitizing path segments.
 */
export function sanitizeUrlForReport(rawUrl: string): string {
  if (!rawUrl || typeof rawUrl !== 'string') return '';
  const trimmed = rawUrl.trim();
  if (trimmed.length === 0) return '';

  try {
    const parsed = new URL(trimmed);
    // Strip userinfo credentials
    parsed.username = '';
    parsed.password = '';
    // Strip query strings and fragments by default in bug-bounty reports
    parsed.search = '';
    parsed.hash = '';

    // Redact path
    return sanitizeUrlForStorage(parsed.origin + parsed.pathname);
  } catch {
    // Relative URL or invalid URL format
    const noCreds = trimmed
      .replace(/^[a-zA-Z0-9+.-]+:\/\/[^@/]+@/, '')
      .replace(/^[^@/]+@/, '');
    const beforeHash = noCreds.split('#')[0] ?? '';
    const beforeQuery = beforeHash.split('?')[0] ?? '';
    return sanitizeUrlForStorage(beforeQuery);
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

  // 5. Redact sensitive path segments (handles compound paths like /tenant-reset/, /password-reset/, etc.)
  sanitized = sanitized.replace(
    /(\/(?:[a-zA-Z0-9_.-]*(?:reset|token|auth|verify|confirm|session|secret|credential|passwd|password)[a-zA-Z0-9_.-]*)\/)([^/\s?#]+)/gi,
    '$1[token]',
  );

  // 6. Redact URL query parameter values in text (including percent-encoded query param names)
  sanitized = sanitized.replace(
    /([?&][a-zA-Z0-9_.~%-]+[=:])([^&\s"'<>#]+)/g,
    '$1[REDACTED]',
  );

  // 7. Redact URL fragments in text
  sanitized = sanitized.replace(
    /#([^\s"'<>)\]]+)/g,
    '#[REDACTED]',
  );

  // 8. Redact key-value token patterns in free text (supporting percent-encoding e.g. auth%5Ftoken=...)
  sanitized = sanitized.replace(
    /\b([a-zA-Z0-9_.~%-]*(?:auth|token|secret|api_?key|key|password|passwd|pwd|code_?verifier|code_?challenge|state|session|ticket|credential)[a-zA-Z0-9_.~%-]*)\s*([:=])(\s*)([^\s,;'"<>&)]+)/gi,
    (match, p1: string, p2: string, p3: string, p4: string) => {
      if (p4 === '[REDACTED]' || p4 === '[token]' || p4 === '[id]') {
        return match;
      }
      return `${p1}${p2}${p3}[REDACTED]`;
    },
  );

  // 9. Redact JWTs
  sanitized = sanitized.replace(JWT_RE, '[token]');

  // 10. Redact UUIDs
  sanitized = sanitized.replace(UUID_RE, '[id]');

  // 11. Redact hex tokens
  sanitized = sanitized.replace(HEX_TOKEN_RE, '[token]');

  // 12. Redact known canary patterns
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
    ].map((step) => redactAllSecrets(step));

    const preconditions: string[] = [
      `Valid network access to ${target}.`,
      `Passive HTTP response inspection capabilities.`,
    ].map((pre) => redactAllSecrets(pre));

    const rawObserved =
      finding.evidence.length > 0
        ? `Server responded with: ${sanitizedEvidence}`
        : `Server omitted the required security control for rule ${finding.ruleId}.`;
    const observedBehavior = redactAllSecrets(rawObserved);

    const baseLimitations: string[] = finding.limitations && finding.limitations.length > 0
      ? [...finding.limitations]
      : [
          'Passive observation only; no intrusive payloads were transmitted.',
          'Intermediaries or reverse-proxies may alter response headers dynamically.',
        ];
    const limitations = baseLimitations.map((lim) => redactAllSecrets(lim));

    const reviewState = options?.reviewState ?? 'unreviewed';

    const rawSummary =
      (finding.impact !== undefined && finding.impact.length > 0)
        ? finding.impact
        : `Passive analysis identified ${finding.title} (${finding.ruleId}) on target ${target}.`;

    const rawImpact =
      (finding.impact !== undefined && finding.impact.length > 0)
        ? finding.impact
        : 'Potential security exposure resulting from missing or improperly configured HTTP security controls.';

    const rawRemediation = meta.remediation.length > 0 ? meta.remediation : finding.recommendation;

    const draft: BugBountyReportDraft = {
      id: `aculyx-${finding.ruleId.toLowerCase()}-${Date.now()}`,
      title: redactAllSecrets(`[${finding.severity.toUpperCase()}] ${finding.title} on ${target}`),
      severity: finding.severity,
      target,
      summary: redactAllSecrets(rawSummary),
      reproductionSteps,
      preconditions,
      expectedBehavior: redactAllSecrets(meta.expectedBehavior),
      observedBehavior,
      impact: redactAllSecrets(rawImpact),
      evidence: sanitizedEvidence,
      remediation: redactAllSecrets(rawRemediation),
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
    const rawRefs = meta.references.length > 0 ? meta.references : ((finding.reference !== undefined && finding.reference.length > 0) ? [finding.reference] : []);
    if (rawRefs.length > 0) {
      draft.references = rawRefs.map((ref) => redactAllSecrets(ref));
    }

    return draft;
  }

  /**
   * Deeply sanitizes all draft text fields, URLs, and collections as a final security boundary.
   */
  static sanitizeDraft(draft: BugBountyReportDraft): BugBountyReportDraft {
    const clean: BugBountyReportDraft = {
      ...draft,
      title: redactAllSecrets(draft.title ?? ''),
      target: sanitizeUrlForReport(draft.target ?? ''),
      summary: redactAllSecrets(draft.summary ?? ''),
      reproductionSteps: (draft.reproductionSteps ?? []).map((s) => redactAllSecrets(s)),
      preconditions: (draft.preconditions ?? []).map((p) => redactAllSecrets(p)),
      expectedBehavior: redactAllSecrets(draft.expectedBehavior ?? ''),
      observedBehavior: redactAllSecrets(draft.observedBehavior ?? ''),
      impact: redactAllSecrets(draft.impact ?? ''),
      evidence: redactAllSecrets(draft.evidence ?? ''),
      remediation: redactAllSecrets(draft.remediation ?? ''),
      limitations: (draft.limitations ?? []).map((l) => redactAllSecrets(l)),
    };

    if (draft.references !== undefined) {
      clean.references = draft.references.map((r) => redactAllSecrets(r));
    }

    return clean;
  }

  /**
   * Formats a BugBountyReportDraft into clean, submission-ready Markdown.
   * Independently sanitizes caller-supplied and modified drafts.
   */
  static formatReportAsMarkdown(draft: BugBountyReportDraft): string {
    const cleanDraft = ReportBuilder.sanitizeDraft(draft);
    const lines: string[] = [];

    lines.push(`# ${cleanDraft.title}\n`);

    lines.push(`## Vulnerability Details`);
    lines.push(`- **Target:** \`${cleanDraft.target}\``);
    lines.push(`- **Severity:** **${cleanDraft.severity.toUpperCase()}**`);
    if (cleanDraft.ruleId !== undefined && cleanDraft.ruleId.length > 0) lines.push(`- **Rule ID:** \`${cleanDraft.ruleId}\``);
    if (cleanDraft.cweId !== undefined && cleanDraft.cweId.length > 0) lines.push(`- **CWE:** [${cleanDraft.cweId}](https://cwe.mitre.org/data/definitions/${cleanDraft.cweId.replace('CWE-', '')}.html)`);
    if (cleanDraft.cvssScore !== undefined) lines.push(`- **CVSS Score:** ${cleanDraft.cvssScore.toFixed(1)}`);
    if (cleanDraft.scopeStatus !== undefined) lines.push(`- **Scope Status:** \`${cleanDraft.scopeStatus}\``);
    lines.push(`- **Researcher Review State:** \`${cleanDraft.reviewState}\`\n`);

    lines.push(`## Executive Summary`);
    lines.push(`${cleanDraft.summary}\n`);

    lines.push(`## Preconditions`);
    for (const pre of cleanDraft.preconditions) {
      lines.push(`- ${pre}`);
    }
    lines.push('');

    lines.push(`## Reproduction Steps`);
    for (const step of cleanDraft.reproductionSteps) {
      lines.push(`${step}`);
    }
    lines.push('');

    lines.push(`## Expected vs Observed Behavior`);
    lines.push(`**Expected:**\n${cleanDraft.expectedBehavior}\n`);
    lines.push(`**Observed:**\n${cleanDraft.observedBehavior}\n`);

    lines.push(`## Sanitized Evidence`);
    lines.push('```http');
    lines.push(cleanDraft.evidence);
    lines.push('```\n');

    lines.push(`## Security Impact`);
    lines.push(`${cleanDraft.impact}\n`);

    lines.push(`## Remediation`);
    lines.push(`${cleanDraft.remediation}\n`);

    if (cleanDraft.limitations.length > 0) {
      lines.push(`## Detection Limitations & Caveats`);
      for (const lim of cleanDraft.limitations) {
        lines.push(`- ${lim}`);
      }
      lines.push('');
    }

    if (cleanDraft.references !== undefined && cleanDraft.references.length > 0) {
      lines.push(`## References`);
      for (const ref of cleanDraft.references) {
        lines.push(`- ${ref}`);
      }
      lines.push('');
    }

    lines.push(`---\n*Report generated by ACULYX Passive Bug-Bounty Scanner. URLs, headers, and reported fields have been processed by automated secret redaction; researchers must review all details prior to submission.*`);

    return lines.join('\n');
  }

  /**
   * Serializes a BugBountyReportDraft into formatted JSON string.
   * Independently sanitizes caller-supplied and modified drafts.
   */
  static formatReportAsJson(draft: BugBountyReportDraft): string {
    const cleanDraft = ReportBuilder.sanitizeDraft(draft);
    return JSON.stringify(cleanDraft, null, 2);
  }
}
