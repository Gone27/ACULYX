/**
 * Content-Security-Policy Rule.
 *
 * Rules:
 *   CSP-001 (high)   — CSP header is absent entirely
 *   CSP-002 (high)   — effective script-src contains 'unsafe-inline'
 *   CSP-003 (high)   — effective script-src contains 'unsafe-eval'
 *   CSP-004 (medium) — effective script-src contains an overly broad wildcard source
 *   CSP-005 (medium) — frame-ancestors directive is absent
 *   CSP-006 (medium) — effective object-src is absent or not 'none'
 *   CSP-007 (low)    — base-uri directive is absent
 *   CSP-009 (info)   — script-src trusts a small curated set of bypass-prone hosts (heuristic)
 *
 * Returns both findings and the parsed directive map so other rules
 * (e.g. XFO) can inspect directives without re-parsing.
 */

import type { Finding, Hop } from '../../shared/types';
import { sanitizeEvidence, parseCspDirectives, hasCspBypassProtection } from '../utils';
import { URLS as JSONP_BYPASS_URLS } from 'csp_evaluator/dist/allowlist_bypasses/jsonp';
import { CspEvaluator } from 'csp_evaluator/dist/evaluator';
import { CspParser } from 'csp_evaluator/dist/parser';
import { Type, Severity } from 'csp_evaluator/dist/finding';

const REFERENCE =
  'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy';

const CSP_HEADER = 'content-security-policy';


/**
 * Bypass-prone hosts derived from Google's csp_evaluator maintained JSONP list.
 * Extracted at module-load time: strip scheme/path from each URL and deduplicate.
 *
 * This replaces the hand-written 4-item list with the package's curated set,
 * which Google keeps up to date with real-world bypass-prone endpoints.
 */
const CSP_BYPASS_HOSTS: ReadonlySet<string> = new Set(
  JSONP_BYPASS_URLS.map((url) => {
    // Strip leading '//' or 'https?://', take the host portion before first '/'
    const stripped = url.replace(/^(https?:)?\/\//, '');
    return (stripped.split('/')[0] ?? '').toLowerCase();
  }).filter((host) => host.length > 0),
);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Resolve the effective source list for a directive, falling back to
 * default-src when the specific directive is absent.
 *
 * Returns undefined when neither the specific directive nor default-src exists.
 */
function resolveEffective(
  directives: Map<string, string>,
  directive: string,
): string | undefined {
  return directives.get(directive) ?? directives.get('default-src');
}

/**
 * Split a CSP source-list string on whitespace and return individual tokens.
 */
function sourceTokens(sourceList: string): string[] {
  return sourceList.split(/\s+/).filter((t) => t.length > 0);
}

/**
 * Returns true when the source list contains a truly open wildcard or insecure scheme:
 *   - exactly '*' (allows script execution from any origin or scheme)
 *   - exactly 'http:' (allows unencrypted scripts subject to MITM)
 *   - exactly 'https:' when NOT protected by 'strict-dynamic' or nonces
 *
 * Scoped domain wildcards (e.g. '*.example.com', '*.muscache.com') are legitimate
 * CDN/subdomain patterns and are evaluated under subdomain trust, not as open wildcards.
 */
function hasWildcardSource(sourceList: string, isModernStrict: boolean): boolean {
  // In CSP Level 3, host-based sources and 'https:' are ignored when 'strict-dynamic' or nonces are present.
  if (isModernStrict) return false;

  const tokens = sourceTokens(sourceList);
  return tokens.some(
    (token) =>
      token === '*' ||
      token === 'http:' ||
      token === 'https:',
  );
}

function findBypassProneHosts(sourceList: string): string[] {
  const matched = new Set<string>();
  for (const token of sourceTokens(sourceList)) {
    if (token.startsWith("'") || token === '*') continue;
    const schemeStripped = token.replace(/^https?:\/\//i, '');
    const hostSource = schemeStripped.split('/')[0]?.toLowerCase() ?? '';
    const wildcard = hostSource.startsWith('*.');
    const host = hostSource.replace(/^\*\./, '').replace(/:\d+$/, '');
    if (host.length === 0) continue;

    for (const riskyHost of CSP_BYPASS_HOSTS) {
      if (host === riskyHost || host.endsWith(`.${riskyHost}`) || (wildcard && riskyHost.endsWith(`.${host}`))) {
        matched.add(riskyHost);
      }
    }
  }
  return [...matched];
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface CspResult {
  findings: Finding[];
  /** The parsed directive map — empty when CSP is absent. */
  directives: Map<string, string>;
}

/**
 * Evaluate the Content-Security-Policy header for the final response hop.
 * This function is pure — no browser APIs are used.
 *
 * @param finalHop - The last hop in the redirect chain.
 * @returns An object containing all findings and the parsed directives map.
 */
export function checkCsp(finalHop: Hop, metaCspFound = false): CspResult {
  const findings: Finding[] = [];
  const cspValue = finalHop.headers[CSP_HEADER];

  // CSP-001 — header absent entirely.
  if (cspValue === undefined) {
    const reportOnlyValue = finalHop.headers['content-security-policy-report-only'];
    if (metaCspFound) {
      findings.push({
        ruleId: 'CSP-008',
        category: 'header',
        severity: 'info',
        title: 'CSP detected in a meta tag; policy details are not evaluated',
        impact:
          'A meta CSP can enforce some policy directives, but it cannot replace response-header protections such as frame-ancestors and may take effect later in document parsing.',
        evidence: sanitizeEvidence('<meta http-equiv="Content-Security-Policy">'),
        recommendation:
          'Also send Content-Security-Policy as an HTTP response header for complete coverage. This report does not assess the meta policy contents.',
        reference: REFERENCE,
      });
    } else if (reportOnlyValue !== undefined) {
      findings.push({
        ruleId: 'CSP-001',
        category: 'header',
        severity: 'high',
        title: 'Only Content-Security-Policy-Report-Only is present; no enforcing CSP is configured',
        impact:
          'Report-Only policies observe violations but do not block unsafe content, so they do not provide CSP enforcement.',
        evidence: sanitizeEvidence(reportOnlyValue),
        recommendation:
          'After validating reports, deploy the intended policy as Content-Security-Policy. Keep Report-Only separately if continued monitoring is desired.',
        reference: REFERENCE,
      });
    } else {
      findings.push({
        ruleId: 'CSP-001',
        category: 'header',
        severity: 'high',
        title: 'Content-Security-Policy header is missing',
        impact:
          'Without a CSP, any Cross-Site Scripting (XSS) vulnerability can execute malicious scripts, steal login cookies, or take over user accounts.',
        evidence: sanitizeEvidence('(header absent)'),
        recommendation:
          'Add a Content-Security-Policy header. Start with a strict base policy ' +
          "such as \"default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'\".",
        reference: REFERENCE,
      });
    }
    // Without a CSP there is nothing more to parse.
    return { findings, directives: new Map() };
  }

  // Parse the header value into a directive map.
  const directives = parseCspDirectives(cspValue);

  if (!directives.has('default-src') && !directives.has('script-src')) {
    findings.push({
      ruleId: 'CSP-010', category: 'header', severity: 'info',
      title: 'CSP has no default-src or script-src fallback',
      impact: 'The policy does not establish a general resource fallback or an explicit script source policy.',
      evidence: sanitizeEvidence(cspValue),
      recommendation: "Add default-src as a baseline and define script-src explicitly where script loading needs a different policy.",
      reference: REFERENCE,
    });
  }

  // -------------------------------------------------------------------------
  // Script-src checks (falls back to default-src)
  // -------------------------------------------------------------------------
  const effectiveScriptSrc = resolveEffective(directives, 'script-src');

  if (effectiveScriptSrc !== undefined) {
    const { isModernStrict } = hasCspBypassProtection(effectiveScriptSrc);
    const bypassProneHosts = isModernStrict ? [] : findBypassProneHosts(effectiveScriptSrc);

    if (bypassProneHosts.length > 0) {
      findings.push({
        ruleId: 'CSP-009',
        category: 'header',
        severity: 'info',
        title: 'CSP script-src trusts host(s) with historically bypass-prone endpoints or libraries',
        impact:
          'Some allowlisted hosts expose JSONP endpoints or host libraries with script gadgets; actual exploitability depends on the specific endpoint, path, and version.',
        evidence: sanitizeEvidence(bypassProneHosts.join(', ')),
        recommendation:
          'Review whether each host is required, restrict paths where practical, pin library versions, and prefer nonces or hashes. This curated host match is a heuristic, not proof of a bypass.',
        reference: 'https://csp-evaluator.withgoogle.com/',
      });
    }

    // CSP-002 — 'unsafe-inline' in effective script-src.
    if (effectiveScriptSrc.includes("'unsafe-inline'")) {
      if (isModernStrict) {
        // Modern CSP Level 3: 'unsafe-inline' is ignored in modern browsers when a nonce,
        // hash, or 'strict-dynamic' is present. It is kept purely as an older-browser fallback.
        findings.push({
          ruleId: 'CSP-002',
          category: 'header',
          severity: 'info',
          title: "CSP script-src includes 'unsafe-inline' as a legacy fallback (safely ignored due to nonce/strict-dynamic)",
          impact:
            'Older browsers may allow inline scripts, but modern browsers safely ignore this fallback because a nonce or strict-dynamic is present.',
          evidence: sanitizeEvidence(effectiveScriptSrc),
          recommendation:
            "No action needed for modern browsers. 'unsafe-inline' is ignored by CSP Level 3 browsers when a nonce or 'strict-dynamic' is present.",
          reference: REFERENCE,
        });
      } else {
        findings.push({
          ruleId: 'CSP-002',
          category: 'header',
          severity: 'high',
          title: "CSP script-src contains 'unsafe-inline'",
          impact:
            'Injected HTML tags (like <script> or event handlers) can execute arbitrary JavaScript directly inside victim browsers.',
          evidence: sanitizeEvidence(effectiveScriptSrc),
          recommendation:
            "Remove 'unsafe-inline' and use nonces or hashes to allow specific inline scripts.",
          reference: REFERENCE,
        });
      }
    }

    // CSP-003 — 'unsafe-eval' in effective script-src.
    if (effectiveScriptSrc.includes("'unsafe-eval'")) {
      findings.push({
        ruleId: 'CSP-003',
        category: 'header',
        severity: 'high',
        title: "CSP script-src contains 'unsafe-eval'",
        impact:
          'Allows dynamic code execution via eval() and new Function(), enabling attackers who control string inputs to run arbitrary JavaScript.',
        evidence: sanitizeEvidence(effectiveScriptSrc),
        recommendation:
          "Remove 'unsafe-eval'. Refactor code that uses eval(), new Function(), or similar dynamic evaluation.",
        reference: REFERENCE,
      });
    }

    // CSP-004 — overly broad wildcard source in effective script-src.
    if (hasWildcardSource(effectiveScriptSrc, isModernStrict)) {
      findings.push({
        ruleId: 'CSP-004',
        category: 'header',
        severity: 'medium',
        title: 'CSP script-src contains an overly broad wildcard or scheme-only source',
        impact:
          'Open wildcard sources allow scripts to be loaded and executed from any external host on the web.',
        evidence: sanitizeEvidence(effectiveScriptSrc),
        recommendation:
          'Replace wildcard or scheme-only sources (*, http:, https:) with explicit ' +
          'allowlisted hostnames or use nonces/hashes.',
        reference: REFERENCE,
      });
    }
  }

  // -------------------------------------------------------------------------
  // CSP-005 — frame-ancestors absent.
  // -------------------------------------------------------------------------
  if (!directives.has('frame-ancestors')) {
    const xfo = finalHop.headers['x-frame-options']?.trim().toUpperCase();
    const hasValidXfo = xfo === 'DENY' || xfo === 'SAMEORIGIN';

    findings.push({
      ruleId: 'CSP-005',
      category: 'header',
      severity: hasValidXfo ? 'info' : 'medium',
      title: hasValidXfo
        ? "CSP is missing 'frame-ancestors' (mitigated by X-Frame-Options)"
        : "CSP is missing the 'frame-ancestors' directive",
      impact: hasValidXfo
        ? 'Legacy browsers without XFO support could potentially embed this page, but modern browsers are protected by X-Frame-Options.'
        : 'Malicious websites can embed your site in an invisible iframe to trick users into clicking buttons they cannot see (Clickjacking).',
      evidence: sanitizeEvidence(cspValue),
      recommendation:
        "Add \"frame-ancestors 'none'\" (or \"'self'\") to control which origins may embed this page.",
      reference: REFERENCE,
    });
  }

  // -------------------------------------------------------------------------
  // CSP-006 — object-src absent or not 'none' (falls back to default-src).
  // -------------------------------------------------------------------------
  const effectiveObjectSrc = resolveEffective(directives, 'object-src');

  if (
    effectiveObjectSrc === undefined ||
    !sourceTokens(effectiveObjectSrc).includes("'none'")
  ) {
    findings.push({
      ruleId: 'CSP-006',
      category: 'header',
      severity: 'medium',
      title: "CSP object-src is absent or not restricted to 'none'",
      impact:
        'Allows plugins (Flash, Java applets, PDF objects) to load untrusted resources that can bypass standard script constraints.',
      evidence: sanitizeEvidence(effectiveObjectSrc ?? '(directive absent)'),
      recommendation:
        "Add \"object-src 'none'\" to block plugin-based content (Flash, Java applets, etc.).",
      reference: REFERENCE,
    });
  }

  // -------------------------------------------------------------------------
  // CSP-007 — base-uri absent.
  // -------------------------------------------------------------------------
  if (!directives.has('base-uri')) {
    findings.push({
      ruleId: 'CSP-007',
      category: 'header',
      severity: 'low',
      title: "CSP is missing the 'base-uri' directive",
      impact:
        'An attacker injecting a <base> tag can redirect all relative script, image, and form action URLs to an external phishing/exfiltration server.',
      evidence: sanitizeEvidence(cspValue),
      recommendation:
        "Add \"base-uri 'none'\" (or \"'self'\") to prevent base-tag injection attacks.",
      reference: REFERENCE,
    });
  }


  // -------------------------------------------------------------------------
  // Deep CSP Evaluator integration
  // -------------------------------------------------------------------------
  try {
    const parsed = new CspParser(cspValue).csp;
    const evaluator = new CspEvaluator(parsed);
    const evalFindings = evaluator.evaluate();

    const existingRules = new Set(findings.map(f => f.ruleId));

    for (const f of evalFindings) {
      if (f.severity === Severity.STRICT_CSP || f.severity === Severity.NONE) continue;
      
      if (f.type === Type.STYLE_UNSAFE_INLINE) {
        if (!existingRules.has('CSP-002S')) {
          findings.push({
            ruleId: 'CSP-002S',
            category: 'header',
            severity: 'low',
            title: "CSP style-src contains 'unsafe-inline'",
            impact: 'Allows injection of malicious CSS which can exfiltrate data via attribute selectors or deface the site.',
            evidence: sanitizeEvidence(`${f.directive}: ${f.value || ''}`),
            recommendation: 'Remove unsafe-inline from style-src and use external stylesheets or nonces/hashes for inline styles.',
            reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/style-src'
          });
          existingRules.add('CSP-002S');
        }
      } else if (f.severity === Severity.SYNTAX || f.type === Type.NONCE_CHARSET || f.type === Type.NONCE_LENGTH || f.type === Type.STATIC_NONCE || f.type === Type.MISSING_SEMICOLON || f.type === Type.UNKNOWN_DIRECTIVE || f.type === Type.INVALID_KEYWORD) {
        findings.push({
          ruleId: 'CSP-SYNTAX-001',
          category: 'header',
          severity: 'info',
          title: 'CSP Syntax or Nonce Issue',
          impact: f.description,
          evidence: sanitizeEvidence(`${f.directive}: ${f.value || ''}`),
          recommendation: 'Review CSP syntax.',
          reference: 'https://csp-evaluator.withgoogle.com/'
        });
      }
    }
  } catch (e) {
    // Ignore parser errors
  }

  return { findings, directives };

}
