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
 *
 * Returns both findings and the parsed directive map so other rules
 * (e.g. XFO) can inspect directives without re-parsing.
 */

import type { Finding, Hop } from '../../shared/types';
import { sanitizeEvidence, parseCspDirectives, hasCspBypassProtection } from '../utils';

const REFERENCE =
  'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy';

const CSP_HEADER = 'content-security-policy';

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
export function checkCsp(finalHop: Hop): CspResult {
  const findings: Finding[] = [];
  const cspValue = finalHop.headers[CSP_HEADER];

  // CSP-001 — header absent entirely.
  if (cspValue === undefined) {
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
    // Without a CSP there is nothing more to parse.
    return { findings, directives: new Map() };
  }

  // Parse the header value into a directive map.
  const directives = parseCspDirectives(cspValue);

  // -------------------------------------------------------------------------
  // Script-src checks (falls back to default-src)
  // -------------------------------------------------------------------------
  const effectiveScriptSrc = resolveEffective(directives, 'script-src');

  if (effectiveScriptSrc !== undefined) {
    const { isModernStrict } = hasCspBypassProtection(effectiveScriptSrc);

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

  return { findings, directives };
}
