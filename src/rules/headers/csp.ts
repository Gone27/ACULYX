/** Content-Security-Policy Rule with Bounded Precision & Caveats. */

import type { Finding, Hop } from '../../shared/types';
import { sanitizeEvidence, parseCspDirectives, hasCspBypassProtection } from '../utils';
import { URLS as JSONP_BYPASS_URLS } from 'csp_evaluator/dist/allowlist_bypasses/jsonp';
import { CspEvaluator } from 'csp_evaluator/dist/evaluator';
import { CspParser } from 'csp_evaluator/dist/parser';
import { Type, Severity } from 'csp_evaluator/dist/finding';

const REFERENCE =
  'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy';
const CSP_HEADER = 'content-security-policy';

const CSP_BYPASS_HOSTS: ReadonlySet<string> = new Set(
  JSONP_BYPASS_URLS.map((url) => {
    const stripped = url.replace(/^(https?:)?\/\//, '');
    return (stripped.split('/')[0] ?? '').toLowerCase();
  }).filter((host) => host.length > 0),
);

function resolveEffective(directives: Map<string, string>, directive: string): string | undefined {
  return directives.get(directive) ?? directives.get('default-src');
}

function sourceTokens(sourceList: string): string[] {
  return sourceList.split(/\s+/).filter((t) => t.length > 0);
}

function hasWildcardSource(sourceList: string, hasStrictDynamic: boolean): boolean {
  if (hasStrictDynamic) return false;
  const tokens = sourceTokens(sourceList);
  return tokens.some((token) => token === '*' || token === 'http:' || token === 'https:');
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

export interface CspResult {
  findings: Finding[];
  directives: Map<string, string>;
}

export function checkCsp(finalHop: Hop, metaCspFound = false): CspResult {
  const findings: Finding[] = [];
  const cspValue = finalHop.headers[CSP_HEADER];
  const fromCache = finalHop.fromCache === true;

  if (cspValue === undefined) {
    const reportOnlyValue = finalHop.headers['content-security-policy-report-only'];
    if (metaCspFound) {
      findings.push({
        ruleId: 'CSP-008',
        category: 'header',
        severity: 'info',
        confidence: 'heuristic',
        provenance: 'dom-signal',
        outcome: 'pass',
        title: 'CSP detected in a meta tag; policy details are not evaluated',
        impact:
          'A meta CSP can enforce some policy directives, but cannot replace response-header protections such as frame-ancestors and may take effect later in document parsing.',
        evidence: sanitizeEvidence('<meta http-equiv="Content-Security-Policy">'),
        recommendation:
          'Also send Content-Security-Policy as an HTTP response header for complete coverage. This report does not assess the meta policy contents.',
        reference: REFERENCE,
        limitations: ['Meta tag CSP detected via DOM signal; HTTP response header remains authoritative.'],
      });
    } else if (reportOnlyValue !== undefined) {
      findings.push({
        ruleId: 'CSP-001',
        category: 'header',
        severity: 'high',
        confidence: 'deterministic',
        provenance: 'response-header',
        outcome: fromCache ? 'partial-coverage' : 'fail',
        title: 'Only Content-Security-Policy-Report-Only is present; no enforcing CSP is configured',
        impact: 'Report-Only policies observe violations but do not block unsafe content.',
        evidence: sanitizeEvidence(reportOnlyValue),
        recommendation:
          'After validating reports, deploy the intended policy as Content-Security-Policy. Keep Report-Only separately if continued monitoring is desired.',
        reference: REFERENCE,
        limitations: fromCache ? ['Response served from cache; report-only status unverified on live hit.'] : [],
      });
    } else {
      findings.push({
        ruleId: 'CSP-001',
        category: 'header',
        severity: 'high',
        confidence: 'deterministic',
        provenance: 'response-header',
        outcome: fromCache ? 'partial-coverage' : 'fail',
        title: 'Content-Security-Policy header is missing',
        impact: 'Without a CSP, XSS vulnerabilities can execute malicious scripts.',
        evidence: sanitizeEvidence('(header absent)'),
        recommendation:
          'Add a Content-Security-Policy header. Start with a strict base policy ' +
          "such as \"default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'\".",
        reference: REFERENCE,
        limitations: fromCache
          ? ['Response served from browser cache; header presence cannot be confirmed without live network hit.']
          : ['Passive header analysis; no active script injection tested.'],
      });
    }
    return { findings, directives: new Map() };
  }

  const directives = parseCspDirectives(cspValue);

  if (!directives.has('default-src') && !directives.has('script-src')) {
    findings.push({
      ruleId: 'CSP-010',
      category: 'header',
      severity: 'info',
      confidence: 'deterministic',
      provenance: 'response-header',
      outcome: 'pass',
      title: 'CSP has no default-src or script-src fallback',
      impact: 'The policy does not establish a general resource fallback.',
      evidence: sanitizeEvidence(cspValue),
      recommendation: "Add default-src as a baseline and define script-src explicitly where script loading needs a different policy.",
      reference: REFERENCE,
      limitations: ['Informational configuration observation.'],
    });
  }

  const effectiveScriptSrc = resolveEffective(directives, 'script-src');

  if (effectiveScriptSrc !== undefined) {
    const { isModernStrict, hasStrictDynamic } = hasCspBypassProtection(effectiveScriptSrc);
    const bypassProneHosts = hasStrictDynamic ? [] : findBypassProneHosts(effectiveScriptSrc);

    if (bypassProneHosts.length > 0) {
      findings.push({
        ruleId: 'CSP-009',
        category: 'header',
        severity: 'info',
        confidence: 'heuristic',
        provenance: 'response-header',
        outcome: 'pass',
        title: 'CSP script-src trusts host(s) with historically bypass-prone endpoints or libraries',
        impact:
          'Some allowlisted hosts expose JSONP endpoints or host libraries with script gadgets; actual exploitability depends on endpoint path and version.',
        evidence: sanitizeEvidence(bypassProneHosts.join(', ')),
        recommendation:
          'Review whether each host is required, restrict paths where practical, pin library versions, and prefer nonces or hashes. This curated host match is a heuristic, not proof of a bypass.',
        reference: 'https://csp-evaluator.withgoogle.com/',
        limitations: ['Passive heuristic analysis only; presence of domain does not verify an active JSONP or gadget endpoint.'],
      });
    }

    if (effectiveScriptSrc.includes("'unsafe-inline'")) {
      if (isModernStrict) {
        findings.push({
          ruleId: 'CSP-002',
          category: 'header',
          severity: 'info',
          confidence: 'deterministic',
          provenance: 'response-header',
          outcome: 'pass',
          title: "CSP script-src includes 'unsafe-inline' as a legacy fallback (safely ignored due to nonce/strict-dynamic)",
          impact: 'Modern browsers safely ignore this fallback because a nonce or strict-dynamic is present.',
          evidence: sanitizeEvidence(effectiveScriptSrc),
          recommendation: "No action needed for modern browsers.",
          reference: REFERENCE,
          limitations: ['Level 3 CSP browsers ignore unsafe-inline when nonces or strict-dynamic are present.'],
        });
      } else {
        findings.push({
          ruleId: 'CSP-002',
          category: 'header',
          severity: 'high',
          confidence: 'deterministic',
          provenance: 'response-header',
          outcome: fromCache ? 'partial-coverage' : 'fail',
          title: "CSP script-src contains 'unsafe-inline'",
          impact: 'Injected HTML tags can execute arbitrary JavaScript directly inside victim browsers.',
          evidence: sanitizeEvidence(effectiveScriptSrc),
          recommendation: "Remove 'unsafe-inline' and use nonces or hashes.",
          reference: REFERENCE,
          limitations: fromCache ? ['Response served from cache.'] : ['Passive policy inspection.'],
        });
      }
    }

    if (effectiveScriptSrc.includes("'unsafe-eval'")) {
      findings.push({
        ruleId: 'CSP-003',
        category: 'header',
        severity: 'high',
        confidence: 'deterministic',
        provenance: 'response-header',
        outcome: fromCache ? 'partial-coverage' : 'fail',
        title: "CSP script-src contains 'unsafe-eval'",
        impact: 'Allows dynamic code execution via eval() and new Function().',
        evidence: sanitizeEvidence(effectiveScriptSrc),
        recommendation: "Remove 'unsafe-eval'.",
        reference: REFERENCE,
        limitations: fromCache ? ['Response served from cache.'] : ['Passive policy inspection.'],
      });
    }

    if (hasWildcardSource(effectiveScriptSrc, hasStrictDynamic)) {
      findings.push({
        ruleId: 'CSP-004',
        category: 'header',
        severity: 'medium',
        confidence: 'deterministic',
        provenance: 'response-header',
        outcome: fromCache ? 'partial-coverage' : 'fail',
        title: 'CSP script-src contains an overly broad wildcard or scheme-only source',
        impact: 'Open wildcard sources allow scripts to be loaded from any external host.',
        evidence: sanitizeEvidence(effectiveScriptSrc),
        recommendation: 'Replace wildcard sources with explicit hostnames.',
        reference: REFERENCE,
        limitations: fromCache ? ['Response served from cache.'] : ['Passive policy inspection.'],
      });
    }
  }

  if (!directives.has('frame-ancestors')) {
    const xfo = finalHop.headers['x-frame-options']?.trim().toUpperCase();
    const hasValidXfo = xfo === 'DENY' || xfo === 'SAMEORIGIN';

    findings.push({
      ruleId: 'CSP-005',
      category: 'header',
      severity: hasValidXfo ? 'info' : 'medium',
      confidence: 'deterministic',
      provenance: 'response-header',
      outcome: hasValidXfo ? 'pass' : (fromCache ? 'partial-coverage' : 'fail'),
      title: hasValidXfo
        ? "CSP is missing 'frame-ancestors' (mitigated by X-Frame-Options)"
        : "CSP is missing the 'frame-ancestors' directive",
      impact: hasValidXfo
        ? 'Protected by X-Frame-Options in modern browsers.'
        : 'Malicious websites can embed your site in an iframe for Clickjacking.',
      evidence: sanitizeEvidence(cspValue),
      recommendation: "Add \"frame-ancestors 'none'\" (or 'self').",
      reference: REFERENCE,
      limitations: hasValidXfo ? ['XFO mitigation confirmed.'] : [],
    });
  }

  const effectiveObjectSrc = resolveEffective(directives, 'object-src');
  if (effectiveObjectSrc === undefined || !sourceTokens(effectiveObjectSrc).includes("'none'")) {
    findings.push({
      ruleId: 'CSP-006',
      category: 'header',
      severity: 'medium',
      confidence: 'deterministic',
      provenance: 'response-header',
      outcome: fromCache ? 'partial-coverage' : 'fail',
      title: "CSP object-src is absent or not restricted to 'none'",
      impact: 'Allows plugins to load untrusted resources.',
      evidence: sanitizeEvidence(effectiveObjectSrc ?? '(directive absent)'),
      recommendation: "Add \"object-src 'none'\".",
      reference: REFERENCE,
      limitations: fromCache ? ['Response served from cache.'] : [],
    });
  }

  if (!directives.has('base-uri')) {
    findings.push({
      ruleId: 'CSP-007',
      category: 'header',
      severity: 'low',
      confidence: 'deterministic',
      provenance: 'response-header',
      outcome: fromCache ? 'partial-coverage' : 'fail',
      title: "CSP is missing the 'base-uri' directive",
      impact: 'An attacker injecting a <base> tag can hijack relative URLs.',
      evidence: sanitizeEvidence(cspValue),
      recommendation: "Add \"base-uri 'none'\".",
      reference: REFERENCE,
      limitations: fromCache ? ['Response served from cache.'] : [],
    });
  }

  try {
    const parsed = new CspParser(cspValue).csp;
    const evaluator = new CspEvaluator(parsed);
    const evalFindings = evaluator.evaluate();
    const existingRules = new Set(findings.map((f) => f.ruleId));

    for (const f of evalFindings) {
      if (f.severity === Severity.STRICT_CSP || f.severity === Severity.NONE) continue;

      if (f.type === Type.STYLE_UNSAFE_INLINE) {
        if (!existingRules.has('CSP-002S')) {
          findings.push({
            ruleId: 'CSP-002S',
            category: 'header',
            severity: 'low',
            confidence: 'deterministic',
            provenance: 'response-header',
            outcome: fromCache ? 'partial-coverage' : 'fail',
            title: "CSP style-src contains 'unsafe-inline'",
            impact: 'Allows injection of malicious CSS which can exfiltrate data via attribute selectors or deface the site.',
            evidence: sanitizeEvidence(`${f.directive}: ${f.value ?? ''}`),
            recommendation: 'Remove unsafe-inline from style-src and use external stylesheets or nonces/hashes for inline styles.',
            reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/style-src',
            limitations: ['Passive analysis.'],
          });
          existingRules.add('CSP-002S');
        }
      } else if (f.type === Type.SCRIPT_ALLOWLIST_BYPASS || f.type === Type.OBJECT_ALLOWLIST_BYPASS) {
        if (f.value !== "'self'" && !existingRules.has('CSP-009')) {
          findings.push({
            ruleId: 'CSP-009',
            category: 'header',
            severity: 'info',
            confidence: 'heuristic',
            provenance: 'response-header',
            outcome: 'pass',
            title: 'CSP allowlist bypass or structural weakness',
            impact: f.description,
            evidence: sanitizeEvidence(`${f.directive}: ${f.value ?? ''}`),
            recommendation: 'Remove the bypass host or use strict-dynamic / nonces instead of an allowlist.',
            reference: 'https://csp-evaluator.withgoogle.com/',
            limitations: ['Passive heuristic analysis only.'],
          });
          existingRules.add('CSP-009');
        }
      } else if (
        (f.severity === Severity.SYNTAX ||
          f.type === Type.NONCE_CHARSET ||
          f.type === Type.NONCE_LENGTH ||
          f.type === Type.STATIC_NONCE ||
          f.type === Type.MISSING_SEMICOLON ||
          f.type === Type.UNKNOWN_DIRECTIVE ||
          f.type === Type.INVALID_KEYWORD) &&
        !existingRules.has('CSP-SYNTAX-001')
      ) {
        findings.push({
          ruleId: 'CSP-SYNTAX-001',
          category: 'header',
          severity: 'info',
          confidence: 'deterministic',
          provenance: 'response-header',
          outcome: 'pass',
          title: 'CSP Syntax or Nonce Issue',
          impact: f.description,
          evidence: sanitizeEvidence(`${f.directive}: ${f.value ?? ''}`),
          recommendation: 'Review CSP syntax.',
          reference: 'https://csp-evaluator.withgoogle.com/',
          limitations: ['Informational syntax issue.'],
        });
        existingRules.add('CSP-SYNTAX-001');
      }
    }
  } catch {
    // Ignore parser errors — a malformed CSP is already flagged by our own checks above.
  }

  return { findings, directives };
}
