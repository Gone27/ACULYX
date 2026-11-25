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

const NONCE_OR_HASH_RE = /'(?:nonce-[a-z0-9+/=_-]+|sha(?:256|384|512)-[a-z0-9+/=_-]+)'/i;

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

function checkSinglePolicy(finalHop: Hop, metaCspFound = false): CspResult {
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
    const scriptLc = effectiveScriptSrc.toLowerCase(); // CSP keywords are ASCII case-insensitive
    const { isModernStrict, hasStrictDynamic } = hasCspBypassProtection(scriptLc);
    const bypassProneHosts = hasStrictDynamic ? [] : findBypassProneHosts(effectiveScriptSrc);

    if (bypassProneHosts.length > 0) {
      findings.push({
        ruleId: 'CSP-009',
        category: 'header',
        severity: 'info',
        confidence: 'heuristic',
        provenance: 'response-header',
        outcome: 'pass',
        title: 'CSP script-src trusts third-party host(s) with historically bypass-prone endpoints or libraries',
        impact:
          'Observed configuration: allowlisted host(s) appear in a curated list of domains that have historically hosted JSONP/script-gadget endpoints; actual bypass risk depends on hosted paths and versions.',
        evidence: sanitizeEvidence(bypassProneHosts.join(', ')),
        recommendation:
          'Next check: verify whether the allowlisted host exposes JSONP callbacks or outdated script libraries, restrict paths where practical, or migrate to nonces/hashes with strict-dynamic.',
        reference: 'https://csp-evaluator.withgoogle.com/',
        limitations: ['Passive heuristic match on domain name only; does not prove an active JSONP or script-gadget bypass exists.'],
      });
    }

    // Check for 'data:' scheme in script-src
    const tokens = sourceTokens(effectiveScriptSrc);
    if (tokens.includes('data:') || tokens.includes('data;')) {
      findings.push({
        ruleId: 'CSP-004D',
        category: 'header',
        severity: 'medium',
        confidence: 'deterministic',
        provenance: 'response-header',
        outcome: fromCache ? 'partial-coverage' : 'fail',
        title: "CSP script-src contains 'data:' scheme source",
        impact: "The 'data:' scheme allows arbitrary script execution via data URIs, completely undermining CSP script execution controls.",
        evidence: sanitizeEvidence(effectiveScriptSrc),
        recommendation: "Remove 'data:' from script-src and default-src directives.",
        reference: REFERENCE,
        limitations: fromCache ? ['Response served from cache.'] : ['Passive policy inspection.'],
      });
    }

    // Check for short or predictable nonces (< 16 chars)
    const nonceMatches = effectiveScriptSrc.match(/'nonce-([A-Za-z0-9+/=_-]+)'/gi);
    if (nonceMatches) {
      for (const nm of nonceMatches) {
        const nonceVal = nm.replace(/^'nonce-|'$/gi, '');
        if (nonceVal.length < 16) {
          findings.push({
            ruleId: 'CSP-NONCE-001',
            category: 'header',
            severity: 'medium',
            confidence: 'deterministic',
            provenance: 'response-header',
            outcome: fromCache ? 'partial-coverage' : 'fail',
            title: 'CSP script-src nonce is too short / predictable',
            impact: 'A nonce with insufficient entropy (< 128 bits / 16 chars) can be brute-forced or guessed by an attacker to execute unauthorized scripts.',
            evidence: sanitizeEvidence(`nonce length: ${nonceVal.length}`),
            recommendation: 'Generate cryptographically random nonces with at least 128 bits of entropy (e.g. 16+ base64 characters).',
            reference: REFERENCE,
            limitations: ['Passive header inspection.'],
          });
          break;
        }
      }
    }

    if (scriptLc.includes("'unsafe-inline'")) {
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
          severity: 'medium',
          confidence: 'deterministic',
          provenance: 'response-header',
          outcome: fromCache ? 'partial-coverage' : 'fail',
          title: "CSP script-src permits 'unsafe-inline' without nonce/hash protection",
          impact:
            "Observed configuration permits inline script execution, weakening XSS defense-in-depth if an HTML or DOM injection sink is present; exploitability depends on application execution paths.",
          evidence: sanitizeEvidence(effectiveScriptSrc),
          recommendation:
            "Remove 'unsafe-inline' and adopt cryptographic nonces or hashes. Next check: inspect application markup and DOM sinks for unescaped user input.",
          reference: REFERENCE,
          limitations: fromCache
            ? ['Response served from cache.', 'Observed CSP configuration only; passive analysis does not prove an injectable XSS sink.']
            : ['Observed CSP configuration only; passive inspection does not prove an HTML or DOM injection vulnerability exists.'],
        });
      }
    }

    if (scriptLc.includes("'unsafe-eval'")) {
      findings.push({
        ruleId: 'CSP-003',
        category: 'header',
        severity: 'medium',
        confidence: 'heuristic',
        provenance: 'response-header',
        outcome: fromCache ? 'partial-coverage' : 'fail',
        title: "CSP script-src permits 'unsafe-eval' (weakens dynamic evaluation restriction)",
        impact:
          'Observed configuration allows eval() and Function() string evaluation. This increases XSS impact only if application code passes untrusted input into a dynamic evaluation sink.',
        evidence: sanitizeEvidence(effectiveScriptSrc),
        recommendation:
          "Remove 'unsafe-eval' where scripts do not require dynamic evaluation. Next check: audit JavaScript execution paths for eval-like sinks reachable by user input.",
        reference: REFERENCE,
        limitations: fromCache
          ? ['Response served from cache.', 'Observed policy directive only; does not prove eval() or an attacker-controlled sink is used.']
          : ['Observed policy directive only; does not prove eval() usage or an exploitable injection path exists.'],
      });
    }

    if (hasWildcardSource(scriptLc, hasStrictDynamic)) {
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

  // --- Review additions: gaps that produced false negatives -------------------------------
  const mk = (ruleId: string, severity: Finding['severity'], title: string, impact: string, evidence: string, recommendation: string): Finding => ({
    ruleId, category: 'header', severity, confidence: 'deterministic', provenance: 'response-header',
    outcome: fromCache ? 'partial-coverage' : 'fail', title, impact,
    evidence: sanitizeEvidence(evidence), recommendation, reference: REFERENCE,
    limitations: fromCache ? ['Response served from cache.'] : ['Passive policy inspection.'],
  });

  const scriptEffective = resolveEffective(directives, 'script-src')?.toLowerCase();
  if (scriptEffective !== undefined) {
    const t = sourceTokens(scriptEffective);
    const strictDyn = t.includes("'strict-dynamic'");
    if (t.includes('blob:') && !strictDyn) {
      findings.push(mk('CSP-004B', 'low', "CSP script-src allows 'blob:' sources",
        'Attacker-controlled Blob URLs (for example created from injected data) can be executed as scripts, weakening the allowlist.',
        scriptEffective, "Remove 'blob:' from script-src unless a Worker/Blob design strictly requires it."));
    }
    if (t.includes("'unsafe-hashes'")) {
      findings.push(mk('CSP-004H', 'low', "CSP script-src uses 'unsafe-hashes'",
        'Allows hashed inline event handlers (onclick=...), re-enabling the inline-handler injection surface for any matching hash.',
        scriptEffective, "Refactor inline handlers to addEventListener and drop 'unsafe-hashes'."));
    }
  }

  // script-src-elem / script-src-attr override script-src for <script> elements and inline handlers.
  for (const name of ['script-src-elem', 'script-src-attr'] as const) {
    const v = directives.get(name)?.toLowerCase();
    if (v === undefined) continue;
    const t = sourceTokens(v);
    const nonceOrHash = NONCE_OR_HASH_RE.test(v) || t.includes("'strict-dynamic'");
    if (t.includes("'unsafe-inline'") && !(name === 'script-src-elem' && nonceOrHash)) {
      findings.push(mk(name === 'script-src-elem' ? 'CSP-002E' : 'CSP-002A', 'medium',
        `CSP ${name} permits 'unsafe-inline' (overrides script-src)`,
        'Observed directive takes precedence over script-src for its target, weakening inline-script protection if an injection sink is present; passive header evidence does not prove exploitability.',
        `${name} ${v}`, `Remove 'unsafe-inline' from ${name} and adopt nonces/hashes. Next check: verify whether user input reaches inline ${name} contexts.`));
    }
    if (name === 'script-src-elem' && !t.includes("'strict-dynamic'") &&
        t.some((x) => x === '*' || x === 'http:' || x === 'https:' || x === 'data:' || x === 'blob:')) {
      findings.push(mk('CSP-004E', 'medium', 'CSP script-src-elem allows wildcard or scheme-only sources',
        'script-src-elem overrides script-src for <script> elements, so a broad source here lets scripts load from arbitrary hosts.',
        `${name} ${v}`, 'Replace wildcard/scheme sources with explicit hosts or nonces.'));
    }
  }

  // frame-ancestors that allows everything gives no clickjacking protection, and browsers then
  // IGNORE X-Frame-Options, so it is worse than having no frame-ancestors at all.
  const fa = directives.get('frame-ancestors');
  if (fa !== undefined) {
    const ft = sourceTokens(fa.toLowerCase());
    if (ft.some((x) => x === '*' || x === 'https:' || x === 'http:' || x === 'data:')) {
      findings.push(mk('CSP-005W', 'medium', "CSP frame-ancestors allows any origin to embed this page",
        'Any site can frame this page, and because frame-ancestors is present browsers ignore X-Frame-Options, so clickjacking protection is effectively absent.',
        `frame-ancestors ${fa}`, "Use frame-ancestors 'none' or 'self' (or an explicit allowlist)."));
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

// ─── Multiple enforced policies ───────────────────────────────────────────────

/** Browsers enforce EVERY Content-Security-Policy header (and every comma-separated policy). */
function collectEnforcedPolicies(hop: Hop): string[] {
  const raw = (hop.rawHeaders ?? [])
    .filter((h) => h.name.toLowerCase() === CSP_HEADER)
    .map((h) => h.value);
  const values = raw.length > 0 ? raw : (hop.headers[CSP_HEADER] !== undefined ? [hop.headers[CSP_HEADER]] : []);
  return values.flatMap((v) => v.split(',')).map((v) => v.trim()).filter((v) => v.length > 0);
}

/**
 * Evaluate the response's CSP. When several policies are enforced (CDN + origin is common) the
 * effective policy is their intersection, so a weakness is only real if EVERY policy has it.
 * The previous "last header wins" behaviour reported the wrong policy in both directions.
 */
export function checkCsp(finalHop: Hop, metaCspFound = false): CspResult {
  const policies = collectEnforcedPolicies(finalHop);
  if (policies.length <= 1) return checkSinglePolicy(finalHop, metaCspFound);

  const results = policies.map((policy) =>
    checkSinglePolicy({ ...finalHop, headers: { ...finalHop.headers, [CSP_HEADER]: policy } }, metaCspFound));

  const first = results[0] as CspResult;
  const inAll = (ruleId: string): boolean => results.every((r) => r.findings.some((f) => f.ruleId === ruleId));
  const findings = first.findings.filter((f) => inAll(f.ruleId));

  const directives = new Map<string, string>();
  for (const r of results) for (const [k, v] of r.directives) if (!directives.has(k)) directives.set(k, v);

  findings.push({
    ruleId: 'CSP-011',
    category: 'header',
    severity: 'info',
    confidence: 'deterministic',
    provenance: 'response-header',
    outcome: 'pass',
    title: `${policies.length} Content-Security-Policy policies are enforced together`,
    impact: 'Browsers enforce all policies at once; the effective policy is the intersection, so weaknesses are only reported when every policy has them.',
    evidence: sanitizeEvidence(`${policies.length} policies`),
    recommendation: 'Confirm the layered policies are intentional (for example CDN plus origin) and that they do not contradict each other.',
    reference: REFERENCE,
    limitations: ['Per-policy results were intersected by rule id.'],
  });
  return { findings, directives };
}
