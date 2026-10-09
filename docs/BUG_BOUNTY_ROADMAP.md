# ACULYX — High-Confidence Bug-Bounty Scanner Roadmap

**Prepared**: 2026-10-08
**Project baseline inspected**: repository at `86160ac`
**Purpose**: Improve ACULYX into a precise, smooth, evidence-first scanner for authorized bug-bounty work.

---

## North Star

Make ACULYX the scanner a researcher trusts: it observes the browser’s real responses, stays inside declared scope, shows exactly what it saw, and reports a security issue only when the evidence and rule applicability justify it.

The quality target is **zero known false-positive confirmed findings**. No scanner can honestly guarantee zero mistakes across every site and configuration. ACULYX avoids misleading researchers by strictly separating confirmed observations from uncertain leads: if the rule cannot establish its conditions, it returns `Not observed`, `Partial coverage`, or `Needs manual verification` — never a definitive vulnerability claim.

---

## Product Principles

1. **Evidence before severity**: Every finding must identify its source, the observed condition, the applicable rule, and what the evidence does not prove.
2. **Conservative by default**: Missing coverage, ambiguous browser behavior, unsupported contexts, or heuristic-only signals must never be presented as a confirmed vulnerability.
3. **Scope is explicit**: Unknown scope is not authorization. A redirect, third-party service, or related subdomain is not automatically in scope.
4. **Local-first and privacy-preserving**: Preserve existing design: no cookie values, tokens, or unnecessary URL details in stored or exported findings; do not send browsing data elsewhere.
5. **Fast and integrated**: Keep capture callbacks lightweight; use bounded, coalesced processing and one consistent rule pipeline. A scanner outage or unsupported site must not freeze the popup or browser.
6. **Human-reviewed reporting**: ACULYX prepares evidence and drafts; the researcher decides whether an issue is valid and suitable for submission.

---

## Build Sequence

### Phase 1 — Make the Scanner Trustworthy Before Adding More Checks
Use the current capture and rules architecture rather than replacing it wholesale. Trace one captured response through the full pipeline — capture, normalization, secret redaction, rule evaluation, deduplication, scoring, persistence, and display — and ensure every stage preserves provenance and privacy.

**Priorities**:
- Preserve incognito/private-window isolation, URL and secret redaction, settings correctness, retention, and permission semantics.
- Ensure a restricted URL, cache response, service-worker response, missing capture, or partial redirect chain cannot produce a reassuring grade or an unjustifiably certain warning.
- Keep browser event handlers fast and non-blocking. Avoid adding work per network request; coalesce DOM signals and recompute a tab once for a batch of related events.
- Bound per-tab queues, endpoint maps, history, and finding counts. Make cancellation and tab/navigation generations continue to prevent stale results from replacing current-page findings.
- Establish finding identity and deduplication using stable rule ID plus normalized origin and relevant non-sensitive evidence — not raw URLs, secrets, or timestamps.

**Deliverable**: A stable, privacy-preserving scanner pipeline with clear coverage and no duplicate finding spam.

---

### Phase 2 — Add Explicit Program-Scope Control
Create local Program Scope profiles before offering any active validation.

Each profile should support:
- Name
- Exact domains
- Explicitly defined wildcard rules (`*.example.com`)
- Exclusions
- Notes
- Last-reviewed date

Show one of three states for the current host and each finding:
- **`In scope`**
- **`Out of scope`**
- **`Unknown`**

The matcher must:
- Treat apex and subdomains deliberately, respect public-suffix boundaries, normalize case/IDNA/trailing dots, and handle ports consistently.
- A rule for `*.example.org` must not silently imply the apex unless the profile says so.
- Exclusions take priority over broad includes.
- Redirect destinations and third-party services are checked independently; a site’s payment processor, CDN, identity provider, or API vendor is not presumed authorized because the referring page is in scope.
- Keep scope profiles local. Unknown scope must block any future active validation and remain clearly visible in passive findings.

**Deliverable**: Reliable scope status with comprehensive tests for wildcard, exclusion, redirect, third-party, apex/subdomain, IDNA, and boundary cases.

---

### Phase 3 — Improve High-Value Passive Detection
Add or refine rules only where ACULYX can observe enough evidence in the current browser workflow. Prioritize checks reproducible from actual captured responses and explain the limits of that evidence.

**Candidate areas, in order**:
1. **Headers and browser policies**: CSP directives and weaknesses, HSTS applicability, framing policy, referrer policy, permissions policy, MIME-sniffing protection, and redirect-hop changes.
2. **Cookies**: Secure, HttpOnly, SameSite, prefixes (`__Host-`, `__Secure-`), path/domain scope, partitioning, persistence, and evidence provenance. Never read, persist, display, or export cookie values.
3. **CORS**: Normalize `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, preflight/response context, wildcard and null behavior, and missing coverage. Do not claim exploitability from a header string alone when actual request context is unknown.
4. **Caching**: Flag potentially sensitive responses only when ACULYX has sufficient evidence to identify the response context. Distinguish a policy concern from proof of shared-cache disclosure.
5. **Redirects and transport**: Report observed downgrade or security-header loss across captured hops; state when browser-internal HSTS, cache, service-worker behavior, or incomplete coverage prevents a conclusion.
6. **Page signals**: Mixed content and Subresource Integrity gaps can be useful leads. Source-map exposure or postMessage patterns remain informational unless concrete, reproducible evidence establishes a security impact.

---

### Phase 4 — Evidence and Reporting Workflow
Give every finding a details view and a local report workflow. A researcher should be able to see:
- Stable rule ID, title, category, severity, and whether the rule is deterministic or heuristic.
- Affected origin and only the minimum sanitized path needed to reproduce the observation.
- Timestamp, response/redirect/DOM provenance, ruleset version, and captured evidence.
- Expected versus observed condition, likely impact, recommendation, and canonical reference.
- Coverage gaps and an explicit statement of what the observation does not prove.
- Researcher review state: `unreviewed`, `needs-manual-verification`, `verified-by-researcher`, `not-reproducible`, or `not-a-finding`.

Keep source observations separate from researcher notes. Provide basic local Markdown and JSON report drafts first. Reports should include reproduction steps, preconditions, expected/observed behavior, impact, evidence, remediation, and a scope note. Redact sensitive data before display and export.

**Deliverable**: Reproducible, editable, privacy-safe reports that do not turn a configuration observation into an unsupported exploit claim.

---

### Phase 5 — Add Carefully Bounded Active Validation Only After Scope
Active validation is separate from passive scanning and must be opt-in per action. It must never run automatically during browsing.

- Show the target, exact test/request, expected side effects, and a clear Start/Cancel choice before execution.
- Permit it only when the exact target is `In scope`; deny `Out of scope` and `Unknown`.
- Include conservative rate and concurrency limits, progress, stop/cancel controls, and a clear record of sent requests.
- Keep tests non-destructive and read-only. No credential attacks, destructive writes, stealth/evasion, high-volume fuzzing, or automatic exploitation.

---

### Phase 6 — Optional Local CLI After Browser Workflows Are Proven
A CLI may help with repeatable authorized checks, local scope profiles, report formatting, and CI severity thresholds. Keep it separate from the extension’s capture code and make every network action explicit.

---

## How to Add a New Rule Safely

1. **State a narrow security claim**: One sentence describing the specific condition. Identify what consequence is possible and what additional evidence would be required to claim exploitability.
2. **Use an authoritative basis**: Link exact relevant specification, browser documentation, or recognized security guidance.
3. **Define applicability before implementation**: Specify inputs, resource types, schemes, origins, capture points, and conditions that make the rule `not-applicable`, `not-observed`, or `partial-coverage`.
4. **Implement a pure, small rule**: Put under `src/rules/`. Pure functions: normalized evidence in, finding or explicit no-finding outcome out. No network or DOM calls inside rules.
5. **Add positive, negative, and boundary tests together**: Test canonical positive, secure/safe configuration, non-applicable context, missing/incomplete capture, syntax variations, and malformed inputs.
6. **Evaluate before enabling by default**: Test on curated known-safe and known-affected sets. If a safe case alerts, narrow conditions or classify as an informational lead.
7. **Integrate and document**: Register once in the pipeline, update documentation, and verify popup, side panel, history, export, and CLI behavior.

---

## Release Bar: "God-Tier" Means Dependable, Not Noisy

- No rule with a known safe-case alert is labeled as a confirmed finding.
- Every confirmed finding has a rule ID, evidence, provenance, applicability, and an honest statement of limitations.
- Uncertain conditions are represented as partial coverage or a lead requiring verification — not a definitive vulnerability.
- Scope status is correct for apexes, subdomains, wildcard inclusions, exclusions, redirects, and third parties; unknown status never authorizes active validation.
- Captured/exported data has no cookie values, credentials, tokens, or unnecessary query strings.
- Passive scanning has no avoidable blocking or unbounded per-request work; UI remains responsive under many findings and tabs.
- Chrome and Firefox behavior is covered, including private-window isolation, service-worker restart, cache/service-worker coverage, and permission transitions.
- Researcher reports can be edited and exported locally without losing evidence provenance or overstating impact.
- Combined quality gates pass and release notes state scanner limitations.
