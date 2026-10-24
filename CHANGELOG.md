# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.3] - 2026-10-24

### Security & Accuracy
- **Zero-Trust Messaging Privacy Boundary Hardening (P0)**:
  - Eliminated raw page-derived input values (`sourceValue`) across the extension messaging boundary.
  - S3 main-world hooks now relay strictly category metadata (`sourceCategory`: `location.hash`, `location.search`, `document.referrer`, `window.name`, `window.postMessage`) without transmitting user-controlled strings to the background service worker.
  - Added comprehensive multi-source canary taint leak integration tests in `tests/leads/canary-leak.test.ts`.
- **F1 Generic Secret ReDoS Elimination (P1)**:
  - Replaced exponential-backtracking generic secret regex with a bounded linear-time two-stage matcher (`/[a-zA-Z0-9_$-]{1,64}/` key token capture followed by bounded keyword validation).
  - Added adversarial scaling benchmarks in `tests/leads/bounty-hardening.test.ts` verifying sub-second execution on 100 KB and 1 MB adversarial payloads.
- **SSRF DNS Rebinding Elimination (P1)**:
  - Implemented socket-level DNS connection pinning in CLI (`createPinnedLookup`).
  - Intercepts hostname resolution during TCP/TLS socket creation, verifying that every resolved IP is non-private and pinning the socket connection to the validated address.
  - Added unit test suite in `tests/cli.test.ts` verifying connection pinning and rejection of private IPs.
- **Action-Path IDOR Parameter Intelligence (P1)**:
  - Added action verb recognition (`/edit`, `/delete`, `/update`, `/modify`, `/download`, `/export`, etc.) to elevate IDOR potential on content routes.
  - Expanded private context recognition to plural entities (`users`, `accounts`, `profiles`, `members`, `customers`, `teams`, `orgs`, `invoices`, `subscriptions`).
  - Replaced silent IDOR lead drops on public content pages with low-noise whisper/info leads tagged `public-context`.
- **Dependency Advisory Mitigation (P1)**:
  - Pinned `body-parser` to secure patched versions (`>=1.20.3`) in `package.json` overrides.
- **COOK-004 Cross-Browser Accuracy (P2)**:
  - Updated rule finding text and recommendations to distinguish Chromium's Lax-by-default from Safari and default Firefox (which treat unlabelled cookies as `SameSite=None`), clarifying real-world CSRF exposure.
- **Release Packaging Hardening (P2)**:
  - Rewrote `scripts/pack-release.ps1` using .NET `ZipArchive` to strictly exclude development directories (`.agents`, `.system_generated`, `node_modules`, `.git`, `test-results`, `playwright-report`, `coverage`) and enforce standard RFC 1951 forward-slash entry paths.
- **Bug Bounty Tool Hardening & Noise Reduction**:
  - **Lead ID Collision Resistance**: Replaced monotonic module-level `leadCounter` across all F1–F8 detectors with collision-free `crypto.randomUUID()` identifiers that survive service worker idle/sleep cycles.
  - **Secrets Detector (F1) Noise Reduction & Entropy Validation**:
    - Implemented standalone non-production marker detection in `isPlaceholder` (`test`, `demo`, `fake`, `mock`, `staging`).
    - Separated Discord bot token detection with per-segment HMAC entropy checking (`>= 4.0`), eliminating false positives on arbitrary base64 strings.
    - Increased hard-coded Bearer token length threshold to 32+ characters and enforced Shannon entropy `>= 3.5`.
  - **Endpoint Detector (F2) Parameterized Template Literal Discovery**:
    - Added support for backtick template literal paths in network clients (`fetch`, `axios`, etc.), normalizing variable expressions `${...}` into `{param}` REST placeholders.
  - **Parameter Harvesting (F5) Fragment Routing**:
    - Added URL hash fragment query parameter extraction (`#redirect_uri=...`), capturing client-side SPA and OAuth flow parameters.
  - **Header Leaks (F6) Target Infrastructure Whitelist**:
    - Restricted `INF-001` internal RFC1918/hostname disclosure scanning to genuine backend disclosure headers (`x-backend-server`, `x-real-ip`, etc.), avoiding false positives from client-originating `x-forwarded-for` headers.
  - **Response Body Detector (F7) Stack Trace Precision & GraphQL Introspection**:
    - Required 2+ sequential stack frames for Java error signatures, eliminating false positives from single-line text comments.
    - Added `GQL-001` detection for production GraphQL introspection enabled in response bodies.
  - **Recon Detector (F8) Cloud Storage Coverage**:
    - Added patterns for Cloudflare R2, Alibaba Cloud OSS, Oracle Cloud Object Storage, and Backblaze B2 buckets.
  - **Cookie Security (COOK-004) SameSite Missing Severity Elevation**:
    - Elevated `COOK-004` finding for sensitive session cookies to `severity: 'medium'` and `outcome: 'fail'` when `SameSite` is absent, providing direct visibility into CSRF posture on legacy clients.
  - **Lead Priority Triage Suppression**:
    - Set calculated priority to `0` for leads triaged as `false_positive`.
  - **Comprehensive Test Suite Expansion**:
    - Expanded test suite to **756 unit tests across 52 test suites** alongside 9 Playwright E2E browser tests.
- **Secrets Detector (F1) Pattern Fixes & Vendor Expansions**:
  - Corrected malformed OpenAI API key regex quantifier (`{20,}T3BlbkFJ`).
  - Added detection for GitHub fine-grained personal access tokens (`github_pat_`), Hugging Face access tokens (`hf_`), Discord bot tokens, Twilio Account SID & Auth Token credentials, and hard-coded Bearer tokens with Shannon entropy validation.
- **CSP Multi-Policy Concurrency & Granular Directive Checks**:
  - Implemented multi-policy evaluation (`collectEnforcedPolicies`): browsers enforce all active CSP policies simultaneously; weaknesses are only flagged if permitted across all enforced policies. Emits `CSP-011` when multiple policies are active.
  - Case-insensitive keyword checks across all directives.
  - Added `CSP-004B` for `blob:` scheme in script execution contexts.
  - Added `CSP-004H` for `'unsafe-hashes'` in script-src / default-src.
  - Added CSP Level 3 directive override evaluations: `CSP-002E` (`'unsafe-inline'` in `script-src-elem`), `CSP-002A` (`'unsafe-inline'` in `script-src-attr`), and `CSP-004E` (wildcards in `script-src-elem`).
  - Added `CSP-005W` for overly broad `frame-ancestors` (`*` or plain `https:` wildcard).
- **HSTS RFC 6797 Directive Parsing Compliance**:
  - Implemented `parseHstsDirectives()` with case-insensitivity, support for quoted parameter values (e.g., `max-age="31536000"`), and strict first-occurrence directive precedence.
- **X-Content-Type-Options Fetch Spec Compliance**:
  - Evaluates the first comma-separated token per the Fetch specification, safely accepting duplicate proxy headers (e.g. `nosniff, nosniff`).
- **Cookie Sensitivity Heuristics**:
  - Preserved session-identifier cookies bearing CSRF markers (e.g. `xsrf_session`).
  - Fixed camelCase boundary word splitting to preserve underscores.
  - Added detection for standalone session token identifiers (`SSID`, `refreshToken`, `.AspNetCore.Cookies`, `.ASPXAUTH`, `userid`).

## [2.0.2] - 2026-10-23

### Security & Hardening
- **Cloud Bucket (CLD-001) Scope & Origin Isolation**:
  - Evaluated links independently with `resolveScopeStatus(bucketUrl, settings)` instead of inheriting the parent page's scope status.
  - Derived origin directly from bucket URL (`new URL(bucketUrl).origin`), ensuring third-party buckets (e.g. AWS S3, GCP Storage) linking from an in-scope target are never mislabeled as in-scope assets.
- **Nested TabState Export Boundary Hardening**:
  - Hardened `sanitizeStateForExport()` in `src/shared/export.ts` to recursively sanitize nested hop headers, raw headers, hop notes, subdomain trust vector extras/notes, coverage ledger notes/actions, coverage blind spots, score breakdown notes/descriptions, and top-level notes.
  - Verified 0 canary leakage across JSON, Markdown, and SARIF exports.
- **LeadStore Allowlisted Builder & Strict Enum Validation**:
  - Replaced `{ ...lead }` spreads in `LeadStore.sanitizeLeadEvidence` (`src/leads/store/lead-store.ts`) with explicit allowlisted builders.
  - Sanitized and length-capped `id`, `ruleId`, `origin`, `chainIds`, `title`, `url`, `preview`, `location`, `context`, `extractedNames`, `tags`, `needs`, `doesNotProve`, and `remediation`.
  - Validated enum fields (`family`, `tier`, `potential`, `sourceSensor`, `scopeStatus`, `triageState`) against strict sets with safe fallbacks.
- **Lead Report Enum Sanitization**:
  - Enforced enum validation in `sanitizeReportLead` (`src/leads/export/export.ts`) before emitting Markdown, JSON, or SARIF reports.
- **Resource-Level Scope Classification Completeness**:
  - In `src/background/leads-handler.ts`, passed resource-specific `origin` and `scopeStatus` for storage keys, form inputs, and action endpoints to `recordParam()`.
  - Preserved `scopeStatus: param.scopeStatus ?? 'unknown'` in `ReconStore` (`src/leads/store/recon-store.ts`), dropping out-of-scope entries immediately and maintaining existing in-scope classifications.
- **DevTools Route Tab Validation & Payload Capping**:
  - In `src/background/index.ts`, verified `DEVTOOLS_LEADS_COLLECTED` sender tab context via `await chrome.tabs.get(targetTabId)`, rejecting non-existent or incognito tabs.
  - Capped DevTools leads array to 50 items and applied strict string length caps and redactions to all lead fields.
- **Options Triage Private Context Awareness**:
  - Scoped triage management actions in `src/options/options.ts` to persistent-only context via `{ isIncognito: false }`, preserving in-memory private session annotations when persistent annotations are cleared.

## [2.0.1] - 2026-10-22

### Security & Hardening
- **TabState & Finding Text Export Sanitization**:
  - Implemented recursive, field-aware sanitization in `src/shared/export.ts` via `sanitizeFindingForExport` and `sanitizeStateForExport`.
  - Applies `redactAllSecrets` and URL sanitization to `title`, `impact`, `evidence`, `recommendation`, `reference`, `origin`, `apiEndpoints`, and `subdomainTrust.vectors`.
  - Guaranteed zero leakage of `TABSTATE_CANARY_Z93` and raw finding tokens across JSON, Markdown, and SARIF 2.1.0 exports (both object and string forms).
- **Lead Radar Serializer Allowlisting & Metadata Sanitization**:
  - Refactored `src/leads/export/export.ts` to eliminate `{ ...lead }` object spreading.
  - Built explicit allowlisted output objects where every string and array (`id`, `ruleId`, `origin`, `title`, `url`, `preview`, `location`, `context`, `extractedNames`, `tags`, `chainIds`, `needs`, `doesNotProve`, `remediation`) is validated and recursively sanitized via `sanitizeExportString()`.
  - Preserved `needs` (missing proof requirements) and `doesNotProve` caveats across all export formats.
  - Aligned SARIF 2.1.0 output: rule results use `level: "warning"` (leads are unconfirmed hypotheses, not verified vulnerabilities), preserving `potential` in SARIF properties.
- **Pre-Storage Lead Evidence Sanitization**:
  - Enforced the "redact before persistent state" invariant in `LeadStore.sanitizeLeadEvidence` (`src/leads/store/lead-store.ts`), applying `redactAllSecrets` and length caps to `title`, `context`, `extractedNames`, `tags`, `needs`, `doesNotProve`, and `remediation`.
- **S1 Parameter Harvesting Policy & Incognito Gating**:
  - Moved S1 query parameter harvesting in `src/background/capture.ts` strictly downstream of `isCaptureActiveForUrl(details.url)` and gated with `!isIncog`.
  - `registerParamHarvester` in `src/background/index.ts` enforces `!isIncognito` and `!incognitoTabIds.has(tabId)`.
- **Content Script Query Sender Binding & Empty Denial Responses**:
  - Replaced caller-supplied parameters in `GET_LEADS_STATE` with trusted browser state: bound strictly to `_sender.tab.id` and `originFromUrl(_sender.tab.url)`.
  - Rejections across `DOM_LEADS_COLLECTED`, `MAIN_WORLD_LEADS_EVENT`, `DEVTOOLS_LEADS_COLLECTED`, and `GET_LEADS_STATE` now return empty denial responses rather than leaking global state.
  - Enforced deep schema and enum validation on DevTools S4 payloads.
- **External Resource Scope Independence & ReconStore Gating**:
  - External scripts, iframes, and forms independently evaluate `resolveScopeStatus(resourceSrc, settings)` rather than inheriting page scope (`src/background/leads-handler.ts`).
  - Added `scopeStatus` field to `ReconParam`, `ReconEndpoint`, and `ReconBucket` in `src/leads/types.ts`.
  - `ReconStore` (`src/leads/store/recon-store.ts`) immediately drops parameters, endpoints, and buckets if `scopeStatus === 'out-of-scope'`.
- **Triage Store Reset Drainage & Drawer Incognito Isolation**:
  - Wired `await TriageStore.clearAll()` into `executeResetAllData()` in `src/background/index.ts`.
  - Wired `await TriageStore.clearAll({ isIncognitoOnly: true })` into `clearIncognitoSessionRecords()`.
  - Gated popup triage annotations in `src/popup/popup.ts` by incognito status.
- **Chain Heuristic Clarification**:
  - Documented composite chain confidence in `src/leads/chains/chains.ts` as a correlation and triage heuristic rather than statistical likelihood.
  - Calibrated numeric confidence (0.8) when whisper-tier leads are corroborated into multi-lead chains.
  - Excluded out-of-scope leads from chain candidate grouping.
- **Dependency Security Updates**:
  - Upgraded `vitest` to `5.0.5`, maintaining 0 vulnerabilities across low, moderate, and high severities (`npm audit --audit-level=low`).

## [2.0.0] - 2026-10-10

### Added
- **Lead Radar Multi-Sensor Detection Architecture (v2)**:
  - **S1 (Passive Network Headers)**: Continuous passive extraction from response headers and metadata.
  - **S2 (DOM Collector)**: Isolated-world client script extracting forms, scripts, iframes, meta tags, comments, framework hydration state (`__NEXT_DATA__`, `__NUXT_DATA__`, `__INITIAL_STATE__`), resource timings, and storage key names (never values).
  - **S3 (Deep Mode Sinks & Taint Analysis)**: Opt-in MAIN-world execution hooking dangerous DOM sinks (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `setTimeout(string)`, `location.assign`, `location.replace`), wildcard `postMessage` calls, listeners without origin checks, and sensitive token writes to `Storage.prototype.setItem`. Protected with private closure isolation and unforgeable `Symbol` guards.
  - **S4 (DevTools Network Body Analyzer)**: Dedicated Chrome DevTools panel ("ACULYX Leads" at `src/devtools/panel.html`) inspecting live network response bodies in-memory via `chrome.devtools.network.onRequestFinished` for debug stack traces (F7), leaked credentials (F1), and hidden endpoints (F2).
  - **S5 (Worker & Cache Surface)**: Service worker registration and cache surface intelligence.
- **Lead Radar Detector Families (F1–F8)**:
  - **F1 (Secrets & Credentials)**: High-precision secret detection across AWS keys (`AKIA...`), GitHub PATs/fine-grained tokens, Stripe secrets, Slack bot tokens (`xoxb-...` with multi-segment IDs), unsigned JWTs (`alg=none`), MongoDB/PostgreSQL URIs, and private key PEM blocks. High-precision, false-positive resilient on test corpora, with strict classification separating public identifiers (e.g. `pk_live_...`) from secrets.
  - **F2 (Endpoints & Hidden Surface)**: Harvests internal REST routes, admin paths, and GraphQL queries from client bundles and fetch calls.
  - **F3 (Source Maps)**: Discovers `sourceMappingURL` references, enabling source inspection for unminified codebases.
  - **F4 (Auth & OAuth)**: Detects implicit OAuth grants (`response_type=token`), missing CSRF on state-changing forms, and unhardened storage keys.
  - **F5 (Parameter Intelligence)**: Classifies query parameters into vulnerability classes (SSRF, IDOR, Open Redirect, SQLi, LFI).
  - **F6 (Security Headers)**: Flags missing hardening headers, overly permissive CORS, and weak cookies.
  - **F7 (Response Bodies & Errors)**: Discloses framework stack traces (Django, Flask/Werkzeug, Spring, Laravel, ASP.NET), GraphQL error leaks, and JSON excessive data exposure.
  - **F8 (Reconnaissance & Cloud Storage)**: Identifies AWS S3 buckets, Google Cloud Storage buckets, Azure Blob containers, and cross-origin iframe scopes.
- **The Sieve Privacy & Masking Engine (`src/leads/sieve/mask.ts`)**:
  - Invariant: Raw secrets and authentication tokens NEVER enter memory or storage.
  - Formats secrets into redacted previews preserving only prefix, suffix, length, and 64-bit cryptographic entropy hash (e.g., `AKIA...GH (len 20) [hash]`).
  - Automatic query parameter masking across all constructed leads and recon data, stripping credentials and high-entropy parameters from URLs.
- **MV3 Session Storage Persistence (`chrome.storage.session`)**:
  - Replaces volatile in-memory Maps with debounced persistence into `chrome.storage.session`, ensuring leads and tab associations survive service worker sleep and wake cycles cleanly.
- **Chains & Attack Surface Ranking**:
  - Correlates multi-lead attack paths into composite exploit scenarios (e.g., Open Redirect + OAuth Implicit Grant &rarr; Account Takeover).
  - Dynamic prioritization algorithm balancing finding potential, confidence, evidence tier, and scope status.
- **Hunter Active Verification Engine & Hunter Edition Build Flavor**:
  - Controlled, rate-limited, user-confirmed active HTTP probes (GET, HEAD, OPTIONS) for safe out-of-band vulnerability verification.
  - Recomputes scope status on background and enforces explicit user confirmation.
  - Introduced dedicated **ACULYX Hunter Edition** build flavor (`npm run build:hunter`) outputting to `dist-hunter/` with configured active probe CSP permissions (`connect-src 'self' http: https:`).
- **ACULYX Canonical Identity & Branding**:
  - Rebranded the extension from SecCheck to **ACULYX** (descriptor: *Header & Cookie Security Checker*).
  - Authored and owned by **Dhyan Patel**; updated `LICENSE` to Copyright 2024–2026 Dhyan Patel.
  - Added formal [`NOTICE`](NOTICE) file reserving ACULYX trademarks and brand assets under Dhyan Patel.
  - Added [`docs/PROVENANCE.md`](docs/PROVENANCE.md) with master asset SHA-256 checksums and release verification guides.
  - Replaced icon family (`icons/icon16.png`, `icon32.png`, `icon48.png`, `icon128.png`) with clean, transparent square silhouette marks derived from the master katana lockup.
  - Added high-resolution local wordmark artwork at `src/assets/aculyx-wordmark.png` and `docs/assets/aculyx-wordmark.png`.
- **In-Extension About, Privacy & Copyright Destination**:
  - Expanded Options `#section-about` into a full legal and provenance destination with embedded local ACULYX wordmark, live version badge, author attribution, copyright notice, Apache 2.0 license details, trademark notice, and official repository links.
- **Storage Write Barrier & Linearization (`src/shared/write-barrier.ts`)**:
  - Decoupled `KeyedAsyncMutex`, `StorageWriteBarrier`, and `onEpochChange` event bus to eliminate circular dependencies between storage and settings modules.
  - Linearized all storage reads and writes against full data reset, ensuring pre-reset writes cannot finish after storage clear and resurrect stale data.
- **Single-Owner Reset Epoch Synchronization**:
  - Synchronized service worker `currentResetEpoch` with `getStorageResetEpoch()` using an active subscriber.
  - Prevented epoch divergence during `executeResetAllData()`, allowing fresh post-reset captures to persist immediately to session storage and origin history without worker restarts.
- **Settings Barrier Protection**:
  - Routed `SettingsService.updateSettings()`, migration writes, and onboarding dismissals through `storageWriteBarrier.enter()` and `storageWriteBarrier.track(promise)` with epoch staleness checks, discarding stale settings modifications.
- **Fail-Closed Tab Privacy Resolution**:
  - Updated `resolveTabPrivacy()` to return `undefined` on lookup errors or unknown tabs, gating `LocalStorage` persistence behind `isPositivelyRegular = state.isIncognito === false`.
- **Query Parameter & URL Fragment Redaction**:
  - Enforced `sanitizeUrlForStorage()` across document hops, redirects, and API subresources, stripping all query parameters and fragments.
  - Extended `assertNoSensitiveSecrets()` to guard `state.url`, `hop.url`, `ledger.url`, `apiEndpoints`, and finding source URLs against OAuth `state`, emails, UUIDs, JWTs, and long opaque tokens.
- **Multi-Surface Appearance Pipeline (`src/shared/appearance.ts`)**:
  - Unified theme tokens (`dark`, `cyber`, `solar`), density levels (`comfortable`, `compact`), and reduced-motion modes across Options, Popup, and Sidepanel with dynamic `SETTINGS_CHANGED` broadcasts.
- **CLI & CI Capabilities**:
  - Added `npm run aculyx` as canonical CLI command while preserving `npm run seccheck` as a documented compatibility alias.
  - Emits `ACULYX` as the SARIF 2.1.0 tool driver name and Markdown report signature.
- **Pre-login vs. Post-login Posture Diff**:
  - Automatically snapshots and diffs security findings on authenticated transitions (`authdiff:`), identifying newly exposed weaknesses or resolved issues when sensitive auth cookies are established.
- **Attack-Surface Graph (Side Panel)**:
  - Dedicated sidepanel powered by `d3-force` interactive SVG visualization mapping apex domains, subdomains, and trust vectors (CSP, Cookie `Domain=`, CORS `Access-Control-Allow-Origin`).
- **Client-Side Verification Sandbox (PoC Generator)**:
  - MV3 sandboxed verification environment (`src/sandbox/poc.html`) for defensive security verification with ethical authorization gating.
  - Scope Gating: Verification sandbox generation (`GENERATE_POC`) strictly enforces `state.scopeStatus === 'in-scope'` under an active scope profile.
- **Bug-Bounty Scope Engine (`src/shared/scope/`)**:
  - Pure, deterministic scope evaluation supporting globs (`*.example.com`), CIDR blocks, exact host:port pairs, and regex patterns.
  - IDNA lowercase host normalization, trailing dot removal, and explicit port preservation (no silent port stripping).
  - Strict exclusion precedence: exclusion rules always override inclusion rules.
  - Immediate background tab reclassification: modifying or activating a scope profile immediately updates `scopeStatus` (`in-scope`, `out-of-scope`, `unknown`) across active tabs.
- **Researcher Triage Management (`src/shared/reporting/triage-store.ts`)**:
  - Decoupled triage store maintaining review states (`unreviewed`, `needs-manual-verification`, `verified-by-researcher`, `not-reproducible`, `not-a-finding`).
  - Pre-storage secret sanitization: triage notes are scrubbed using `redactAllSecrets` and capped to 5,000 characters before writing to disk (`chrome.storage.local`).
  - Ephemeral memory isolation: private and incognito triage annotations never touch persistent storage.
- **Bug-Bounty Report Builder & Secret Redaction (`src/shared/reporting/report-builder.ts`)**:
  - One-click Markdown and JSON report drafting tailored for bug-bounty platforms (HackerOne, Bugcrowd).
  - Generates deterministic reproduction steps, preconditions, expected vs observed behavior, impact narratives, and remediation guidance.
  - Multi-pass secret scrubbers: credentials in URLs, sensitive path segments (`/tenant-reset/`, `/password-reset/`), query tokens (`auth_token`, `state`, `code_verifier`), raw headers (`Authorization`, `Set-Cookie`), JWTs, UUIDs, and canaries are scrubbed across all export fields.
- **CLI SSRF Protection & Safe Redirect Following (`src/cli.ts`)**:
  - Blocks loopback, private IPv4 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`), IPv6 local, and cloud metadata (`169.254.169.254`) requests and redirects by default.
  - Added `--allow-private-ips` flag for authorized local development auditing.

### Changed
- **Score Versioning**: Bumped `SCORE_VERSION` to `1.7.0` to reflect rule registry and semantic CSP enhancements.
- **Dependency Security**: Added `"overrides": { "source-map-js": "^1.2.2" }` to resolve `GHSA-68fv-2mgg-jv7q` (`source-map-js@1.2.1`). `npm audit --audit-level=low` reports 0 vulnerabilities.
- **Firefox MV3 Compatibility**: Aligned release Gecko ID to `aculyx@security-checker.local` in `manifest.firefox.json` and build scripts, synchronizing Firefox manifests in `dist-firefox/`.

### Fixed
- **Settings Re-scoring Race**: Fixed delta detection when storage change events arrived prior to port messages.
- **Page-Signal Injection Hydration**: Queued signal evaluation behind settings readiness to prevent lost hard-navigation signals on cold worker start.
- **Stale Generation Leaks**: Guarded navigation generation counters to discard late arriving responses from earlier navigations.

---

## [1.6.0] - 2026-09-29

### Added
- **Cookie Name Overrides**: Customise `alwaysSensitive` and `alwaysIgnore` cookie heuristics via Options UI.
- **CSS Subresource Integrity (SRI)**: Scans `<link rel="stylesheet">` elements in addition to `<script>` tags.
- **Subdomain Trust Heuristics**: Added `SUB-003H` rule for CORS `Vary: Origin` heuristics.

### Changed
- Refined `COOK-001` and `COOK-002` name-based heuristics to cap severity at `medium` unless explicit security flags are configured.
- Tightened `LEAK-001` version pattern matching to reduce false positives on IP addresses.

---

## [1.0.0] - 2026-09-21

### Added
- **Initial Release**: Real-time passive observation of HTTP security headers (HSTS, CSP, XFO, XCTO, Referrer-Policy, Cache-Control).
- **Cookie Metadata Auditing**: Analyzes `Secure`, `HttpOnly`, `SameSite`, and prefix compliance without ever touching cookie values.
- **Browser Action UI**: Live grade badge, popup report, and historical origin scores.
- **Offline CLI**: Terminal audit tool supporting JSON, Markdown, and SARIF 2.1.0 output formats.
