# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-10-10

### Added
- **Lead Radar Multi-Sensor Detection Architecture (v2)**:
  - **S1 (Passive Network Headers)**: Continuous passive extraction from response headers and metadata.
  - **S2 (DOM Collector)**: Isolated-world client script extracting forms, scripts, iframes, meta tags, comments, framework hydration state (`__NEXT_DATA__`, `__NUXT_DATA__`, `__INITIAL_STATE__`), resource timings, and storage key names (never values).
  - **S3 (Deep Mode Sinks & Taint Analysis)**: Opt-in MAIN-world execution hooking dangerous DOM sinks (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `setTimeout(string)`, `location.assign`, `location.replace`), wildcard `postMessage` calls, listeners without origin checks, and sensitive token writes to `Storage.prototype.setItem`. Protected with private closure isolation and unforgeable `Symbol` guards.
  - **S4 (DevTools Network Body Analyzer)**: Dedicated Chrome DevTools panel ("ACULYX Leads" at `src/devtools/panel.html`) inspecting live network response bodies in-memory via `chrome.devtools.network.onRequestFinished` for debug stack traces (F7), leaked credentials (F1), and hidden endpoints (F2).
  - **S5 (Worker & Cache Surface)**: Service worker registration and cache surface intelligence.
- **Lead Radar Detector Families (F1–F8)**:
  - **F1 (Secrets & Credentials)**: High-precision secret detection across AWS keys (`AKIA...`), GitHub PATs/fine-grained tokens, Stripe secrets, Slack bot tokens (`xoxb-...` with multi-segment IDs), unsigned JWTs (`alg=none`), MongoDB/PostgreSQL URIs, and private key PEM blocks. Zero false positives on test corpora, with strict classification separating public identifiers (e.g. `pk_live_...`) from secrets.
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
