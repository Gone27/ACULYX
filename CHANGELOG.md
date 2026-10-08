# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-10-08

### Added
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

### Changed
- **Score Versioning**: Bumped `SCORE_VERSION` to `1.7.0` to reflect rule registry and semantic CSP enhancements.
- **Dependency Security**: Added `"overrides": { "source-map-js": "^1.2.2" }` to resolve `GHSA-68fv-2mgg-jv7q` (`source-map-js@1.2.1`). `npm audit --audit-level=low` reports 0 vulnerabilities.
- **Firefox MV3 Compatibility**: Maintained release Gecko ID `seccheck@security-checker.local` and synchronized Firefox manifests in `dist-firefox/`.

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
