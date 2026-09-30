# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-09-30

### Added
- **Pre-login vs. Post-login Posture Diff**: Automatically snapshots and diffs security findings on authenticated transitions (`authdiff:`), identifying newly exposed weaknesses or resolved issues when sensitive auth cookies are established.
- **Attack-Surface Graph (Side Panel)**: Dedicated sidepanel powered by `d3-force` interactive SVG visualization mapping apex domains, subdomains, and trust vectors (CSP, Cookie `Domain=`, CORS `Access-Control-Allow-Origin`) with Free and Pro tier view modes.
- **Client-Side Verification Sandbox (PoC Generator)**: MV3 sandboxed verification environment (`src/sandbox/poc.html`) for defensive security verification, featuring interactive Clickjacking framing analysis and Cross-Origin-Opener-Policy (COOP) reverse-tabnabbing decoupling demonstrations with ethical authorization gating.
- **SecCheck Pro Mode**: Settings toggle to enable full accumulated cross-session multi-host attack surface mapping.

## [Unreleased]

### Added
- **Cookie Name Overrides**: Added UI in the extension options to allow users to specify `alwaysSensitive` and `alwaysIgnore` lists for cookie names, overriding the regex heuristics.
- **CSS SRI Coverage**: Expanded Subresource Integrity (SRI) checks in the content script to cover `<link rel="stylesheet">` tags, in addition to `<script>` tags.

### Changed
- **Score Versioning**: Bumped `SCORE_VERSION` to `1.6.0` to reflect scoring logic updates that affect historical comparisons.
- **Vary: Origin Scoring**: Separated the CORS `Vary: Origin` heuristic into a distinct rule ID (`SUB-003H`) with a reduced penalty (3 points) to distinguish it from confirmed wildcard credential leaks (`SUB-003`, 12 points).
- **Cookie Heuristic Evidence**: Refined `COOK-001` and `COOK-002` rules. Name-based regex matches are now capped at `medium` severity and labeled `(name-based heuristic)` unless a strong signal of security intent is present (e.g., setting `HttpOnly` on a cookie missing `Secure`).
- **LEAK-001 Tightening**: Replaced generic numeric regexes with strict `Product/Version` matchers to eliminate false positives on IP addresses and response times (e.g., `x-backend-server`, `x-runtime`). Bare decimals are now only checked for headers explicitly implying a version (e.g., `x-aspnet-version`).

### Fixed
- **CORS-001 False Positives**: Excluded `text/html` documents from wildcard CORS checks, eliminating noise on public CDN-fronted pages where top-level navigation is not gated by CORS.
- **Privacy Copy**: Softened language in options UI to accurately reflect that outbound requests are blocked by the extension's CSP.
- **Release Readiness**: Fixed placeholder links to the GitHub repository and marked Phase 4 as complete in the README roadmap.

## [1.0.0] - Initial Release
- **Core Engine**: Real-time analysis of HSTS, CSP, COEP/CORP, permissions policies, and cache behaviors.
- **Cookie Analysis**: Analysis of `Secure`, `HttpOnly`, `SameSite`, and prefix compliance without ever storing cookie values.
- **UI**: Live badge updates, popup for top findings, and per-origin score history.
- **CLI/CI**: Support for offline HAR import, SARIF 2.1.0 exports, and CI severity thresholds.
- **Diagnostics**: Redirect chain tracking, internal redirect detection, and cookie persistence diagnostics.
