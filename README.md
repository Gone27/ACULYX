# Header & Cookie Security Checker

A Chrome (Manifest V3) extension that passively observes security headers and cookies as you browse, reports findings in real time, and keeps everything local — nothing leaves your device.

Since analysis observes the browser's own responses, it can inspect pages you reach after signing in, once you grant access to that origin. It does not bypass authentication or crawl unvisited pages.

## Main Features

- **Live In-Browser Analysis**: Audits headers and cookies in real-time as you navigate. Inspects authenticated pages locally without requiring external crawls or bypassing authentication.
- **Two-Stage Redirect Tracking**: Captures headers before and after browser processing to detect internal HSTS upgrades and redirect degradation (headers present on one hop but dropped on the next).
- **Cookie Jar Correlation (Phase 2)**: Correlates `Set-Cookie` response headers with the live browser cookie jar. Cookies present in the jar but absent from the current response's headers are marked as **unknown origin** (possibly JS-set or set by a prior navigation). Also detects CHIPS (partitioning) and persistence issues, without ever storing sensitive cookie values.
- **Cookie Name Overrides**: Customise sensitive/ignored cookie heuristics via the extension's options page.
- **Scoring & Historical Trends**: Computes a strict A-F grade with penalties based on a versioned weighting model. Tracks per-origin score trends over time in a local graphical timeline.
- **CLI & CI Integrations**: Export findings to JSON, Markdown, or GitHub-compatible SARIF 2.1.0 formats. Supports offline HAR file analysis and CI severity thresholds (`--fail-on high`).
- **Zero-Telemetry Privacy**: Analysis is completely local. The extension uses `connect-src 'none'` to guarantee no data leaves the browser.


- **Cache Checks**: Ensures responses setting cookies enforce Cache-Control: no-store.
- **Coverage Indicator**: Tracks expected vs captured hops to show if service workers or caches intercepted traffic.
- **Configuration-Quality Sub-Score**: Separates security risks from best-practice hygiene in the UI.
- **Audit Exports & HAR Import**: Export findings to JSON, Markdown, or SARIF. Import offline HAR files with Set-Cookie redaction.
- **CSP Host Heuristics**: Warns on allowlisted hosts known to host JSONP endpoints or angular libraries.

## Main Rules Evaluated

The engine evaluates responses against over a dozen targeted security rules. Key checks include:

- **Transport Security (HSTS)**: Checks for `Strict-Transport-Security`, `includeSubDomains`, and ensures `max-age` is sufficient for preload readiness.
- **Content Security (CSP)**: Flags missing policies, `unsafe-inline`/`unsafe-eval` in script directives, wildcard origins, and missing framing (`frame-ancestors`) or `base-uri` protections. Warns on weak hosts (heuristic).
- **Cookie Security**: Flags missing `Secure` or `HttpOnly` flags on sensitive tokens (detected via regex heuristics or user overrides), validates `__Host-`/`__Secure-` prefixes, and checks `SameSite` enforcement.
- **Subdomain Trust & CORS**: Detects wildcard or null `Access-Control-Allow-Origin` on API responses, credentialed CORS wildcards, and overly permissive subdomain cookie scoping (e.g., setting a sensitive cookie to `.example.com` instead of a specific host).
- **Information Leakage**: Detects known product/version strings (e.g., `Express 4.x`, `PHP/8.1`, `nginx/1.24`) in headers like `Server` and `X-Powered-By`.
- **Legacy & Cache**: Flags deprecated headers (`X-XSS-Protection`) and ensures responses setting cookies enforce `Cache-Control: no-store`.
- **Subresource Integrity (SRI)**: Verifies that `<script>` and `<link rel="stylesheet">` tags in the HTML payload use `integrity` attributes.
## Privacy

- Cookie values are not accessed, persisted, displayed, or exported by this extension. Chrome's `cookies.getAll()` API returns cookie objects that include a `value` property; this extension reads only metadata fields and never accesses `cookie.value`.
- The extension manifest declares `connect-src 'none'` in its Content Security Policy, making outbound network requests from extension pages impossible (and easily verifiable in the source).
- No remote code, no analytics, no telemetry
- All storage is local: `chrome.storage.session` for live tab state, `chrome.storage.local` for settings
- **CLI network contact**: The CLI `--url` mode intentionally contacts the target URL to fetch headers. This is the only operation that sends a network request outside the browser.

## Permissions

The extension requests **no host permissions at install time.** Access is granted per-site or globally through an explicit user action:

- **Per-site (default):** click "Monitor this site" in the popup → grants access to that origin only
- **All sites:** toggle in the Options page → grants `<all_urls>`

## Out of scope

The following are intentionally excluded:

- Active probing (sending crafted `Origin` headers, CORS fuzzing, exploitation)
- TLS/cipher auditing
- HSTS preload-list membership verification (the extension checks only basic preload header readiness)
- Crawling pages the user hasn't visited
- DOM/JS vulnerability analysis (XSS, etc.)
- Any network request the user's own browsing didn't already make

**Use only on sites you own or have permission to test.** Passive observation of your own browsing is harmless, but be mindful of the data you're handling.

## Development

### Prerequisites

- Node.js ≥ 22.12.0
- npm ≥ 10

### Setup

```bash
npm install
```

### Development build (with HMR)

```bash
npm run dev
```

Load the unpacked extension from `dist/` in `chrome://extensions`.

### Production build

```bash
npm run build
```

### Firefox production build

```bash
npm run build:firefox
```

### Type checking

```bash
npm run typecheck
```

### Linting

```bash
npm run lint
```

### Unit tests (rule engine)

```bash
npm test
```

### CLI audit

See [CLI usage](docs/CLI.md) for URL scans, offline input, and CI exit thresholds.

**Note:** The CLI does not read extension configuration, so custom cookie override lists (`alwaysSensitive`, `alwaysIgnore`) configured in the browser will not be applied to CLI scans.

Exit codes: `0` means no finding met the threshold, `1` means a finding met or exceeded `--fail-on`, and `2` means invalid input or a scan error. The default threshold is `high` (critical and high findings fail).

### E2e tests (requires built extension)

```bash
npm run build && npm run test:e2e
```

## Project Structure

```
src/
├── background/       # MV3 service worker — capture, correlate, orchestrate
├── rules/            # Pure rule functions (zero browser APIs — fully unit-testable)
│   ├── headers/      # One file per header family
│   └── weights.json  # Versioned score weights (cited per rule against OWASP/MDN)
├── popup/            # Badge popup — grade + top findings + "Monitor" button
├── options/          # Settings page
└── shared/           # Types, constants, messaging protocol, storage wrappers
tests/
├── rules/            # Vitest fixture-driven unit tests
│   └── fixtures/     # JSON: headers-in → expected finding IDs
├── server/           # Express test server serving pages with deliberate header combos
└── e2e/              # Playwright integration tests
```

## Score Weights

Weights are in [`src/rules/weights.json`](src/rules/weights.json) and sourced from the [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/) and [MDN HTTP Observatory](https://developer.mozilla.org/en-US/observatory). Each rule's penalty and rationale are documented inline.

The `scoreVersion` field is stored with every result so historical comparisons remain valid after weight changes.

## Limitations

- **Restricted pages** (`chrome://`, the Web Store, `about:`) cannot be inspected — the extension shows an explicit "restricted" state rather than a misleading empty report
- **Cache and service-worker responses** are flagged with a coverage warning; the headers shown are "what the browser received from cache," not necessarily the current server headers
- **HSTS preloaded sites** redirect internally before any request leaves the browser, so the HTTP→HTTPS hop is invisible; Chrome's `Non-Authoritative-Reason: HSTS` header is used to label these hops
- **Meta-tag CSP** is detected and collected, but its policy contents are not evaluated against HTTP response header directives; the popup and report call out this coverage limit
- **Subresource & API capture** passively observes first-party and third-party XHR/fetch endpoints; findings are displayed in a dedicated API section and do not alter the top-level document security grade
- **Embedded content** is not inspected: only top-level (`main_frame`) navigation responses and same-session XHR/fetch calls are captured, so third-party iframe document headers are outside the audit
- **CSP analysis is heuristic** — the tool flags known-weak patterns but cannot prove a policy is secure
- **Scores are opinionated** — weights are documented and versioned, not objective truth

## Roadmap

| Phase | Status | Deliverable |
|---|---|---|
| 1 | ✅ | Header capture, 8 header rules, badge, popup |
| 2 | ✅ | Cookie store integration, cookie rules, cookie correlation & origin tracking, subdomain trust analysis |
| 3 | ✅ | Score breakdown, JSON/Markdown audit reports, historical score trend |
| 4 | ✅ | Side panel, redirect-chain analysis, SRI coverage, historical score trend, CI pipeline, full automated test suite (150+ tests), Firefox build, CLI/SARIF export, audit bundles & finding diffs |
| 5 | Stretch | Opt-in iframe subresource coverage, semantic meta-CSP evaluation, DevTools panel, mixed-content detection, signed remote rule updates |

## License

Apache 2.0. Includes [csp-evaluator](https://github.com/nicktacular/csp-evaluator) (Apache 2.0 © Google LLC).
