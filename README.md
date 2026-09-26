# Header & Cookie Security Checker

A Chrome (Manifest V3) extension that passively observes security headers and cookies as you browse, reports findings in real time, and keeps everything local — nothing leaves your device.

## Features

- **Live analysis** of `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `X-XSS-Protection` (deprecated), server version leaks, and cache behaviour
- **Redirect chain tracking** with two-capture-point diff to detect header modifications by other extensions
- **HSTS internal-redirect detection** via `Non-Authoritative-Reason: HSTS`
- **Coverage indicator** — shows "from cache", "restricted page", or "headers modified by another extension" instead of silently misleading you
- **A–F grade** with per-rule score breakdown; weights are versioned and documented
- **Live badge** updates as you navigate; popup shows top findings immediately
- **Cookie analysis** (Phase 2): `Secure`, `HttpOnly`, `SameSite`, prefix compliance, JS-set detection, CHIPS

## Privacy

- Cookie **values are never stored, displayed, or exported** — only attributes (name, flags, domain, path, expiry)
- The extension manifest declares `connect-src 'none'` in its Content Security Policy, making outbound network requests from extension pages impossible to verify in the source
- No remote code, no analytics, no telemetry
- All storage is local: `chrome.storage.session` for live tab state, `chrome.storage.local` for settings

## Permissions

The extension requests **no host permissions at install time.** Access is granted per-site or globally through an explicit user action:

- **Per-site (default):** click "Monitor this site" in the popup → grants access to that origin only
- **All sites:** toggle in the Options page → grants `<all_urls>`

## Out of scope

The following are intentionally excluded. See [design docs](./SCOPE.md) for rationale.

- Active probing (sending crafted `Origin` headers, CORS fuzzing, exploitation)
- TLS/cipher auditing
- Crawling pages the user hasn't visited
- DOM/JS vulnerability analysis (XSS, etc.)
- Any network request the user's own browsing didn't already make

**Use only on sites you own or have permission to test.** Passive observation of your own browsing is harmless, but be mindful of the data you're handling.

## Development

### Prerequisites

- Node.js ≥ 20
- pnpm ≥ 9

### Setup

```bash
pnpm install
```

### Development build (with HMR)

```bash
pnpm dev
```

Load the unpacked extension from `dist/` in `chrome://extensions`.

### Production build

```bash
pnpm build
```

### Type checking

```bash
pnpm typecheck
```

### Linting

```bash
pnpm lint
```

### Unit tests (rule engine)

```bash
pnpm test
```

### E2e tests (requires built extension)

```bash
pnpm build && pnpm test:e2e
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

See [SCOPE.md](./SCOPE.md) for a full discussion. Short version:

- **Restricted pages** (`chrome://`, the Web Store, `about:`) cannot be inspected — the extension shows an explicit "restricted" state rather than a misleading empty report
- **Cache and service-worker responses** are flagged with a coverage warning; the headers shown are "what the browser received from cache," not necessarily the current server headers
- **HSTS preloaded sites** redirect internally before any request leaves the browser, so the HTTP→HTTPS hop is invisible; Chrome's `Non-Authoritative-Reason: HSTS` header is used to label these hops
- **Meta-tag CSP** requires a content script (Phase 2); currently only HTTP-header CSP is analysed
- **CSP analysis is heuristic** — the tool flags known-weak patterns but cannot prove a policy is secure
- **Scores are opinionated** — weights are documented and versioned, not objective truth

## Roadmap

| Phase | Status | Deliverable |
|---|---|---|
| 1 | ✅ | Header capture, 8 header rules, badge, popup |
| 2 | Planned | Cookie store integration, cookie rules, JS-set detection |
| 3 | Planned | Side panel, redirect chain view, score breakdown, JSON export |
| 4 | Planned | Hardening, privacy pass, MV3 lifecycle testing, full automated test suite |
| 5 | Stretch | Diff/monitor history, mixed content, DevTools panel, Firefox port |

## License

Apache 2.0. Includes [csp-evaluator](https://github.com/nicktacular/csp-evaluator) (Apache 2.0 © Google LLC).
