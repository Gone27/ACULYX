# Chrome Web Store & Firefox Add-ons Store Listing Assets

---

## 1. Title & Short Name
- **Extension Name:** ACULYX: Header & Cookie Security Checker
- **Short Name:** ACULYX
- **Version:** 2.0.6
- **Author:** Dhyan Patel

---

## 2. One-Line Punchy Pitch (Summary / Tagline)
> Passively inspect HTTP response headers, cookies, and subdomain trust escalation paths — 100% locally, with zero telemetry.

---

## 3. Short Description (Max 132 chars for Chrome Web Store)
> Passive HTTP security header & cookie analysis with live grading, CSP evaluation, and privacy-preserving audit capabilities.

---

## 4. Detailed Description

### 🛡️ Why ACULYX?
Most security header checkers are remote online scanners that run outside your authenticated session or simple checklist extensions that overwhelm you with confusing warnings.

**ACULYX** is a developer- and security-focused browser extension designed for web developers, penetration testers, and security researchers. It passively evaluates HTTP response headers and live cookie configurations directly from within your browser as pages load — giving you an accurate, real-world security grade without sending a single byte of your browsing data over the network.

Because ACULYX observes responses in the browser you are already using, it can audit pages reached after you sign in, subject to the per-origin permission you grant. It does not bypass authentication, defeat access controls, or discover pages you have not visited.

---

### 🚀 Key Features

- **🎯 Defensive Scoring Engine:**
  - Evaluates HSTS, Content-Security-Policy (CSP Level 3 aware, recognizing modern nonces and strict-dynamic via Google `csp_evaluator`), COEP/CORP, Permissions-Policy, Document-/Integrity-Policy, browser reporting, legacy headers, server fingerprints, and cache directives.
  - Sensitivity-aware cookie rules: distinguishes between high-value session tokens and harmless client-side UI cookies (preventing false alarms on theme or analytics cookies).
  - Categorized penalty caps prevent minor cookie issues from artificially tanking an otherwise rock-solid site.

- **💡 Explains "Why", Not Just "What":**
  - Every finding includes a concise, plain-English **Real-World Impact** explanation, helping you understand actual exploitability rather than theoretical compliance.

- **⚡ Subdomain→Main-Domain Trust Escalation Analysis:**
  - Unique attack-surface analysis inspecting whether a compromise on a low-security subdomain (e.g. blog, staging, dev) can jump over to compromise the apex domain via broad cookie scoping, missing `__Host-` prefixes, or wildcard CSP sources.

- **🔒 Zero-Telemetry Guarantee & Controlled Probes:**
  - Standard operation runs 100% locally with zero analytics, telemetry, or remote reporting.
  - If the optional credential liveness check is turned on by the user, outbound requests are strictly limited to the specific official provider API (`api.github.com`, `api.stripe.com`, `slack.com`), protected by explicit runtime user confirmation, restricted CSP, and optional host permissions.
  - Cookie values, auth tokens, passwords, and sensitive bodies are never stored, displayed in plain text, or exported.

- **📊 Modern Cyber-Inspired UI:**
  - Dark, Cyberpunk, and Solar theme modes with comfortable and compact density settings.
  - Interactive Attack Surface Graph powered by D3-force in the Side Panel.

---

## 5. Category & Search Keywords
- **Category:** Developer Tools / Security
- **Keywords:** security headers, cookie security, csp evaluator, hsts, subresource integrity, privacy, oauth, web security, owasp, penetration testing

---

## 6. Permission Privacy Justifications (Store Submissions)

- **`cookies`**: Passively audits cookie security attributes (`HttpOnly`, `Secure`, `SameSite`, `__Host-`, `__Secure-` prefixes). Cookie values are strictly never accessed, logged, stored, or transmitted (`cookie.value` is ignored).
- **`webRequest`**: Passively reads HTTP response headers to evaluate transport security (HSTS, CSP, X-Frame-Options, CORS, Cache-Control). Does not read request/response bodies or modify network traffic.
- **`webNavigation`**: Detects document navigation completions, redirects, and SPA client-side navigations to recompute security grades for the active tab.
- **`tabs`**: Queries current tab URL and ID to display per-tab grades, update toolbar action badges, and cleanly free resources when tabs close.
- **`scripting`**: Injects client-side DOM inspection sensors (S2/S3) on user-monitored tabs to analyze DOM sinks and subresource integrity.
- **`storage`**: Saves local user preferences, scope profiles, researcher triage notes, and bounded score history entirely on the user's device.
- **`alarms`**: Triggers periodic local cache pruning and data retention cleanup without running background threads.
- **`optional_permissions` / `optional_host_permissions` (`https://api.github.com/*`, `https://api.stripe.com/*`, `https://slack.com/*`, `<all_urls>`)**: Only requested upon explicit user consent per-site, when all-sites monitoring is activated, or when the user manually initiates an authenticated credential liveness check for a supported provider.

---

## 7. Reviewer Notes (Chrome Web Store & Mozilla AMO)

- **Use of `eval` in `main-world-hooks.ts`**:
  ACULYX wraps `window.eval` in the page's MAIN execution world strictly as a passive taint-tracking sensor. It observes calls made by the web page to detect unvalidated string execution. ACULYX **never** generates, compiles, or executes dynamic code via `eval()`. The original function is invoked with unmodified arguments, and only a sanitized event type is relayed to the extension.
- **Gated Passive Reconnaissance**:
  Query parameter harvesting (S1) is strictly gated by the user's capture policy and defined scope. Unmonitored, unknown, or out-of-scope hosts are completely ignored and never stored in memory or persistence.
- **Zero-Telemetry Guarantee & Strict Host Boundaries**:
  All extension pages enforce strict CSP and connect to no external analytics or telemetry services. Outbound connections are prohibited except for the optional, user-confirmed credential check which targets only the three declared provider APIs.

